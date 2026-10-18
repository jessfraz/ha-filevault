use crate::{
    controller::{Controller, Outcome},
    policy::Decision,
    secret::Secret,
    transport::Disabled,
};
use anyhow::{Context as _, Result};
use dropshot::{
    ApiDescription, Body, ClientErrorStatusCode as Status, ConfigDropshot, HttpError,
    HttpResponseHeaders, HttpResponseOk, HttpServer, HttpServerStarter, RequestContext,
    UntypedBody, endpoint,
};
use http::Response;
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use subtle::ConstantTimeEq;

pub enum Access {
    Ingress {
        peer: IpAddr,
        users: HashSet<String>,
    },
    Status {
        token_hash: [u8; 32],
    },
}

pub struct Context {
    pub access: Access,
    pub controller: Arc<Controller>,
}

impl Context {
    pub fn new(access: Access) -> Self {
        Self {
            access,
            controller: Arc::new(Controller::new(
                Arc::new(Disabled),
                String::new(),
                std::time::Instant::now(),
            )),
        }
    }
    pub fn with_controller(access: Access, controller: Arc<Controller>) -> Self {
        Self { access, controller }
    }
}

#[derive(Serialize, JsonSchema)]
pub struct StatusReport {
    pub version: &'static str,
    pub decision: Decision,
    pub transport_ready: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct SystemReport {
    version: &'static str,
    credential_role: &'static str,
}

#[endpoint {method=GET,path="/v1/system",tags=["system"]}]
async fn system(
    r: RequestContext<Arc<Context>>,
) -> Result<HttpResponseHeaders<HttpResponseOk<SystemReport>>, HttpError> {
    authenticate(&r)?;
    let mut response = HttpResponseHeaders::new_unnamed(HttpResponseOk(SystemReport {
        version: env!("CARGO_PKG_VERSION"),
        credential_role: if matches!(r.context().access, Access::Status { .. }) {
            "integration"
        } else {
            "ha_user"
        },
    }));
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}

fn deny(code: Status, message: &'static str) -> HttpError {
    HttpError::for_client_error(None, code, message.into())
}

fn header<'a>(r: &'a RequestContext<Arc<Context>>, key: &str) -> Option<&'a str> {
    r.request.headers().get(key)?.to_str().ok()
}

pub fn authorize(access: &Access, peer: IpAddr, user: Option<&str>, token: Option<&str>) -> bool {
    match access {
        Access::Ingress {
            peer: expected,
            users,
        } => peer == *expected && user.is_some_and(|id| !id.is_empty() && users.contains(id)),
        Access::Status { token_hash } => token.is_some_and(|value| {
            let actual: [u8; 32] = Sha256::digest(value).into();
            bool::from(actual.ct_eq(token_hash))
        }),
    }
}

fn authenticate(r: &RequestContext<Arc<Context>>) -> Result<(), HttpError> {
    let token = header(r, "authorization").and_then(|s| s.strip_prefix("Bearer "));
    if !authorize(
        &r.context().access,
        r.request.remote_addr().ip(),
        header(r, "x-remote-user-id"),
        token,
    ) {
        return Err(deny(Status::FORBIDDEN, "access denied"));
    }
    Ok(())
}

#[endpoint {method=GET,path="/v1/status",tags=["system"]}]
async fn status(
    r: RequestContext<Arc<Context>>,
) -> Result<HttpResponseHeaders<HttpResponseOk<StatusReport>>, HttpError> {
    authenticate(&r)?;
    let report = StatusReport {
        version: env!("CARGO_PKG_VERSION"),
        decision: r.context().controller.status().await,
        transport_ready: r.context().controller.ready(),
    };
    let mut response = HttpResponseHeaders::new_unnamed(HttpResponseOk(report));
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}

fn browser_user(r: &RequestContext<Arc<Context>>) -> Result<&str, HttpError> {
    web_access(r)?;
    if r.request.uri().query().is_some()
        || header(r, "sec-fetch-site") != Some("same-origin")
        || !header(r, "origin").is_some_and(|origin| r.context().controller.valid_origin(origin))
    {
        return Err(deny(Status::FORBIDDEN, "browser request rejected"));
    }
    header(r, "x-remote-user-id").ok_or_else(|| deny(Status::FORBIDDEN, "access denied"))
}

#[derive(Serialize, JsonSchema)]
pub struct ChallengeReport {
    nonce: String,
    expires_in: u64,
}

#[endpoint {method=POST,path="/v1/session",tags=["recovery"]}]
async fn prepare(
    r: RequestContext<Arc<Context>>,
    body: UntypedBody,
) -> Result<HttpResponseHeaders<HttpResponseOk<ChallengeReport>>, HttpError> {
    let user = browser_user(&r)?;
    let base = ingress_base(&r)?;
    if !body.as_bytes().is_empty() {
        return Err(deny(Status::BAD_REQUEST, "empty request required"));
    }
    let challenge = r
        .context()
        .controller
        .challenge(user)
        .await
        .map_err(|_| deny(Status::CONFLICT, "verified preboot unavailable"))?;
    let cookie = format!(
        "fv_session={}; Secure; HttpOnly; SameSite=Strict; Path={base}; Max-Age=60",
        challenge.cookie
    );
    let mut response = HttpResponseHeaders::new_unnamed(HttpResponseOk(ChallengeReport {
        nonce: challenge.nonce,
        expires_in: 60,
    }));
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response.headers_mut().insert(
        "set-cookie",
        cookie
            .parse()
            .map_err(|_| deny(Status::BAD_REQUEST, "response unavailable"))?,
    );
    Ok(response)
}

fn session_cookie(value: Option<&str>) -> Option<&str> {
    let value = value.filter(|v| v.len() < 4096)?;
    let mut found = value
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("fv_session="));
    let cookie = found.next()?;
    if found.next().is_some()
        || cookie.len() != 64
        || !cookie.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(cookie)
}

#[derive(Serialize, JsonSchema)]
pub struct AttemptReport {
    outcome: &'static str,
}

#[endpoint {method=POST,path="/v1/unlock",tags=["recovery"]}]
async fn unlock(
    r: RequestContext<Arc<Context>>,
    body: UntypedBody,
) -> Result<HttpResponseHeaders<HttpResponseOk<AttemptReport>>, HttpError> {
    let user = browser_user(&r)?;
    let base = ingress_base(&r)?;
    if header(&r, "content-type") != Some("application/octet-stream") {
        return Err(deny(Status::BAD_REQUEST, "invalid request"));
    }
    let nonce = header(&r, "x-filevault-nonce")
        .filter(|s| s.len() == 64)
        .ok_or_else(|| deny(Status::FORBIDDEN, "request grant required"))?;
    let cookie = session_cookie(header(&r, "cookie"))
        .ok_or_else(|| deny(Status::FORBIDDEN, "request grant required"))?;
    let password = Secret::from_bytes(body.as_bytes().to_vec())
        .ok_or_else(|| deny(Status::BAD_REQUEST, "invalid request"))?;
    let result = r
        .context()
        .controller
        .submit(
            nonce,
            cookie,
            user,
            header(&r, "origin").unwrap_or(""),
            password,
        )
        .await;
    let outcome = match result {
        Outcome::Running => "running",
        Outcome::Booting => "booting",
        Outcome::Rejected => "rejected",
        Outcome::TimedOut => "timed_out",
    };
    let mut response = HttpResponseHeaders::new_unnamed(HttpResponseOk(AttemptReport { outcome }));
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response.headers_mut().insert(
        "set-cookie",
        format!(
            "fv_session=; Secure; HttpOnly; SameSite=Strict; Path={}; Max-Age=0",
            base
        )
        .parse()
        .map_err(|_| deny(Status::BAD_REQUEST, "response unavailable"))?,
    );
    Ok(response)
}

fn content(body: String, kind: &'static str) -> Result<Response<Body>, HttpError> {
    Response::builder().header("content-type", kind).header("cache-control", "no-store")
        .header("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'self'")
        .header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer")
        .body(Body::from(body)).map_err(|_| deny(Status::BAD_REQUEST, "response unavailable"))
}

fn ingress_base(r: &RequestContext<Arc<Context>>) -> Result<String, HttpError> {
    let base = header(r, "x-ingress-path").unwrap_or("");
    if !base.is_empty()
        && (!base.starts_with('/')
            || base.starts_with("//")
            || base.len() > 2048
            || !base
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-')))
    {
        return Err(deny(Status::BAD_REQUEST, "invalid ingress prefix"));
    }
    Ok(format!("{}/", base.trim_end_matches('/')))
}

fn web_access(r: &RequestContext<Arc<Context>>) -> Result<(), HttpError> {
    authenticate(r)?;
    if !matches!(r.context().access, Access::Ingress { .. }) {
        return Err(deny(Status::FORBIDDEN, "ingress required"));
    }
    Ok(())
}

#[endpoint {method=GET,path="/",tags=["web"]}]
async fn index(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    let base = header(&r, "x-ingress-path").unwrap_or("");
    if !base.is_empty()
        && (!base.starts_with('/')
            || base.starts_with("//")
            || base.len() > 2048
            || !base
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-')))
    {
        return Err(deny(Status::BAD_REQUEST, "invalid ingress prefix"));
    }
    content(
        include_str!("../web/index.html").replace(
            "__FILEVAULT_BASE__",
            &format!("{}/", base.trim_end_matches('/')),
        ),
        "text/html; charset=utf-8",
    )
}

#[endpoint {method=GET,path="/app.js",tags=["web"]}]
async fn script(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    content(
        include_str!("../web/app.js").into(),
        "text/javascript; charset=utf-8",
    )
}

#[endpoint {method=GET,path="/policy.js",tags=["web"]}]
async fn script_policy(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    content(
        include_str!("../web/policy.js").into(),
        "text/javascript; charset=utf-8",
    )
}

#[endpoint {method=GET,path="/recovery.js",tags=["web"]}]
async fn script_recovery(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    content(
        include_str!("../web/recovery.js").into(),
        "text/javascript; charset=utf-8",
    )
}

#[endpoint {method=GET,path="/style.css",tags=["web"]}]
async fn style(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    content(
        include_str!("../web/style.css").into(),
        "text/css; charset=utf-8",
    )
}

#[endpoint {method=GET,path="/brand.svg",tags=["web"]}]
async fn brand(r: RequestContext<Arc<Context>>) -> Result<Response<Body>, HttpError> {
    web_access(&r)?;
    content(include_str!("../web/brand.svg").into(), "image/svg+xml")
}

pub fn description() -> Result<ApiDescription<Arc<Context>>> {
    let mut api = ApiDescription::new();
    api.register(status).context("register status")?;
    api.register(system).context("register pairing metadata")?;
    api.register(prepare).context("register session")?;
    api.register(unlock).context("register attempt")?;
    api.register(index).context("register dashboard")?;
    api.register(script).context("register script")?;
    api.register(script_policy).context("register UI policy")?;
    api.register(script_recovery)
        .context("register recovery client")?;
    api.register(style).context("register style")?;
    api.register(brand).context("register brand")?;
    Ok(api)
}

pub fn openapi() -> Result<serde_json::Value> {
    Ok(description()?
        .openapi(
            "FileVault API",
            semver::Version::parse(env!("CARGO_PKG_VERSION"))?,
        )
        .description("Status and bounded ephemeral recovery requests. Real unlock disabled until verified preboot transport is available.")
        .json()?)
}

pub fn start(bind: SocketAddr, context: Arc<Context>) -> Result<HttpServer<Arc<Context>>> {
    // Dropshot may attach raw URIs and errors. Discard them rather than accepting
    // request logging into a future credential flow. Operational logs can be
    // added only as a reviewed fixed vocabulary, as in the reference apps.
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    HttpServerStarter::new(
        &ConfigDropshot {
            bind_address: bind,
            default_request_body_max_bytes: 1024,
            ..Default::default()
        },
        description()?,
        context,
        &logger,
    )
    .map(HttpServerStarter::start)
    .map_err(|_| anyhow::anyhow!("start HTTP listener"))
}
