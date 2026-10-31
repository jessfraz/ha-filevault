//! HA owns the identity on an ingress session. Never manufacture ingress headers.
use futures_util::{SinkExt, StreamExt};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use zeroize::Zeroizing;

const LIMIT: usize = 262_144;
const WAIT: Duration = Duration::from_secs(15);
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct Ingress {
    pub base: Url,
    pub cookie: HeaderValue,
}

#[derive(Serialize)]
struct Auth<'a> {
    r#type: &'static str,
    access_token: &'a str,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum Request<'a> {
    #[serde(rename = "get_panels")]
    Panels { id: u64 },
    #[serde(rename = "supervisor/api")]
    Supervisor {
        id: u64,
        endpoint: &'a str,
        method: &'static str,
    },
}

#[derive(Deserialize)]
struct Reply<T> {
    r#type: String,
    id: Option<u64>,
    success: Option<bool>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct Panel {
    config: Option<PanelConfig>,
}

#[derive(Deserialize)]
struct PanelConfig {
    addon: Option<String>,
}

#[derive(Deserialize)]
struct App {
    slug: String,
    state: String,
    ingress_url: String,
}

#[derive(Deserialize)]
struct Session {
    session: String,
}

pub fn origin(value: &str) -> Result<Url, &'static str> {
    let error = "HOME_ASSISTANT_URL must be an HTTPS origin (loopback HTTP is allowed)";
    let mut url = crate::endpoint(value, crate::Command::Status).map_err(|_| error)?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !local {
        return Err(error);
    }
    url.set_path("/");
    Ok(url)
}

async fn receive<T: DeserializeOwned>(socket: &mut Socket) -> Result<Reply<T>, &'static str> {
    timeout(WAIT, async {
        for _ in 0..16 {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => {
                    return serde_json::from_str(&text)
                        .map_err(|_| "invalid Home Assistant response");
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                _ => return Err("Home Assistant connection closed"),
            }
        }
        Err("unexpected Home Assistant response")
    })
    .await
    .map_err(|_| "Home Assistant response timed out")?
}

async fn send(socket: &mut Socket, value: &impl Serialize) -> Result<(), &'static str> {
    let text = serde_json::to_string(value).map_err(|_| "Home Assistant request unavailable")?;
    timeout(WAIT, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| "Home Assistant request timed out")?
        .map_err(|_| "Home Assistant request failed")
}

async fn query<T: DeserializeOwned>(
    socket: &mut Socket,
    id: u64,
    request: Request<'_>,
) -> Result<T, &'static str> {
    send(socket, &request).await?;
    let reply: Reply<T> = receive(socket).await?;
    if reply.r#type != "result" || reply.id != Some(id) {
        return Err("unexpected Home Assistant response");
    }
    if reply.success != Some(true) {
        return Err("Home Assistant rejected ingress access; use an allowed HA administrator");
    }
    reply.result.ok_or("incomplete Home Assistant response")
}

pub async fn ingress(base: Url, token: &str) -> Result<Ingress, &'static str> {
    if token.is_empty() || token.len() > 8192 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("HOME_ASSISTANT_TOKEN is invalid");
    }
    let mut websocket = base.clone();
    let scheme = if base.scheme() == "https" {
        "wss"
    } else {
        "ws"
    };
    websocket
        .set_scheme(scheme)
        .map_err(|_| "invalid HA origin")?;
    websocket.set_path("/api/websocket");
    let config = WebSocketConfig::default()
        .max_message_size(Some(LIMIT))
        .max_frame_size(Some(LIMIT));
    let (mut socket, _) = timeout(
        WAIT,
        connect_async_with_config(websocket.as_str(), Some(config), true),
    )
    .await
    .map_err(|_| "Home Assistant connection timed out")?
    .map_err(|_| "Home Assistant connection failed")?;
    if receive::<()>(&mut socket).await?.r#type != "auth_required" {
        return Err("unexpected Home Assistant authentication response");
    }
    send(
        &mut socket,
        &Auth {
            r#type: "auth",
            access_token: token,
        },
    )
    .await?;
    if receive::<()>(&mut socket).await?.r#type != "auth_ok" {
        return Err("Home Assistant authentication rejected");
    }
    let panels: BTreeMap<String, Panel> = query(&mut socket, 1, Request::Panels { id: 1 }).await?;
    let candidates: Vec<String> = panels
        .into_values()
        .filter_map(|panel| panel.config.and_then(|config| config.addon))
        .filter(|slug| slug == "filevault" || slug.ends_with("_filevault"))
        .collect();
    let slug = match candidates.as_slice() {
        [slug] => slug,
        [] => return Err("FileVault app was not found in Home Assistant"),
        _ => {
            return Err(
                "multiple FileVault apps found; expose only the intended app in the sidebar",
            );
        }
    };
    if slug.len() > 128 || !slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("invalid FileVault app identity");
    }
    let app: App = query(
        &mut socket,
        2,
        Request::Supervisor {
            id: 2,
            endpoint: &format!("/addons/{slug}/info"),
            method: "get",
        },
    )
    .await?;
    if app.slug != *slug || app.state != "started" {
        return Err("FileVault app is not running");
    }
    let prefix = "/api/hassio_ingress/";
    let ingress_token = app
        .ingress_url
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix('/').or(Some(s)))
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 256
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        .ok_or("invalid FileVault ingress address")?;
    let session: Session = query(
        &mut socket,
        3,
        Request::Supervisor {
            id: 3,
            endpoint: "/ingress/session",
            method: "post",
        },
    )
    .await?;
    let session = Zeroizing::new(session.session);
    let _ = timeout(Duration::from_secs(2), socket.close(None)).await;
    if session.is_empty()
        || session.len() > 1024
        || !session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("invalid Home Assistant ingress session");
    }
    let mut cookie = HeaderValue::from_str(&format!("ingress_session={}", *session))
        .map_err(|_| "invalid Home Assistant ingress session")?;
    cookie.set_sensitive(true);
    let mut address = base;
    address.set_path(&format!("{prefix}{ingress_token}/"));
    Ok(Ingress {
        base: address,
        cookie,
    })
}
