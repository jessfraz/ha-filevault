use filevault::api::{self, Access, Context};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::test]
async fn status_is_authenticated_no_store_and_never_claims_unlock_ready() {
    let server = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::new(Access::Status {
            token_hash: Sha256::digest("test-only-status-token").into(),
        })),
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{url}/v1/status"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = client
        .get(format!("{url}/v1/status"))
        .bearer_auth("test-only-status-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["decision"]["state"], "unknown");
    assert_eq!(body["decision"]["unlock_available"], false);
    assert_eq!(body["transport_ready"], false);
    assert_eq!(body["manual_ready"], false);
    let metadata: serde_json::Value = client
        .get(format!("{url}/v1/system"))
        .bearer_auth("test-only-status-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["credential_role"], "integration");
    assert!(metadata.get("token").is_none());
    assert_eq!(
        client
            .get(format!("{url}/v1/recovery"))
            .bearer_auth("test-only-status-token")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for path in [
        "/v1/manual/session",
        "/v1/manual/attempt",
        "/v1/manual/trust",
    ] {
        assert_eq!(
            client
                .post(format!("{url}{path}"))
                .bearer_auth("test-only-status-token")
                .header("x-remote-user-id", "user")
                .header("origin", "https://ha.example.invalid")
                .header("sec-fetch-site", "same-origin")
                .body("DUMMY_SENTINEL")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    assert_eq!(
        client
            .post(format!("{url}/v1/unlock"))
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{url}/"))
            .bearer_auth("test-only-status-token")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    server.close().await.unwrap();
}

#[test]
fn openapi_has_dedicated_endpoint_without_ha_service_payload() {
    let spec = api::openapi().unwrap();
    let paths = spec["paths"].as_object().unwrap();
    assert!(paths.contains_key("/v1/status"));
    assert!(paths.contains_key("/v1/unlock"));
    assert!(paths.contains_key("/v1/session"));
    assert!(paths.contains_key("/v1/manual/session"));
    assert!(paths.contains_key("/v1/manual/attempt"));
    assert!(paths.contains_key("/v1/manual/trust"));
}
