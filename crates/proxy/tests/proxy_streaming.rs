use std::sync::Arc;

use axum::http::{Request, StatusCode};
use llm_firewall::{app, test_config, AppState};
use llm_firewall_core::{Firewall, PolicySet, SecretDetector};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn streams_benign_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string("data: hello\n\ndata: world\n\n"),
        )
        .mount(&server)
        .await;

    let fw = Firewall::new(
        vec![Box::new(SecretDetector::new())],
        PolicySet::from_yaml("default: allow").unwrap(),
    );
    let state = Arc::new(AppState {
        firewall: fw,
        http: reqwest::Client::new(),
        config: test_config(server.uri()),
    });

    let body = serde_json::json!({
        "model":"gpt-4o","stream":true,
        "messages":[{"role":"user","content":"say hi"}]
    });
    let resp = app(state)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
}
