mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bydev::{Clock, Ports, ServerVerifier, codes, verify_webhook};
use common::{Reply, serve};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

// 안내서 11장의 서명 예시 — 문서와 SDK가 같은 값으로 맞는다(TS · Go 시험과 같은 값)
const SECRET: &str = "whsec_/MU12AiKByBoT7xt+p81N/uKdp/WxQRb";
const ID: &str = "evt_01J9MC4D6E8F0G2H4J6K8M0N2P";
const TIMESTAMP: &str = "1791295205";
const SENT: i64 = 1_791_295_205;
const BODY: &str = r#"{"id":"evt_01J9MC4D6E8F0G2H4J6K8M0N2P","type":"build.review_completed","occurredAt":"2026-10-06T14:00:00Z","mode":"LIVE","simulated":false,"data":{"build":{"id":"build_01J9M4D6F8H0J2K4M6N8P0R2S4","productId":"prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD","version":"1.4.2","reviewedAt":"2026-10-06T13:58:00Z","result":"APPROVED"}}}"#;
const SIGNATURE: &str = "v1,vmsiq2HY4gik/WNJjXJzuESzXAjJgr8Vi13SKwwhgEo=";

struct At(i64);

impl Clock for At {
    fn now_ms(&self) -> i64 {
        self.0 * 1000
    }
}

fn headers(signature: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Webhook-Id", ID.to_owned()),
        ("Webhook-Timestamp", TIMESTAMP.to_owned()),
        ("WEBHOOK-SIGNATURE", signature.to_owned()),
    ]
}

fn check(secrets: &[&str], signature: &str, body: &str, now: i64) -> Result<bydev::WebhookVerification, bydev::Error> {
    let h = headers(signature);
    verify_webhook(secrets, h.iter().map(|(k, v)| (*k, v.as_str())), body.as_bytes(), Some(&At(now)))
}

#[test]
fn webhook_example_matches() {
    let got = check(&[SECRET], SIGNATURE, BODY, SENT + 10).unwrap();
    assert_eq!((got.id.as_str(), got.timestamp), (ID, SENT));
}

#[test]
fn webhook_rotation() {
    check(&[SECRET], &format!("v1,AAAA {SIGNATURE}"), BODY, SENT).unwrap();
    check(&["whsec_AAAAAAAAAAAAAAAAAAAAAAAA", SECRET], SIGNATURE, BODY, SENT).unwrap();
}

#[test]
fn webhook_rejects() {
    let code = |r: Result<_, bydev::Error>| r.unwrap_err().code().to_owned();
    assert_eq!(code(check(&[SECRET], SIGNATURE, &format!("{BODY} "), SENT)), codes::WEBHOOK_INVALID);
    assert_eq!(code(check(&[SECRET], SIGNATURE, BODY, SENT + 301)), codes::WEBHOOK_INVALID);
    assert_eq!(code(check(&[SECRET], SIGNATURE, BODY, SENT - 301)), codes::WEBHOOK_INVALID);
    assert_eq!(code(check(&[SECRET], &format!("v2,{}", &SIGNATURE[3..]), BODY, SENT)), codes::WEBHOOK_INVALID);
    let only_id = [("webhook-id", ID)];
    assert_eq!(
        code(verify_webhook(&[SECRET], only_id.iter().copied(), BODY.as_bytes(), Some(&At(SENT)))),
        codes::WEBHOOK_INVALID
    );
    // 접두사 없는 시크릿은 설정 실수
    assert_eq!(code(check(&["/MU12AiKByBoT7xt+p81N/uKdp/WxQRb"], SIGNATURE, BODY, SENT)), codes::CONFIGURATION);
}

#[test]
fn server_verifier_checks_access_tokens() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let x = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let base = Arc::new(std::sync::OnceLock::<String>::new());
    let b = base.clone();
    let (url, log) = serve(Arc::new(move |_, path| {
        let base = b.get().cloned().unwrap_or_default();
        let ok = |body: serde_json::Value| Reply {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.to_string(),
        };
        match path {
            "/.well-known/openid-configuration" => ok(json!({
                "issuer": base, "jwks_uri": format!("{base}/.well-known/jwks.json"),
                "device_authorization_endpoint": format!("{base}/v1/oauth/device_code"),
                "token_endpoint": format!("{base}/v1/oauth/token"), "revocation_endpoint": format!("{base}/v1/oauth/revoke"),
            })),
            "/.well-known/jwks.json" => {
                let mut r = ok(
                    json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "srv-k1", "use": "sig", "alg": "EdDSA", "x": x }] }),
                );
                r.headers.push(("Cache-Control".into(), "public, max-age=300".into()));
                r
            }
            _ => {
                Reply {
                    status: 404, headers: vec![], body: r#"{"code":"PRODUCT_NOT_FOUND","message":"없음"}"#.into()
                }
            }
        }
    }));
    base.set(url.clone()).unwrap();
    let now = 1_791_295_205_i64;
    let client_id = "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW";
    let mint = |kid: &str, aud: &str| {
        let head = URL_SAFE_NO_PAD.encode(json!({ "alg": "EdDSA", "typ": "at+jwt", "kid": kid }).to_string());
        let body = URL_SAFE_NO_PAD.encode(
            json!({ "iss": url, "sub": "usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", "aud": aud, "client_id": aud, "scope": "entitlement.read",
                    "iat": now, "exp": now + 3600, "jti": "at_srv0001" })
            .to_string(),
        );
        let input = format!("{head}.{body}");
        let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
        format!("{input}.{sig}")
    };
    let verifier = ServerVerifier::new(&url, client_id, Ports { clock: Some(Arc::new(At(now))), ..Ports::default() });
    let claims = verifier.verify_access_token(&mint("srv-k1", client_id)).unwrap();
    assert_eq!((claims.sub.as_str(), claims.scope.as_str()), ("usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", "entitlement.read"));
    assert_eq!(
        verifier.verify_access_token(&mint("srv-k1", "cli_other_client_00000000")).unwrap_err().code(),
        codes::TOKEN_INVALID
    );
    // 모르는 kid — 1분 안에는 다시 받지 않는다
    assert_eq!(verifier.verify_access_token(&mint("srv-k9", client_id)).unwrap_err().code(), codes::TOKEN_INVALID);
    let jwks = log.lock().unwrap().iter().filter(|r| r.ends_with("jwks.json")).count();
    assert_eq!(jwks, 1);
}
