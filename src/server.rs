//! 명세 12절 — 판매자 서버의 도우미. 앱 쪽 클라이언트와 상태를 나누지 않는다.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::api::Api;
use crate::defaults::SystemClock;
use crate::errors::Error;
use crate::generated::{codes, rules};
use crate::models::{AccessClaims, LicenseClaims};
use crate::ports::{Clock, Ports};
use crate::verify::Verifier;

/// 검증된 웹훅의 id와 시각이다. 중복 수신은 id로 거른다.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookVerification {
    pub id: String,
    pub timestamp: i64,
}

/// 웹훅 서명을 검증한다(안내서 11장 · Standard Webhooks v1). `raw_body`는 받은 그대로의 본문이다 — 파싱했다가 다시 만든 바이트는 서명이 맞지
/// 않는다. 시크릿을 교체하는 중이면 둘 다 넘긴다. `headers`는 (이름, 값) — 이름의 대소문자는 가리지 않는다. `clock`이 `None`이면 시스템 시계.
pub fn verify_webhook<'a>(
    secrets: &[&str],
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    raw_body: &[u8],
    clock: Option<&dyn Clock>,
) -> Result<WebhookVerification, Error> {
    let (mut id, mut timestamp, mut signatures) = (None, None, None);
    for (name, value) in headers {
        match name.to_ascii_lowercase().as_str() {
            "webhook-id" => id = Some(value),
            "webhook-timestamp" => timestamp = Some(value),
            "webhook-signature" => signatures = Some(value),
            _ => {}
        }
    }
    let (Some(id), Some(timestamp), Some(signatures)) = (id, timestamp, signatures) else {
        return Err(Error::new(
            codes::WEBHOOK_INVALID,
            "웹훅 헤더(webhook-id · webhook-timestamp · webhook-signature)가 없다",
        ));
    };
    let now_ms = clock.map_or_else(|| SystemClock.now_ms(), |c| c.now_ms());
    let fresh = timestamp
        .parse::<i64>()
        .ok()
        .filter(|sent| (now_ms as f64 / 1000.0 - *sent as f64).abs() <= rules::WEBHOOK_TOLERANCE_SEC as f64);
    let Some(sent) = fresh else {
        return Err(Error::new(codes::WEBHOOK_INVALID, "웹훅 시각이 허용 범위 밖이다 — 재전송 공격일 수 있다"));
    };
    let candidates: Vec<Vec<u8>> = signatures
        .split_whitespace()
        .filter_map(|entry| entry.split_once(','))
        .filter(|(version, _)| *version == rules::WEBHOOK_SIGNATURE_VERSION)
        .filter_map(|(_, value)| STANDARD.decode(value).ok())
        .collect();
    let mut signed = format!("{id}.{timestamp}.").into_bytes();
    signed.extend_from_slice(raw_body);
    for secret in secrets {
        let Some(raw) = secret.strip_prefix(rules::WEBHOOK_SECRET_PREFIX) else {
            return Err(Error::new(
                codes::CONFIGURATION,
                format!("웹훅 시크릿은 {}로 시작한다", rules::WEBHOOK_SECRET_PREFIX),
            ));
        };
        let key =
            STANDARD.decode(raw).map_err(|e| Error::caused(codes::CONFIGURATION, "웹훅 시크릿을 읽지 못했다", e))?;
        for candidate in &candidates {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
                .map_err(|e| Error::caused(codes::CONFIGURATION, "웹훅 시크릿을 읽지 못했다", e.to_string()))?;
            mac.update(&signed);
            if mac.verify_slice(candidate).is_ok() {
                return Ok(WebhookVerification { id: id.to_owned(), timestamp: sent });
            }
        }
    }
    Err(Error::new(codes::WEBHOOK_INVALID, "웹훅 서명이 맞지 않는다"))
}

/// 판매자 서버의 토큰 검증이다(안내서 09장) — JWKS를 받아 캐시한다. 복제하면 같은 캐시다.
#[derive(Clone)]
pub struct ServerVerifier {
    verifier: Arc<Verifier>,
}

impl ServerVerifier {
    /// `ports`는 `transport` · `clock`만 쓴다(비우면 기본 구현).
    pub fn new(base_url: &str, client_id: &str, ports: Ports) -> Self {
        Self::with_user_agent(base_url, client_id, ports, None)
    }

    #[doc(hidden)]
    pub fn with_user_agent(base_url: &str, client_id: &str, ports: Ports, user_agent: Option<&str>) -> Self {
        let api = Arc::new(Api::new(base_url, ports.resolve(), user_agent));
        Self { verifier: Arc::new(Verifier::new(api, client_id, false)) }
    }

    /// access_token(`at+jwt`)을 검증한다.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, Error> {
        self.verifier.verify_access(token)
    }

    /// licenseToken을 검증한다. `min_generation` — 같은 sub · device_id에서 이미 본 가장 큰 세대번호(0이면 보지 않는다).
    pub fn verify_license_token(&self, token: &str, min_generation: i64) -> Result<LicenseClaims, Error> {
        self.verifier.verify_license(token, None, min_generation)
    }
}
