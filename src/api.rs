//! 명세 3 · 4절 — 요청 만들기 · 응답 읽기 · 발견 문서.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::USER_AGENT;
use crate::errors::{Error, wrap};
use crate::generated::{codes, routes};
use crate::models::{Discovery, read_discovery};
use crate::ports::{HttpRequest, Resolved, Signal};

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 한 번에 하나만 도는 작업이다 — 기다리는 쪽은 `Scheduler::wait`로 기다린다(명세 2절).
pub(crate) struct Single<T> {
    current: Mutex<Option<Arc<Flight<T>>>>,
}

struct Flight<T> {
    done: Signal,
    result: Mutex<Option<Result<T, Error>>>,
}

impl<T: Clone> Single<T> {
    pub fn new() -> Self {
        Self { current: Mutex::new(None) }
    }

    pub fn run(&self, ports: &Resolved, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let mut current = lock(&self.current);
        if let Some(flight) = current.clone() {
            drop(current);
            ports.scheduler.wait(&flight.done);
            return lock(&flight.result)
                .clone()
                .unwrap_or_else(|| Err(Error::new(codes::PROTOCOL_ERROR, "작업 결과가 없다")));
        }
        let flight = Arc::new(Flight { done: Signal::new(), result: Mutex::new(None) });
        *current = Some(flight.clone());
        drop(current);
        let result = f();
        *lock(&flight.result) = Some(result.clone());
        *lock(&self.current) = None;
        flight.done.fire();
        result
    }
}

pub(crate) struct ApiResponse {
    pub headers: BTreeMap<String, String>,
    pub json: Value,
}

#[derive(Default)]
pub(crate) struct Req<'a> {
    pub method: &'a str,
    pub url: String,
    pub body: Option<Value>,
    pub bearer: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

pub(crate) struct Api {
    pub base_url: String,
    pub ports: Resolved,
    user_agent: String,
    doc: Mutex<Option<Arc<Discovery>>>,
    discovering: Single<Arc<Discovery>>,
}

/// 경로 조각 — 예약되지 않은 문자(A–Z a–z 0–9 - . _ ~)만 그대로.
fn escape(text: &str, space_plus: bool) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b' ' if space_plus => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl Api {
    pub fn new(base_url: &str, ports: Resolved, user_agent: Option<&str>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            ports,
            user_agent: user_agent.unwrap_or(USER_AGENT).to_owned(),
            doc: Mutex::new(None),
            discovering: Single::new(),
        }
    }

    /// 경로 `{이름}`을 채우고 질의를 붙인다(이름순 — 언어마다 같은 URL).
    pub fn url(&self, path: &str, params: &[(&str, &str)], query: &[(&str, String)]) -> String {
        let mut out = self.base_url.clone();
        let mut rest = path;
        while let Some(i) = rest.find('{') {
            let j = rest[i..].find('}').map(|j| i + j).unwrap_or(rest.len());
            out.push_str(&rest[..i]);
            let name = &rest[i + 1..j];
            out.push_str(&escape(params.iter().find(|(k, _)| *k == name).map(|(_, v)| *v).unwrap_or(""), false));
            rest = rest.get(j + 1..).unwrap_or("");
        }
        out.push_str(rest);
        if !query.is_empty() {
            let mut q: Vec<_> = query.iter().collect();
            q.sort_by(|a, b| a.0.cmp(b.0));
            let pairs: Vec<String> =
                q.iter().map(|(k, v)| format!("{}={}", escape(k, true), escape(v, true))).collect();
            out.push('?');
            out.push_str(&pairs.join("&"));
        }
        out
    }

    /// 처음 한 번 받아 클라이언트 수명 동안 둔다. 실패하면 두지 않는다(명세 4절).
    pub fn discovery(&self) -> Result<Arc<Discovery>, Error> {
        if let Some(doc) = lock(&self.doc).clone() {
            return Ok(doc);
        }
        self.discovering.run(&self.ports, || {
            let url = format!("{}{}", self.base_url, routes::GET_OPEN_ID_CONFIGURATION.path);
            let res = self.send(Req { method: "GET", url, ..Req::default() })?;
            let doc = Arc::new(read_discovery(&res.json)?);
            if doc.issuer.trim_end_matches('/') != self.base_url {
                return Err(Error::new(
                    codes::CONFIGURATION,
                    format!("발견 문서의 issuer({})가 baseUrl({})과 다르다", doc.issuer, self.base_url),
                ));
            }
            *lock(&self.doc) = Some(doc.clone());
            Ok(doc)
        })
    }

    pub fn send(&self, req: Req<'_>) -> Result<ApiResponse, Error> {
        let mut headers = BTreeMap::new();
        headers.insert("accept".to_owned(), "application/json".to_owned());
        headers.insert("user-agent".to_owned(), self.user_agent.clone());
        let body = match &req.body {
            Some(value) => {
                headers.insert("content-type".to_owned(), "application/json".to_owned());
                Some(
                    serde_json::to_vec(value)
                        .map_err(|e| Error::caused(codes::CONFIGURATION, "본문을 만들지 못했다", e))?,
                )
            }
            None => None,
        };
        if let Some(bearer) = req.bearer {
            headers.insert("authorization".to_owned(), format!("Bearer {bearer}"));
        }
        if let Some(key) = req.idempotency_key {
            headers.insert("idempotency-key".to_owned(), key.to_owned());
        }
        let res = self
            .ports
            .transport
            .send(HttpRequest { method: req.method.to_owned(), url: req.url, headers, body })
            .map_err(|e| wrap(e, codes::NETWORK_ERROR, "API에 연결하지 못했다"))?;
        let correlation = res.headers.get("x-correlation-id").cloned();
        let parsed: Option<Value> = if res.body.is_empty() { None } else { serde_json::from_slice(&res.body).ok() };
        if (200..300).contains(&res.status) {
            let Some(json) = parsed else {
                let mut e = Error::new(codes::PROTOCOL_ERROR, "응답 본문이 JSON이 아니다");
                let i = e.inner_mut();
                i.http_status = Some(res.status);
                i.correlation_id = correlation;
                return Err(e);
            };
            return Ok(ApiResponse { headers: res.headers, json });
        }
        Err(error_from(res.status, &res.headers, parsed, correlation))
    }
}

/// 3.2절. 실패 응답 → [`Error`].
fn error_from(
    status: u16,
    headers: &BTreeMap<String, String>,
    parsed: Option<Value>,
    correlation: Option<String>,
) -> Error {
    let mut retry = headers.get("retry-after").and_then(|v| v.trim().parse::<u64>().ok()).filter(|n| *n > 0);
    if let Some(Value::Object(m)) = &parsed
        && let (Some(Value::String(code)), Some(Value::String(message))) = (m.get("code"), m.get("message"))
    {
        if let Some(n) = m.get("retryAfterSec").and_then(Value::as_f64) {
            retry = Some(n as u64);
        }
        let mut e = Error::new(code, message.clone());
        let i = e.inner_mut();
        i.http_status = Some(status);
        i.correlation_id = correlation;
        i.retry_after_sec = retry;
        i.details = m.get("details").and_then(Value::as_object).cloned();
        return e;
    }
    let code = if status >= 500 {
        codes::INTERNAL_ERROR
    } else if status == 429 {
        codes::RATE_LIMITED
    } else {
        codes::PROTOCOL_ERROR
    };
    let mut e = Error::new(code, format!("HTTP {status}"));
    let i = e.inner_mut();
    i.http_status = Some(status);
    i.correlation_id = correlation;
    i.retry_after_sec = retry;
    e
}

/// `round(base × (min + (max − min) × r))`, .5는 올림(명세 2절).
pub(crate) fn jittered(ports: &Resolved, base: Duration, min: f64, max: f64) -> Duration {
    let ms = base.as_millis() as f64 * (min + (max - min) * ports.random.float());
    Duration::from_millis((ms + 0.5).floor() as u64)
}

/// 초(소수 가능) → 밀리초, .5는 올림.
pub(crate) fn seconds(sec: f64) -> Duration {
    Duration::from_millis((sec * 1000.0 + 0.5).floor() as u64)
}
