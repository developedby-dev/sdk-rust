//! 명세 2절 — 기본 구현. 운영체제별 저장소 · 지문 출처는 앱이 고른다(`platform`).

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::Error;
use crate::generated::{codes, rules};
use crate::ports::*;

/// 시스템 시계 — SDK에서 시계를 직접 읽는 유일한 곳.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
    }
}

/// 예약마다 스레드 하나로 기다리는 스케줄러. 취소하면 그 스레드는 작업 없이 끝난다.
pub struct ThreadScheduler;

impl Scheduler for ThreadScheduler {
    fn after(&self, delay: Duration, task: Task) -> Cancel {
        let cancelled = Signal::new();
        let flag = cancelled.clone();
        std::thread::spawn(move || {
            if !flag.block_timeout(delay) {
                task();
            }
        });
        Cancel::new(move || cancelled.fire())
    }

    fn sleep(&self, delay: Duration) {
        std::thread::sleep(delay);
    }

    fn wait(&self, done: &Signal) {
        done.block();
    }
}

/// 운영체제 난수(getrandom).
pub struct CryptoRandom;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // 운영체제 난수를 읽지 못하는 환경은 없다고 본다 — 읽지 못하면 그 자리에서 멈춘다
    getrandom::fill(&mut b).expect("운영체제 난수를 읽지 못했다");
    b
}

impl Random for CryptoRandom {
    fn float(&self) -> f64 {
        (u64::from_be_bytes(random_bytes::<8>()) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn uuid(&self) -> String {
        let mut b = random_bytes::<16>();
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }
}

/// `ureq` 기반 전송이다(TLS는 기능 `rustls` · `native-tls`, 신뢰 저장소는 `platform-verifier`). 리다이렉트를 따라가지 않는다.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// `timeout`이 `None`이면 `rules::HTTP_TIMEOUT_SEC`.
    pub fn new(timeout: Option<Duration>) -> Self {
        let timeout = timeout.unwrap_or(Duration::from_secs(rules::HTTP_TIMEOUT_SEC as u64));
        let builder = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false);
        #[cfg(feature = "platform-verifier")]
        let builder = builder
            .tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build());
        let config = builder.build();
        Self { agent: config.into() }
    }
}

impl Transport for UreqTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
        let mut builder = ureq::http::Request::builder().method(request.method.as_str()).uri(&request.url);
        for (k, v) in &request.headers {
            builder = builder.header(k, v);
        }
        let built = builder
            .body(request.body.unwrap_or_default())
            .map_err(|e| Error::caused(codes::CONFIGURATION, "요청을 만들지 못했다", e))?;
        let mut response =
            self.agent.run(built).map_err(|e| Error::caused(codes::NETWORK_ERROR, "API에 연결하지 못했다", e))?;
        let mut headers = BTreeMap::new();
        for (k, v) in response.headers() {
            let value = String::from_utf8_lossy(v.as_bytes()).into_owned();
            headers
                .entry(k.as_str().to_ascii_lowercase())
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(&value);
                })
                .or_insert(value);
        }
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .read_to_end(&mut body)
            .map_err(|e| Error::caused(codes::NETWORK_ERROR, "응답을 끝까지 받지 못했다", e))?;
        Ok(HttpResponse { status: response.status().as_u16(), headers, body })
    }
}

/// 메모리 저장소 — 앱을 끄면 로그인이 사라진다. 시험 · 짧은 CLI용.
pub struct MemoryStore(Mutex<Option<CredentialRecord>>);

impl MemoryStore {
    pub fn new(initial: Option<CredentialRecord>) -> Self {
        Self(Mutex::new(initial))
    }
}

impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<CredentialRecord>, BoxError> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn save(&self, record: &CredentialRecord) -> Result<(), BoxError> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(record.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), BoxError> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }
}

pub(crate) struct NoFingerprint;

impl FingerprintSource for NoFingerprint {
    fn read(&self) -> Result<Option<String>, BoxError> {
        Ok(None)
    }
}

/// 아무것도 하지 않는 로거.
pub struct NopLogger;

impl Logger for NopLogger {
    fn debug(&self, _: &str) {}
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
}
