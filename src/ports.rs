//! 명세 2절 — 바꿔 끼울 수 있는 포트. SDK 안에서 시계 · 타이머 · 난수를 직접 읽지 않는다.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 포트가 내는 에러.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 전송 포트가 보낼 요청이다. `body`가 `None`이면 본문이 없다.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// 받은 응답이다. 헤더 이름은 소문자다.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// 요청을 보낸다. 연결 실패 · 시간 초과는 `NETWORK_ERROR` [`crate::Error`]로 돌려준다(다른 에러도 `NETWORK_ERROR`로 감싼다). 3xx를 따라가지 않는다.
pub trait Transport: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError>;
}

/// 보안 저장소에 두는 기록이다(명세 3.6). access_token은 두지 않는다.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRecord {
    pub version: i64,
    pub refresh_token: String,
    pub scope: String,
    pub saved_at: String,
}

/// 로그인 기록을 둔다. 없으면 `load`가 `None`을 돌려준다. 실패는 SDK가 `STORAGE_FAILED`로 감싼다.
pub trait CredentialStore: Send + Sync {
    fn load(&self) -> Result<Option<CredentialRecord>, BoxError>;
    fn save(&self, record: &CredentialRecord) -> Result<(), BoxError>;
    fn clear(&self) -> Result<(), BoxError>;
}

/// 지금 시각(Unix 밀리초)이다.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

/// 예약 작업.
pub type Task = Box<dyn FnOnce() + Send + 'static>;

/// 예약 취소. 떨어뜨리면 취소하지 않는다 — `cancel()`을 부른다.
pub struct Cancel(Option<Box<dyn FnOnce() + Send + 'static>>);

impl Cancel {
    pub fn new(cancel: impl FnOnce() + Send + 'static) -> Self {
        Self(Some(Box::new(cancel)))
    }

    pub fn cancel(mut self) {
        if let Some(cancel) = self.0.take() {
            cancel();
        }
    }
}

/// 한 번 켜지는 신호 — 다른 작업의 끝(single-flight · 로그인)을 기다릴 때 쓴다. 복제하면 같은 신호다.
#[derive(Clone, Default)]
pub struct Signal(Arc<(Mutex<bool>, Condvar)>);

impl Signal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fire(&self) {
        let (lock, cvar) = &*self.0;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cvar.notify_all();
    }

    pub fn is_fired(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 켜질 때까지 막는다 — SDK는 이것을 직접 부르지 않고 [`Scheduler::wait`]를 거친다.
    pub fn block(&self) {
        let (lock, cvar) = &*self.0;
        let mut fired = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*fired {
            fired = cvar.wait(fired).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// 켜지거나 시간이 다 될 때까지 막는다. 켜졌으면 `true`.
    pub fn block_timeout(&self, timeout: Duration) -> bool {
        let (lock, cvar) = &*self.0;
        let fired = lock.lock().unwrap_or_else(|e| e.into_inner());
        let (fired, _) = cvar.wait_timeout_while(fired, timeout, |f| !*f).unwrap_or_else(|e| e.into_inner());
        *fired
    }
}

/// 나중 작업 · 기다림이다. SDK가 시간이나 다른 작업을 기다리는 곳은 모두 `sleep` · `wait`를 거친다(명세 2절 — 블로킹 언어).
pub trait Scheduler: Send + Sync {
    fn after(&self, delay: Duration, task: Task) -> Cancel;
    fn sleep(&self, delay: Duration);
    fn wait(&self, done: &Signal);
}

/// `[0, 1)` 실수와 UUID v4다.
pub trait Random: Send + Sync {
    fn float(&self) -> f64;
    fn uuid(&self) -> String;
}

/// 운영체제의 기기 식별자다. 없으면 `None` — 원본은 SDK 밖으로 나가지 않는다(해시만, 명세 10절).
pub trait FingerprintSource: Send + Sync {
    fn read(&self) -> Result<Option<String>, BoxError>;
}

/// 토큰 · 지문 출처 값은 넘어오지 않는다.
pub trait Logger: Send + Sync {
    fn debug(&self, message: &str);
    fn info(&self, message: &str);
    fn warn(&self, message: &str);
}

/// 클라이언트가 쓰는 포트 묶음이다. 비운 칸은 기본 구현이다.
#[derive(Clone, Default)]
pub struct Ports {
    pub transport: Option<Arc<dyn Transport>>,
    pub store: Option<Arc<dyn CredentialStore>>,
    pub clock: Option<Arc<dyn Clock>>,
    pub scheduler: Option<Arc<dyn Scheduler>>,
    pub random: Option<Arc<dyn Random>>,
    pub fingerprint: Option<Arc<dyn FingerprintSource>>,
    pub logger: Option<Arc<dyn Logger>>,
}

/// 기본값을 채운 포트.
#[derive(Clone)]
pub(crate) struct Resolved {
    pub transport: Arc<dyn Transport>,
    pub store: Arc<dyn CredentialStore>,
    pub clock: Arc<dyn Clock>,
    pub scheduler: Arc<dyn Scheduler>,
    pub random: Arc<dyn Random>,
    pub fingerprint: Arc<dyn FingerprintSource>,
    pub logger: Arc<dyn Logger>,
}

impl Ports {
    pub(crate) fn resolve(self) -> Resolved {
        use crate::defaults::*;
        Resolved {
            transport: self.transport.unwrap_or_else(|| Arc::new(UreqTransport::new(None))),
            store: self.store.unwrap_or_else(|| Arc::new(MemoryStore::new(None))),
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            scheduler: self.scheduler.unwrap_or_else(|| Arc::new(ThreadScheduler)),
            random: self.random.unwrap_or_else(|| Arc::new(CryptoRandom)),
            fingerprint: self.fingerprint.unwrap_or_else(|| Arc::new(NoFingerprint)),
            logger: self.logger.unwrap_or_else(|| Arc::new(NopLogger)),
        }
    }
}
