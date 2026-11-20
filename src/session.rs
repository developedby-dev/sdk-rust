//! 명세 8절 — 라이선스 세션(실행 리스) 상태 기계. 참/거짓 하나로 이용 가능을 알리지 않는다.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Api, Req, jittered, lock, seconds};
use crate::errors::Error;
use crate::generated::{codes, needs_decision_reason, routes, rules};
use crate::models::{LicenseClaims, LicenseTokenInfo, SessionInfo, read_session_response};
use crate::ports::Cancel;
use crate::time::parse_iso;
use crate::tokens::TokenManager;
use crate::verify::{Expectation, Verifier};

/// 상태에 싣는 에러다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorView {
    pub code: String,
    pub message: String,
    pub http_status: Option<u16>,
    pub correlation_id: Option<String>,
    pub retry_after_sec: Option<u64>,
    pub details: Option<Map<String, Value>>,
}

impl From<&Error> for ErrorView {
    fn from(e: &Error) -> Self {
        Self {
            code: e.code().to_owned(),
            message: e.message().to_owned(),
            http_status: e.http_status(),
            correlation_id: e.correlation_id().map(str::to_owned),
            retry_after_sec: e.retry_after_sec(),
            details: e.details().cloned(),
        }
    }
}

/// 리스를 쥔 상태 — 기능 코드는 `claims`(exp · sid)를 쓴다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveState {
    pub session: SessionInfo,
    pub license_token: LicenseTokenInfo,
    pub claims: LicenseClaims,
}

/// 하트비트가 실패하는 중 — `offline_until`까지는 계속 쓸 수 있다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DegradedState {
    #[serde(flatten)]
    pub active: ActiveState,
    pub consecutive_failures: u32,
    pub offline_until: String,
    pub last_error: Option<ErrorView>,
}

/// 지금 쓰는 다른 기기(인수 판단에 보인다).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveSession {
    pub device_id: String,
    pub device_name: String,
    pub last_seen_at: String,
}

/// 사용자 판단이 필요하다 — `DEVICE_IN_USE` · `INSTANCE_ALREADY_RUNNING`은 `take_over`, `DEVICE_LIMIT_EXCEEDED`는 기기 해제 뒤 `retry`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NeedsDecisionState {
    pub reason: String,
    pub active_session: Option<ActiveSession>,
    pub max_devices: Option<i64>,
    pub correlation_id: Option<String>,
}

/// 잠금 — 오류 화면에 `correlation_id`를 보인다. `retrying`이면 스스로 풀릴 수 있다(OFFLINE_EXPIRED).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockedState {
    pub code: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub details: Option<Map<String, Value>>,
    pub retrying: bool,
}

/// 세션 상태(판별 유니온, 명세 8.1절). JSON은 `{"type": "Active", …}`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum SessionState {
    #[serde(rename_all = "camelCase")]
    Starting {
        attempt: u32,
        last_error: Option<ErrorView>,
    },
    Active(ActiveState),
    Degraded(DegradedState),
    NeedsDecision(NeedsDecisionState),
    Locked(LockedState),
    Stopped,
}

/// 세션 획득 때 보내는 기기 정보다.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    pub platform: String,
}

/// 실행 중인 앱이다(명세 1절 · ADR-0049) — 배포 대상(업데이트 확인의 `target`과 같은 값 — `distribution_target::WINDOWS_X64` 등)과 콘솔에
/// 업로드한 버전 문자열. 세션 획득에 싣는다. 업데이트 제공 기한이 있는 영구 이용권은 이 값이 없으면 획득이
/// `ENTITLEMENT_VERSION_NOT_COVERED`로 거절된다.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppInfo {
    pub target: String,
    pub version: String,
}

type Listener = Arc<dyn Fn(&SessionState) + Send + Sync>;

/// 구독 — `unsubscribe`로 끊는다(떨어뜨리면 끊지 않는다).
pub struct Subscription {
    session: Session,
    id: u64,
}

impl Subscription {
    pub fn unsubscribe(self) {
        lock(&self.session.inner.state).listeners.retain(|(id, _)| *id != self.id);
    }
}

/// 라이선스 세션이다. `start` · `take_over` · `retry` · `stop`과 상태 구독. 구독 함수는 SDK의 스레드에서 불린다. 복제하면 같은 세션이다.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    api: Arc<Api>,
    tokens: Arc<TokenManager>,
    verifier: Arc<Verifier>,
    device: DeviceInfo,
    app: Option<AppInfo>,
    state: Mutex<State>,
}

struct State {
    current: SessionState,
    listeners: Vec<(u64, Listener)>,
    next_listener: u64,
    run: u64,
    instance: String,
    held: Option<ActiveState>,
    failures: u32,
    heartbeat: Option<Cancel>,
    offline: Option<Cancel>,
    fallback: Option<String>,
    /// 처음 계산한 지문 해시 — 한 실행 동안 다시 쓴다(명세 10절). 획득마다 다시 읽으면 일시적인 읽기 실패 하나로 다른 기기가 된다
    fingerprint: Option<String>,
}

impl State {
    fn cancel_timers(&mut self) {
        if let Some(c) = self.heartbeat.take() {
            c.cancel();
        }
        if let Some(c) = self.offline.take() {
            c.cancel();
        }
    }
}

impl Session {
    pub(crate) fn new(
        api: Arc<Api>,
        tokens: Arc<TokenManager>,
        verifier: Arc<Verifier>,
        device: DeviceInfo,
        app: Option<AppInfo>,
    ) -> Self {
        let state = State {
            current: SessionState::Stopped,
            listeners: Vec::new(),
            next_listener: 0,
            run: 0,
            instance: String::new(),
            held: None,
            failures: 0,
            heartbeat: None,
            offline: None,
            fallback: None,
            fingerprint: None,
        };
        Self { inner: Arc::new(Inner { api, tokens, verifier, device, app, state: Mutex::new(state) }) }
    }

    /// 지금 상태다.
    pub fn state(&self) -> SessionState {
        lock(&self.inner.state).current.clone()
    }

    /// 상태가 바뀔 때마다 부른다.
    pub fn subscribe(&self, listener: impl Fn(&SessionState) + Send + Sync + 'static) -> Subscription {
        let mut state = lock(&self.inner.state);
        let id = state.next_listener;
        state.next_listener += 1;
        state.listeners.push((id, Arc::new(listener)));
        Subscription { session: self.clone(), id }
    }

    /// `Stopped`에서만 의미가 있다(8.2절).
    pub fn start(&self) {
        {
            let mut state = lock(&self.inner.state);
            if state.current != SessionState::Stopped {
                return;
            }
            state.run += 1;
            state.instance = self.inner.api.ports.random.uuid();
        }
        Inner::begin_acquire(&self.inner, false, None);
    }

    /// `NeedsDecision`(다른 기기 · 같은 기기 실행 중) 또는 `Locked(SESSION_SUPERSEDED)`에서 인수한다 — 새 Idempotency-Key.
    pub fn take_over(&self) {
        let allowed = match self.state() {
            SessionState::NeedsDecision(s) => s.reason != needs_decision_reason::DEVICE_LIMIT_EXCEEDED,
            SessionState::Locked(s) => s.code == codes::SESSION_SUPERSEDED,
            _ => false,
        };
        if allowed {
            lock(&self.inner.state).run += 1;
            Inner::begin_acquire(&self.inner, true, None);
        }
    }

    /// `NeedsDecision`(기기 수) 또는 스스로 풀리지 않는 `Locked`에서 다시 얻는다.
    pub fn retry(&self) {
        let allowed = match self.state() {
            SessionState::NeedsDecision(s) => s.reason == needs_decision_reason::DEVICE_LIMIT_EXCEEDED,
            SessionState::Locked(s) => !s.retrying,
            _ => false,
        };
        if allowed {
            lock(&self.inner.state).run += 1;
            Inner::begin_acquire(&self.inner, false, None);
        }
    }

    /// 예약을 모두 취소하고 반납을 한 번 보낸다(8.7절).
    pub fn stop(&self) {
        let sid = {
            let mut state = lock(&self.inner.state);
            if state.current == SessionState::Stopped {
                return;
            }
            state.run += 1;
            state.cancel_timers();
            state.instance.clear();
            state.held.take().map(|h| h.session.id)
        };
        if let Some(sid) = sid {
            let api = &self.inner.api;
            let url = api.url(routes::RELEASE_SESSION.path, &[("sid", &sid)], &[]);
            let result = self.inner.tokens.authed(|bearer| {
                api.send(Req { method: "DELETE", url: url.clone(), bearer: Some(bearer), ..Req::default() })
            });
            if result.is_err() {
                api.ports.logger.debug("세션 반납을 보내지 못했다 — 리스가 저절로 빈다");
            }
        }
        self.inner.set_state(SessionState::Stopped);
    }

    /// 8.5절 — 다른 인증 응답의 `X-Lease-Expires-At`.
    pub(crate) fn note_lease(&self, value: Option<&String>) {
        let Some(value) = value.filter(|v| !v.is_empty()) else { return };
        let next = {
            let mut state = lock(&self.inner.state);
            if state.held.is_none() {
                return;
            }
            let mut next = state.current.clone();
            let session = match &mut next {
                SessionState::Active(a) => &mut a.session,
                SessionState::Degraded(d) => &mut d.active.session,
                _ => return,
            };
            if session.lease_expires_at == *value {
                return;
            }
            session.lease_expires_at = value.clone();
            if let Some(held) = state.held.as_mut() {
                held.session.lease_expires_at = value.clone();
            }
            next
        };
        self.inner.set_state(next);
    }
}

impl Inner {
    fn set_state(&self, next: SessionState) {
        let listeners: Vec<Listener> = {
            let mut state = lock(&self.state);
            if state.current == next {
                return;
            }
            state.current = next.clone();
            state.listeners.iter().map(|(_, l)| l.clone()).collect()
        };
        for listener in listeners {
            listener(&next);
        }
    }

    fn live(&self, run: u64) -> bool {
        lock(&self.state).run == run
    }

    fn after(self: &Arc<Self>, delay: Duration, task: impl FnOnce(Arc<Self>) + Send + 'static) {
        let me = self.clone();
        let cancel = self.api.ports.scheduler.after(delay, Box::new(move || task(me)));
        let old = lock(&self.state).heartbeat.replace(cancel);
        if let Some(old) = old {
            old.cancel();
        }
    }

    fn begin_acquire(self: &Arc<Self>, force: bool, last_error: Option<&Error>) {
        let run = {
            let mut state = lock(&self.state);
            state.cancel_timers();
            state.held = None;
            state.failures = 0;
            state.run
        };
        self.set_state(SessionState::Starting { attempt: 0, last_error: last_error.map(ErrorView::from) });
        let key = self.api.ports.random.uuid();
        self.after(Duration::ZERO, move |me| me.acquire(run, force, key, 0));
    }

    fn fingerprint_hash(&self) -> String {
        if let Some(cached) = lock(&self.state).fingerprint.clone() {
            return cached;
        }
        let computed = self.compute_fingerprint_hash();
        lock(&self.state).fingerprint.get_or_insert(computed).clone() // 동시에 계산했으면 먼저 정한 값
    }

    fn compute_fingerprint_hash(&self) -> String {
        let ports = &self.api.ports;
        let source = ports.fingerprint.read().ok().flatten().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        let value = match source {
            Some(v) => v,
            None => {
                let mut state = lock(&self.state);
                state
                    .fallback
                    .get_or_insert_with(|| {
                        ports.logger.warn(
                            "기기 지문 출처를 읽지 못해 이번 실행 동안만 쓰는 ID를 쓴다 — 출처 포트를 준다(명세 10절)",
                        );
                        ports.random.uuid()
                    })
                    .clone()
            }
        };
        let digest = Sha256::digest(format!("{value}{}", rules::FINGERPRINT_SALT).as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 8.2절. 일시적 실패의 재시도는 같은 키.
    fn acquire(self: &Arc<Self>, run: u64, force: bool, key: String, attempt: u32) {
        if !self.live(run) {
            return;
        }
        let instance = lock(&self.state).instance.clone();
        let mut body = json!({
            "device": { "fingerprintHash": self.fingerprint_hash(), "name": self.device.name, "platform": self.device.platform },
            "instanceId": instance,
            "force": force,
        });
        // 설정에 있을 때만(명세 1절 · ADR-0049) — 인수 · 재획득도 같다
        if let Some(app) = &self.app {
            body["app"] = json!({ "target": app.target, "version": app.version });
        }
        let api = &self.api;
        let url = api.url(routes::ACQUIRE_SESSION.path, &[], &[]);
        let result = self.tokens.authed(|bearer| {
            api.send(Req {
                method: "POST",
                url: url.clone(),
                body: Some(body.clone()),
                bearer: Some(bearer),
                idempotency_key: Some(&key),
            })
        });
        if !self.live(run) {
            return;
        }
        let error = match result.and_then(|res| self.adopt(run, &res.json)) {
            Ok(()) => return,
            Err(_) if !self.live(run) => return,
            Err(e) => e,
        };
        if error.is_transient() {
            let delays = rules::SESSION_START_RETRY_DELAYS_SEC;
            let base = delays[(attempt as usize).min(delays.len() - 1)];
            self.set_state(SessionState::Starting { attempt: attempt + 1, last_error: Some(ErrorView::from(&error)) });
            let delay = jittered(
                &api.ports,
                seconds(base),
                rules::SESSION_HEARTBEAT_JITTER_MIN,
                rules::SESSION_HEARTBEAT_JITTER_MAX,
            );
            self.after(delay, move |me| me.acquire(run, force, key, attempt + 1));
        } else if rules::NEEDS_DECISION_REASONS.contains(&error.code()) {
            let details = error.details();
            let active_session = details.and_then(|d| d.get("activeSession")).and_then(Value::as_object).map(|a| {
                let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
                ActiveSession { device_id: s("deviceId"), device_name: s("deviceName"), last_seen_at: s("lastSeenAt") }
            });
            let max_devices = details.and_then(|d| d.get("maxDevices")).and_then(Value::as_f64).map(|n| n as i64);
            self.set_state(SessionState::NeedsDecision(NeedsDecisionState {
                reason: error.code().to_owned(),
                active_session,
                max_devices,
                correlation_id: error.correlation_id().map(str::to_owned),
            }));
        } else {
            self.lock_with(&error, false);
        }
    }

    /// 200 응답 → 검증(9절) → Active → 다음 하트비트.
    fn adopt(self: &Arc<Self>, run: u64, json: &Value) -> Result<(), Error> {
        let (session, token) = read_session_response(json)?;
        let expect = Expectation { sid: &session.id, device_id: &session.device_id, generation: session.generation };
        let claims = self.verifier.verify_license(&token.token, Some(expect), 0)?;
        if !self.live(run) {
            return Ok(());
        }
        let heartbeat_sec = session.heartbeat_sec;
        let active = ActiveState { session, license_token: token, claims };
        {
            let mut state = lock(&self.state);
            state.held = Some(active.clone());
            state.failures = 0;
            if let Some(c) = state.offline.take() {
                c.cancel();
            }
        }
        self.set_state(SessionState::Active(active));
        self.schedule_heartbeat(run, heartbeat_sec, 0);
        Ok(())
    }

    fn schedule_heartbeat(self: &Arc<Self>, run: u64, heartbeat_sec: i64, retry_after_sec: u64) {
        let delay = jittered(
            &self.api.ports,
            Duration::from_secs(heartbeat_sec.max(0) as u64),
            rules::SESSION_HEARTBEAT_JITTER_MIN,
            rules::SESSION_HEARTBEAT_JITTER_MAX,
        )
        .max(Duration::from_secs(retry_after_sec));
        self.after(delay, move |me| me.beat(run));
    }

    /// 8.3절 하트비트.
    fn beat(self: &Arc<Self>, run: u64) {
        let held = {
            let state = lock(&self.state);
            match (&state.held, state.run == run) {
                (Some(held), true) => held.clone(),
                _ => return,
            }
        };
        let api = &self.api;
        let url = api.url(routes::HEARTBEAT_SESSION.path, &[("sid", &held.session.id)], &[]);
        let body = json!({ "generation": held.session.generation });
        let result = self.tokens.authed(|bearer| {
            api.send(Req {
                method: "POST",
                url: url.clone(),
                body: Some(body.clone()),
                bearer: Some(bearer),
                ..Req::default()
            })
        });
        if !self.live(run) {
            return;
        }
        let error = match result.and_then(|res| self.adopt(run, &res.json)) {
            Ok(()) => return,
            Err(_) if !self.live(run) => return,
            Err(e) => e,
        };
        if error.is_transient() {
            let (failures, holding) = {
                let mut state = lock(&self.state);
                state.failures += 1;
                (state.failures, matches!(state.current, SessionState::Active(_) | SessionState::Degraded(_)))
            };
            if holding {
                let offline_until = held.license_token.expires_at.clone();
                self.set_state(SessionState::Degraded(DegradedState {
                    active: held.clone(),
                    consecutive_failures: failures,
                    offline_until: offline_until.clone(),
                    last_error: Some(ErrorView::from(&error)),
                }));
                self.arm_offline_expiry(run, &offline_until);
            }
            let retry = if error.code() == codes::RATE_LIMITED || error.http_status() == Some(429) {
                error.retry_after_sec().unwrap_or(0)
            } else {
                0
            };
            self.schedule_heartbeat(run, held.session.heartbeat_sec, retry);
        } else if error.code() == codes::SESSION_REVOKED {
            // 리스가 끝났을 때도 이 코드다 — 한 번 다시 얻는다(같은 instanceId, 새 키)
            self.begin_acquire(false, Some(&error));
        } else {
            self.lock_with(&error, false);
        }
    }

    /// 8.4절. `offline_until`이 지나도록 성공하지 못하면 잠근다. 재시도는 그대로.
    fn arm_offline_expiry(self: &Arc<Self>, run: u64, offline_until: &str) {
        if lock(&self.state).offline.is_some() {
            return;
        }
        let now = self.api.ports.clock.now_ms();
        let delay = parse_iso(offline_until).map(|until| (until - now).max(0) as u64).unwrap_or(0);
        let me = self.clone();
        let cancel = self.api.ports.scheduler.after(
            Duration::from_millis(delay),
            Box::new(move || {
                let ok = {
                    let mut state = lock(&me.state);
                    state.offline = None;
                    state.run == run && matches!(state.current, SessionState::Degraded(_))
                };
                if ok {
                    me.set_state(SessionState::Locked(LockedState {
                        code: codes::OFFLINE_EXPIRED.to_owned(),
                        message: "하트비트에 성공하지 못한 채 licenseToken이 만료됐다".to_owned(),
                        correlation_id: None,
                        details: None,
                        retrying: true,
                    }));
                }
            }),
        );
        lock(&self.state).offline = Some(cancel);
    }

    fn lock_with(&self, error: &Error, retrying: bool) {
        lock(&self.state).cancel_timers();
        self.set_state(SessionState::Locked(LockedState {
            code: error.code().to_owned(),
            message: error.message().to_owned(),
            correlation_id: error.correlation_id().map(str::to_owned),
            details: error.details().cloned(),
            retrying,
        }));
    }
}
