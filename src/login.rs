//! 명세 5절 — 디바이스 로그인. 코드를 받은 순간부터 폴링하고 `wait`는 그 결과를 기다린다.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use crate::api::{Api, Req, jittered, lock};
use crate::errors::Error;
use crate::generated::{DEVICE_CODE_GRANT_TYPE, codes, rules};
use crate::models::{DeviceCode, read_token_response};
use crate::ports::{Cancel, Signal};
use crate::time::format_iso;
use crate::tokens::TokenManager;

/// 로그인이 끝났을 때 받은 스코프다.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LoginResult {
    pub scope: String,
}

/// 디바이스 플로우 하나다. 화면에 `user_code` · `verification_uri_complete`(QR)를 보이고 `wait`로 기다린다. 복제하면 같은 시도다.
#[derive(Clone)]
pub struct LoginAttempt {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    /// 코드가 만료되는 시각(ISO 8601).
    pub expires_at: String,
    inner: Arc<Inner>,
}

struct Inner {
    expires_at_ms: i64,
    device_code: String,
    client_id: String,
    api: Arc<Api>,
    tokens: Arc<TokenManager>,
    done: Signal,
    state: Mutex<State>,
}

struct State {
    interval: i64,
    settled: bool,
    cancel: Option<Cancel>,
    result: Option<Result<LoginResult, Error>>,
}

impl LoginAttempt {
    pub(crate) fn start(code: DeviceCode, client_id: &str, api: Arc<Api>, tokens: Arc<TokenManager>) -> Self {
        let expires_at_ms = api.ports.clock.now_ms() + code.expires_in * 1000;
        let inner = Arc::new(Inner {
            expires_at_ms,
            device_code: code.device_code,
            client_id: client_id.to_owned(),
            api,
            tokens,
            done: Signal::new(),
            state: Mutex::new(State { interval: code.interval, settled: false, cancel: None, result: None }),
        });
        Inner::schedule_poll(&inner);
        Self {
            user_code: code.user_code,
            verification_uri: code.verification_uri,
            verification_uri_complete: code.verification_uri_complete,
            expires_at: format_iso(expires_at_ms),
            inner,
        }
    }

    /// 로그인이 끝나기를 기다린다.
    pub fn wait(&self) -> Result<LoginResult, Error> {
        self.inner.api.ports.scheduler.wait(&self.inner.done);
        lock(&self.inner.state)
            .result
            .clone()
            .unwrap_or_else(|| Err(Error::new(codes::LOGIN_CANCELLED, "로그인을 취소했다")))
    }

    /// 로그인을 취소한다 — `wait`는 `LOGIN_CANCELLED`로 끝난다.
    pub fn cancel(&self) {
        self.inner.finish(Err(Error::new(codes::LOGIN_CANCELLED, "로그인을 취소했다")));
    }
}

impl Inner {
    fn finish(&self, result: Result<LoginResult, Error>) {
        let cancel = {
            let mut state = lock(&self.state);
            if state.settled {
                return;
            }
            state.settled = true;
            state.result = Some(result);
            state.cancel.take()
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        self.done.fire();
    }

    fn settled(&self) -> bool {
        lock(&self.state).settled
    }

    /// 폴링 지터는 위로만(interval보다 이르면 SLOW_DOWN이다).
    fn schedule_poll(self: &Arc<Self>) {
        let interval = lock(&self.state).interval;
        let ports = &self.api.ports;
        let delay = jittered(
            ports,
            Duration::from_secs(interval.max(0) as u64),
            rules::LOGIN_POLL_JITTER_MIN,
            rules::LOGIN_POLL_JITTER_MAX,
        );
        if ports.clock.now_ms() + delay.as_millis() as i64 > self.expires_at_ms {
            self.finish(Err(Error::new(codes::EXPIRED_TOKEN, "로그인 코드가 만료됐다 — 처음부터 다시")));
            return;
        }
        let me = self.clone();
        let cancel = ports.scheduler.after(delay, Box::new(move || me.poll()));
        let mut state = lock(&self.state);
        if state.settled {
            drop(state);
            cancel.cancel();
            return;
        }
        state.cancel = Some(cancel);
    }

    fn poll(self: &Arc<Self>) {
        if self.settled() {
            return;
        }
        let outcome = self.api.discovery().and_then(|doc| {
            let body =
                json!({ "grant_type": DEVICE_CODE_GRANT_TYPE, "client_id": self.client_id, "device_code": self.device_code });
            self.api.send(Req { method: "POST", url: doc.token_endpoint.clone(), body: Some(body), ..Req::default() })
        });
        if self.settled() {
            return;
        }
        let e = match outcome {
            Ok(res) => {
                let result = read_token_response(&res.json).and_then(|set| {
                    self.tokens.adopt(&set)?;
                    Ok(LoginResult { scope: set.scope })
                });
                self.finish(result);
                return;
            }
            Err(e) => e,
        };
        if e.code() == codes::AUTHORIZATION_PENDING || e.is_transient() {
            self.schedule_poll();
        } else if e.code() == codes::SLOW_DOWN {
            {
                let mut state = lock(&self.state);
                match e.retry_after_sec() {
                    Some(n) if n > 0 => state.interval = n as i64,
                    _ => state.interval += rules::LOGIN_SLOW_DOWN_INCREMENT_SEC,
                }
            }
            self.schedule_poll();
        } else {
            self.finish(Err(e));
        }
    }
}
