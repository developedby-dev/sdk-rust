//! 명세 3.5 · 3.6 · 6절 — 기록 보관 · 갱신 · 인증 요청 감싸기 · 로그아웃.

use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::api::{Api, ApiResponse, Req, Single, lock, seconds};
use crate::errors::{Error, wrap};
use crate::generated::{codes, rules};
use crate::models::TokenSet;
use crate::ports::CredentialRecord;
use crate::time::format_iso;

struct AccessToken {
    token: String,
    expires_at_ms: i64,
}

pub(crate) struct TokenManager {
    pub api: Arc<Api>,
    client_id: String,
    access: Mutex<Option<AccessToken>>,
    refreshing: Single<String>,
}

fn storage(e: crate::ports::BoxError, message: &str) -> Error {
    let e = wrap(e, codes::STORAGE_FAILED, message);
    if e.code() == codes::STORAGE_FAILED { e } else { Error::caused(codes::STORAGE_FAILED, message, e) }
}

impl TokenManager {
    pub fn new(api: Arc<Api>, client_id: &str) -> Self {
        Self { api, client_id: client_id.to_owned(), access: Mutex::new(None), refreshing: Single::new() }
    }

    pub fn load(&self) -> Result<Option<CredentialRecord>, Error> {
        let record = self.api.ports.store.load().map_err(|e| storage(e, "보안 저장소를 읽지 못했다"))?;
        Ok(record.filter(|r| r.version == rules::STORAGE_RECORD_VERSION))
    }

    /// 6절 3 · 5절. 저장한 뒤에 쓴다.
    pub fn adopt(&self, set: &TokenSet) -> Result<(), Error> {
        *lock(&self.access) = None;
        let ports = &self.api.ports;
        let record = CredentialRecord {
            version: 1,
            refresh_token: set.refresh_token.clone(),
            scope: set.scope.clone(),
            saved_at: format_iso(ports.clock.now_ms()),
        };
        ports
            .store
            .save(&record)
            .map_err(|e| storage(e, "새 로그인을 보안 저장소에 두지 못했다 — 새 토큰을 쓰지 않는다"))?;
        *lock(&self.access) = Some(AccessToken {
            token: set.access_token.clone(),
            expires_at_ms: ports.clock.now_ms() + set.expires_in * 1000,
        });
        Ok(())
    }

    fn access_token(&self) -> Result<String, Error> {
        if let Some(a) = lock(&self.access).as_ref()
            && a.expires_at_ms - rules::TOKEN_REFRESH_SKEW_SEC * 1000 > self.api.ports.clock.now_ms()
        {
            return Ok(a.token.clone());
        }
        self.refresh()
    }

    /// 6절 1. 한 번에 하나.
    pub fn refresh(&self) -> Result<String, Error> {
        *lock(&self.access) = None;
        self.refreshing.run(&self.api.ports, || self.do_refresh())
    }

    fn do_refresh(&self) -> Result<String, Error> {
        let Some(record) = self.load()? else {
            return Err(Error::new(codes::NOT_SIGNED_IN, "로그인이 없다 — 먼저 로그인한다"));
        };
        let doc = self.api.discovery()?;
        let mut attempt = 0;
        loop {
            let body = json!({ "grant_type": "refresh_token", "client_id": self.client_id, "refresh_token": record.refresh_token });
            match self.api.send(Req {
                method: "POST",
                url: doc.token_endpoint.clone(),
                body: Some(body),
                ..Req::default()
            }) {
                Ok(res) => {
                    let set = crate::models::read_token_response(&res.json)?;
                    self.adopt(&set)?;
                    return Ok(set.access_token);
                }
                Err(e) if e.code() == codes::INVALID_GRANT => {
                    self.forget_stored();
                    return Err(e);
                }
                Err(e) => {
                    if !e.is_transient() || attempt >= rules::TOKEN_REFRESH_RETRY_DELAYS_SEC.len() {
                        return Err(e);
                    }
                    self.api.ports.scheduler.sleep(seconds(rules::TOKEN_REFRESH_RETRY_DELAYS_SEC[attempt]));
                    attempt += 1;
                }
            }
        }
    }

    /// 3.5절. 만료면 한 번만 갱신하고 다시 보낸다.
    pub fn authed(&self, send: impl Fn(&str) -> Result<ApiResponse, Error>) -> Result<ApiResponse, Error> {
        let token = self.access_token()?;
        match send(&token) {
            Err(e) if e.code() == codes::EXPIRED_TOKEN => {}
            other => return other,
        }
        let token = self.refresh()?;
        let result = send(&token);
        if matches!(&result, Err(e) if e.code() == codes::EXPIRED_TOKEN) {
            // 갓 받은 토큰도 거절됐다 — 다음 요청이 같은 토큰을 다시 쓰지 않게 버린다
            *lock(&self.access) = None;
        }
        result
    }

    fn forget_stored(&self) {
        *lock(&self.access) = None;
        if self.api.ports.store.clear().is_err() {
            self.api.ports.logger.warn("끝난 로그인의 기록을 지우지 못했다");
        }
    }

    /// 7절. 폐기 요청은 한 번, 결과와 상관없이 지운다. 서버가 폐기했는지를 돌려준다.
    pub fn logout(&self) -> Result<bool, Error> {
        let record = self.load()?;
        let mut revoked = false;
        if let Some(record) = record
            && let Ok(doc) = self.api.discovery()
        {
            let body = json!({ "client_id": self.client_id, "token": record.refresh_token, "token_type_hint": "refresh_token" });
            revoked = self
                .api
                .send(Req { method: "POST", url: doc.revocation_endpoint.clone(), body: Some(body), ..Req::default() })
                .is_ok();
        }
        *lock(&self.access) = None;
        self.api.ports.store.clear().map_err(|e| storage(e, "로그인 기록을 지우지 못했다"))?;
        Ok(revoked)
    }
}
