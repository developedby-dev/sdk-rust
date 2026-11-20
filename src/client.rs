use std::sync::{Arc, Mutex};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::{Api, ApiResponse, Req, lock};
use crate::errors::Error;
use crate::generated::{codes, routes};
use crate::login::LoginAttempt;
use crate::models::*;
use crate::ports::Ports;
use crate::session::{AppInfo, DeviceInfo, Session};
use crate::tokens::TokenManager;
use crate::verify::Verifier;

/// 명세 1절의 설정이다.
#[derive(Clone, Default)]
pub struct Config {
    pub base_url: String,
    pub client_id: String,
    pub product_id: String,
    pub scopes: Vec<String>,
    /// 세션을 쓰면 필요하다.
    pub device: Option<DeviceInfo>,
    /// 실행 중인 앱의 배포 대상 · 버전이다 — 세션을 쓰면 준다(명세 1절 · ADR-0049).
    pub app: Option<AppInfo>,
    pub ports: Ports,
}

/// 데브 라이선스 API 클라이언트다. 서버 응답 하나의 참/거짓으로 기능을 열지 않는다 — `session().state()`와 검증된 토큰의 클레임을 쓴다.
/// 블로킹 API다. 복제하면 같은 클라이언트다(스레드 사이에 나눠 쓴다).
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    api: Arc<Api>,
    tokens: Arc<TokenManager>,
    verifier: Arc<Verifier>,
    login: Mutex<Option<LoginAttempt>>,
    session: Mutex<Option<Session>>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_user_agent(config, None)
    }

    /// 이 크레이트 위에 지은 다른 언어 SDK(C)가 자기 User-Agent(`bydev-c/<판>`)로 부른다 — 명세 3.1.
    #[doc(hidden)]
    pub fn with_user_agent(config: Config, user_agent: Option<&str>) -> Result<Self, Error> {
        if config.scopes.is_empty() {
            return Err(Error::new(codes::CONFIGURATION, "scopes가 비었다"));
        }
        let api = Arc::new(Api::new(&config.base_url, config.ports.clone().resolve(), user_agent));
        let tokens = Arc::new(TokenManager::new(api.clone(), &config.client_id));
        let verifier = Arc::new(Verifier::new(api.clone(), &config.client_id, true));
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                api,
                tokens,
                verifier,
                login: Mutex::new(None),
                session: Mutex::new(None),
            }),
        })
    }

    /// 디바이스 로그인을 시작한다(명세 5절). 진행 중인 로그인은 취소한다.
    pub fn start_login(&self) -> Result<LoginAttempt, Error> {
        if let Some(previous) = lock(&self.inner.login).take() {
            previous.cancel();
        }
        let api = &self.inner.api;
        let doc = api.discovery()?;
        let body = serde_json::json!({ "client_id": self.inner.config.client_id, "scope": self.inner.config.scopes.join(" ") });
        let res = api.send(Req {
            method: "POST",
            url: doc.device_authorization_endpoint.clone(),
            body: Some(body),
            ..Req::default()
        })?;
        let code = read_device_code(&res.json)?;
        let attempt = LoginAttempt::start(code, &self.inner.config.client_id, api.clone(), self.inner.tokens.clone());
        *lock(&self.inner.login) = Some(attempt.clone());
        Ok(attempt)
    }

    /// 저장된 로그인이 있는지다 — 이용 가능 여부가 아니다.
    pub fn has_credentials(&self) -> Result<bool, Error> {
        Ok(self.inner.tokens.load()?.is_some())
    }

    fn get(&self, path: &str, params: &[(&str, &str)], query: &[(&str, String)]) -> Result<Value, Error> {
        let api = &self.inner.api;
        let url = api.url(path, params, query);
        let res = self.inner.tokens.authed(|bearer| {
            api.send(Req { method: "GET", url: url.clone(), bearer: Some(bearer), ..Req::default() })
        })?;
        self.note_lease(&res);
        Ok(res.json)
    }

    fn note_lease(&self, res: &ApiResponse) {
        let session = lock(&self.inner.session).clone();
        if let Some(session) = session {
            session.note_lease(res.headers.get("x-lease-expires-at"));
        }
    }

    /// 이 제품의 이용권이다.
    pub fn entitlement(&self) -> Result<Entitlement, Error> {
        read_entitlement_response(&self.get(routes::GET_MY_ENTITLEMENT.path, &[], &[])?)
    }

    /// 등록된 기기 한 쪽이다. 다음 쪽을 저절로 따라가지 않는다.
    pub fn devices(&self, cursor: Option<&str>, limit: Option<u32>) -> Result<DevicePage, Error> {
        let mut query = Vec::new();
        if let Some(cursor) = cursor.filter(|c| !c.is_empty()) {
            query.push(("cursor", cursor.to_owned()));
        }
        if let Some(limit) = limit.filter(|l| *l > 0) {
            query.push(("limit", limit.to_string()));
        }
        read_device_page(&self.get(routes::LIST_DEVICES.path, &[], &query)?)
    }

    /// 기기를 해제한다(월 횟수 제한).
    pub fn release_device(&self, device_id: &str) -> Result<DeviceRelease, Error> {
        let api = &self.inner.api;
        let key = api.ports.random.uuid();
        let url = api.url(routes::RELEASE_DEVICE.path, &[("deviceId", device_id)], &[]);
        let res = self.inner.tokens.authed(|bearer| {
            api.send(Req {
                method: "DELETE",
                url: url.clone(),
                bearer: Some(bearer),
                idempotency_key: Some(&key),
                ..Req::default()
            })
        })?;
        self.note_lease(&res);
        read_device_release(&res.json)
    }

    /// 닉네임과 가명 식별자다.
    pub fn profile(&self) -> Result<Profile, Error> {
        read_profile_response(&self.get(routes::GET_PROFILE.path, &[], &[])?)
    }

    /// 업데이트 확인이다. `entitled`가 있으면 그 `release`를 따른다. `update_status()`가 `REQUIRED`면 업데이트 전까지 실행을 막는다. 받은
    /// 파일은 설치 전에 `verify_download`.
    pub fn check_for_update(&self, target: &str, current_version: &str) -> Result<UpdateCheck, Error> {
        let query = [("target", target.to_owned()), ("currentVersion", current_version.to_owned())];
        let product_id = self.inner.config.product_id.clone();
        read_update_check(&self.get(routes::GET_PRODUCT_UPDATES.path, &[("id", &product_id)], &query)?)
    }

    /// 내려받은 파일의 SHA-256을 확인한다 — 다르면 `DOWNLOAD_INTEGRITY`.
    pub fn verify_download(&self, data: &[u8], sha256: &str) -> Result<(), Error> {
        let digest: String = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect();
        if digest != sha256.to_ascii_lowercase() {
            return Err(Error::new(codes::DOWNLOAD_INTEGRITY, "내려받은 파일의 SHA-256이 다르다 — 설치하지 않는다"));
        }
        Ok(())
    }

    /// licenseToken을 검증한다(명세 9절) — 앱이 기능 코드 여러 곳에서 다시 검증할 때.
    pub fn verify_token(&self, token: &str) -> Result<LicenseClaims, Error> {
        self.inner.verifier.verify_license(token, None, 0)
    }

    /// 세션을 멈추고 폐기 요청을 한 번 보낸 뒤 기록을 지운다. 서버 폐기에 성공했는지를 돌려준다.
    pub fn logout(&self) -> Result<bool, Error> {
        if let Some(login) = lock(&self.inner.login).take() {
            login.cancel();
        }
        let session = lock(&self.inner.session).clone();
        if let Some(session) = session {
            session.stop();
        }
        self.inner.tokens.logout()
    }

    /// 이 클라이언트의 세션이다(하나뿐).
    pub fn session(&self) -> Result<Session, Error> {
        let mut slot = lock(&self.inner.session);
        if let Some(session) = slot.as_ref() {
            return Ok(session.clone());
        }
        let Some(device) = self.inner.config.device.clone() else {
            return Err(Error::new(codes::CONFIGURATION, "세션을 쓰려면 device { name, platform }을 준다"));
        };
        let i = &self.inner;
        let session = Session::new(i.api.clone(), i.tokens.clone(), i.verifier.clone(), device, i.config.app.clone());
        *slot = Some(session.clone());
        Ok(session)
    }
}
