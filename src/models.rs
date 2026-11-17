//! 공개 API 응답의 SDK 모델 — JSON 이름은 contracts 그대로, 없을 수 있는 값은 `Option`. 열거 값은 `String`(모르는 값도 — 명세 0절 5,
//! 아는 값은 생성된 상수 모듈 `entitlement_status` 등).

use serde::Serialize;
use serde::ser::SerializeMap;
use serde_json::{Map, Value};

use crate::errors::Error;
use crate::generated::{install_mode, update_coverage_type};
use crate::read::{Reader, field as f};

/// 기간이다. `kind`를 먼저 분기한다 — 영구(`PERPETUAL`)는 잔여 필드가 `None`이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementTerm {
    #[serde(rename = "type")]
    pub kind: String,
    pub expires_at: Option<String>,
    pub remaining_days: Option<i64>,
    pub remaining_seconds: Option<i64>,
}

/// 구독형일 때만 있다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementSubscription {
    pub id: String,
    pub status: String,
    pub will_renew: bool,
    pub next_billing_at: Option<String>,
    pub grace_ends_at: Option<String>,
}

/// 판매자가 정한 정책 수치다 — 앱에 하드코딩하지 않는다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicensePolicy {
    pub max_devices: i64,
    pub max_concurrent: i64,
    pub heartbeat_sec: i64,
    pub offline_grace_hours: i64,
}

/// 업데이트 제공 범위다(ADR-0049). `kind()`를 먼저 분기한다 — `Until`이면 `until` 전에 출시된 버전을 실행할 수 있다. 모르는 종류면
/// `Other`(종류 이름만).
#[derive(Clone, Debug, PartialEq)]
pub enum UpdateCoverage {
    /// 모든 업데이트 포함.
    All,
    /// `until`(ISO 8601) 전에 출시된 버전까지.
    Until {
        until: String,
    },
    Other {
        kind: String,
    },
}

impl UpdateCoverage {
    /// `type` 값 — `ALL` · `UNTIL` …
    pub fn kind(&self) -> &str {
        match self {
            Self::All => update_coverage_type::ALL,
            Self::Until { .. } => update_coverage_type::UNTIL,
            Self::Other { kind } => kind,
        }
    }
}

/// 계약의 판별 유니온 모양 — 종류마다 그 종류의 필드만.
impl Serialize for UpdateCoverage {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("type", self.kind())?;
        if let Self::Until { until } = self {
            m.serialize_entry("until", until)?;
        }
        m.end()
    }
}

/// 이 제품의 이용권이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entitlement {
    pub id: String,
    pub product_id: String,
    pub status: String,
    pub term: EntitlementTerm,
    pub update_coverage: UpdateCoverage,
    pub subscription: Option<EntitlementSubscription>,
    pub policy: LicensePolicy,
    pub evaluated_at: String,
}

pub(crate) fn read_entitlement_response(json: &Value) -> Result<Entitlement, Error> {
    let mut r = Reader::default();
    let root = r.object(json, "$");
    let e = r.object(f(root, "entitlement"), "entitlement");
    let t = r.object(f(e, "term"), "entitlement.term");
    let kind = r.str(f(t, "type"), "entitlement.term.type");
    let mut term = EntitlementTerm { kind, expires_at: None, remaining_days: None, remaining_seconds: None };
    if term.kind != "PERPETUAL" {
        term.expires_at = r.opt_str(f(t, "expiresAt"), "entitlement.term.expiresAt");
        term.remaining_days = r.opt_int(f(t, "remainingDays"), "entitlement.term.remainingDays");
        term.remaining_seconds = r.opt_int(f(t, "remainingSeconds"), "entitlement.term.remainingSeconds");
    }
    let c = r.object(f(e, "updateCoverage"), "entitlement.updateCoverage");
    let coverage = r.str(f(c, "type"), "entitlement.updateCoverage.type");
    let update_coverage = match coverage.as_str() {
        update_coverage_type::ALL => UpdateCoverage::All,
        update_coverage_type::UNTIL => {
            UpdateCoverage::Until { until: r.str(f(c, "until"), "entitlement.updateCoverage.until") }
        }
        _ => UpdateCoverage::Other { kind: coverage },
    };
    let p = r.object(f(e, "policy"), "entitlement.policy");
    let policy = LicensePolicy {
        max_devices: r.int(f(p, "maxDevices"), "entitlement.policy.maxDevices"),
        max_concurrent: r.int(f(p, "maxConcurrent"), "entitlement.policy.maxConcurrent"),
        heartbeat_sec: r.int(f(p, "heartbeatSec"), "entitlement.policy.heartbeatSec"),
        offline_grace_hours: r.int(f(p, "offlineGraceHours"), "entitlement.policy.offlineGraceHours"),
    };
    let subscription = match f(e, "subscription") {
        Value::Null => None,
        sub => {
            let s = r.object(sub, "entitlement.subscription");
            Some(EntitlementSubscription {
                id: r.str(f(s, "id"), "entitlement.subscription.id"),
                status: r.str(f(s, "status"), "entitlement.subscription.status"),
                will_renew: r.bool(f(s, "willRenew"), "entitlement.subscription.willRenew"),
                next_billing_at: r.opt_str(f(s, "nextBillingAt"), "entitlement.subscription.nextBillingAt"),
                grace_ends_at: r.opt_str(f(s, "graceEndsAt"), "entitlement.subscription.graceEndsAt"),
            })
        }
    };
    let out = Entitlement {
        id: r.str(f(e, "id"), "entitlement.id"),
        product_id: r.str(f(e, "productId"), "entitlement.productId"),
        status: r.str(f(e, "status"), "entitlement.status"),
        term,
        update_coverage,
        subscription,
        policy,
        evaluated_at: r.str(f(e, "evaluatedAt"), "entitlement.evaluatedAt"),
    };
    r.finish(out)
}

/// 등록된 기기다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub registered_at: String,
    pub last_seen_at: String,
}

/// 기기 목록 한 쪽이다. `next_cursor`가 `None`이면 마지막 쪽이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePage {
    pub items: Vec<Device>,
    pub next_cursor: Option<String>,
}

pub(crate) fn read_device_page(json: &Value) -> Result<DevicePage, Error> {
    let mut r = Reader::default();
    let page = r.object(json, "$");
    let mut items = Vec::new();
    for v in r.array(f(page, "items"), "items") {
        let d = r.object(v, "items[]");
        items.push(Device {
            id: r.str(f(d, "id"), "items[].id"),
            name: r.str(f(d, "name"), "items[].name"),
            platform: r.str(f(d, "platform"), "items[].platform"),
            registered_at: r.str(f(d, "registeredAt"), "items[].registeredAt"),
            last_seen_at: r.str(f(d, "lastSeenAt"), "items[].lastSeenAt"),
        });
    }
    let next_cursor = r.opt_str(f(page, "nextCursor"), "nextCursor");
    r.finish(DevicePage { items, next_cursor })
}

/// 기기 해제 결과다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRelease {
    pub id: String,
    pub status: String,
    pub released_at: String,
}

pub(crate) fn read_device_release(json: &Value) -> Result<DeviceRelease, Error> {
    let mut r = Reader::default();
    let root = r.object(json, "$");
    let d = r.object(f(root, "device"), "device");
    let out = DeviceRelease {
        id: r.str(f(d, "id"), "device.id"),
        status: r.str(f(d, "status"), "device.status"),
        released_at: r.str(f(d, "releasedAt"), "device.releasedAt"),
    };
    r.finish(out)
}

/// 닉네임과 가명 식별자다. `pseudonymous_id`를 판매자 쪽 고객 키로 쓴다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub pseudonymous_id: String,
    pub nickname: String,
    pub email: Option<String>,
}

pub(crate) fn read_profile_response(json: &Value) -> Result<Profile, Error> {
    let mut r = Reader::default();
    let root = r.object(json, "$");
    let p = r.object(f(root, "profile"), "profile");
    let out = Profile {
        pseudonymous_id: r.str(f(p, "pseudonymousId"), "profile.pseudonymousId"),
        nickname: r.str(f(p, "nickname"), "profile.nickname"),
        email: r.opt_str(f(p, "email"), "profile.email"),
    };
    r.finish(out)
}

/// 외부 채널의 설치 위치다.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExternalChannel {
    pub channel: String,
    pub locator: String,
}

/// 설치 방법이다. 모르는 방식이면 `Other`(방식 이름만).
#[derive(Clone, Debug, PartialEq)]
pub enum ProductInstall {
    Hosted { build_id: String, download_url: String, download_url_expires_at: String, sha256: String, size_bytes: i64 },
    External { channels: Vec<ExternalChannel> },
    Other { mode: String },
}

impl ProductInstall {
    pub fn mode(&self) -> &str {
        match self {
            Self::Hosted { .. } => install_mode::HOSTED,
            Self::External { .. } => install_mode::EXTERNAL,
            Self::Other { mode } => mode,
        }
    }
}

/// 계약의 판별 유니온 모양 — 방식마다 그 방식의 필드만.
impl Serialize for ProductInstall {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("mode", self.mode())?;
        match self {
            Self::Hosted { build_id, download_url, download_url_expires_at, sha256, size_bytes } => {
                m.serialize_entry("buildId", build_id)?;
                m.serialize_entry("downloadUrl", download_url)?;
                m.serialize_entry("downloadUrlExpiresAt", download_url_expires_at)?;
                m.serialize_entry("sha256", sha256)?;
                m.serialize_entry("sizeBytes", size_bytes)?;
            }
            Self::External { channels } => m.serialize_entry("channels", channels)?,
            Self::Other { .. } => {}
        }
        m.end()
    }
}

/// 최신 버전.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLatest {
    pub version: String,
    pub released_at: String,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct IdOnly {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct StatusOnly {
    pub status: String,
}

/// 최신 버전 · 업데이트 판정 · 설치 방법이다 — 업데이트 확인의 최상위와 `entitled.release`가 같은 모양이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UpdateRelease {
    pub latest: UpdateLatest,
    update: StatusOnly,
    pub install: ProductInstall,
}

impl UpdateRelease {
    /// `update_status` 값 — `NONE` · `AVAILABLE` · `REQUIRED` …
    pub fn update_status(&self) -> &str {
        &self.update.status
    }
}

/// 업데이트 제공 기한이 있는 구매자에게만 오는 값이다(ADR-0049 4절). 있으면 앱은 최상위 대신 `release`를 따른다 — 최상위 최신은 그 구매자가
/// 실행할 수 없는 버전일 수 있다(범위 밖 버전을 설치하면 세션 획득이 `ENTITLEMENT_VERSION_NOT_COVERED`로 거절된다). 이 대상에 범위 안
/// 버전이 없으면 `release`는 `None`이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitledUpdate {
    pub covered_until: String,
    pub release: Option<UpdateRelease>,
}

/// 업데이트 확인 결과다. `entitled`가 있으면 `latest` · `update_status()` · `install` 대신 그 `release`를 따른다. `update_status()`가
/// `REQUIRED`면 업데이트 전까지 실행을 막는다.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UpdateCheck {
    product: IdOnly,
    pub target: String,
    pub latest: UpdateLatest,
    update: StatusOnly,
    pub install: ProductInstall,
    /// 업데이트 제공 기한이 있는 구매자에게만 있다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitled: Option<EntitledUpdate>,
}

impl UpdateCheck {
    pub fn product_id(&self) -> &str {
        &self.product.id
    }

    /// `update_status` 값 — `NONE` · `AVAILABLE` · `REQUIRED` …
    pub fn update_status(&self) -> &str {
        &self.update.status
    }
}

fn read_install(r: &mut Reader, json: &Value, path: &str) -> ProductInstall {
    let install = r.object(json, path);
    let mode = r.str(f(install, "mode"), &format!("{path}.mode"));
    match mode.as_str() {
        install_mode::HOSTED => ProductInstall::Hosted {
            build_id: r.str(f(install, "buildId"), &format!("{path}.buildId")),
            download_url: r.str(f(install, "downloadUrl"), &format!("{path}.downloadUrl")),
            download_url_expires_at: r.str(f(install, "downloadUrlExpiresAt"), &format!("{path}.downloadUrlExpiresAt")),
            sha256: r.str(f(install, "sha256"), &format!("{path}.sha256")),
            size_bytes: r.int(f(install, "sizeBytes"), &format!("{path}.sizeBytes")),
        },
        install_mode::EXTERNAL => {
            let mut channels = Vec::new();
            for v in r.array(f(install, "channels"), &format!("{path}.channels")) {
                let c = r.object(v, &format!("{path}.channels[]"));
                channels.push(ExternalChannel {
                    channel: r.str(f(c, "channel"), &format!("{path}.channels[].channel")),
                    locator: r.str(f(c, "locator"), &format!("{path}.channels[].locator")),
                });
            }
            ProductInstall::External { channels }
        }
        _ => ProductInstall::Other { mode },
    }
}

/// `latest` · `update` · `install` — `prefix`는 오류 경로 앞에 붙인다(최상위는 빈 문자열).
fn read_release(r: &mut Reader, o: &Map<String, Value>, prefix: &str) -> UpdateRelease {
    let latest = r.object(f(o, "latest"), &format!("{prefix}latest"));
    let latest = UpdateLatest {
        version: r.str(f(latest, "version"), &format!("{prefix}latest.version")),
        released_at: r.str(f(latest, "releasedAt"), &format!("{prefix}latest.releasedAt")),
        notes: r.opt_str(f(latest, "notes"), &format!("{prefix}latest.notes")),
    };
    let update = r.object(f(o, "update"), &format!("{prefix}update"));
    let status = r.str(f(update, "status"), &format!("{prefix}update.status"));
    let install = read_install(r, f(o, "install"), &format!("{prefix}install"));
    UpdateRelease { latest, update: StatusOnly { status }, install }
}

pub(crate) fn read_update_check(json: &Value) -> Result<UpdateCheck, Error> {
    let mut r = Reader::default();
    let o = r.object(json, "$");
    let product = r.object(f(o, "product"), "product");
    let product_id = r.str(f(product, "id"), "product.id");
    let target = r.str(f(o, "target"), "target");
    let UpdateRelease { latest, update, install } = read_release(&mut r, o, "");
    let entitled = match f(o, "entitled") {
        Value::Null => None,
        v => {
            let e = r.object(v, "entitled");
            let covered_until = r.str(f(e, "coveredUntil"), "entitled.coveredUntil");
            let release = match f(e, "release") {
                Value::Null => None,
                v => {
                    let release = r.object(v, "entitled.release");
                    Some(read_release(&mut r, release, "entitled.release."))
                }
            };
            Some(EntitledUpdate { covered_until, release })
        }
    };
    r.finish(UpdateCheck { product: IdOnly { id: product_id }, target, latest, update, install, entitled })
}

pub(crate) struct TokenSet {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
}

pub(crate) fn read_token_response(json: &Value) -> Result<TokenSet, Error> {
    let mut r = Reader::default();
    let t = r.object(json, "$");
    let out = TokenSet {
        access_token: r.str(f(t, "access_token"), "access_token"),
        expires_in: r.int(f(t, "expires_in"), "expires_in"),
        refresh_token: r.str(f(t, "refresh_token"), "refresh_token"),
        scope: r.str(f(t, "scope"), "scope"),
    };
    r.finish(out)
}

pub(crate) struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

pub(crate) fn read_device_code(json: &Value) -> Result<DeviceCode, Error> {
    let mut r = Reader::default();
    let d = r.object(json, "$");
    let out = DeviceCode {
        device_code: r.str(f(d, "device_code"), "device_code"),
        user_code: r.str(f(d, "user_code"), "user_code"),
        verification_uri: r.str(f(d, "verification_uri"), "verification_uri"),
        verification_uri_complete: r.str(f(d, "verification_uri_complete"), "verification_uri_complete"),
        expires_in: r.int(f(d, "expires_in"), "expires_in"),
        interval: r.int(f(d, "interval"), "interval"),
    };
    r.finish(out)
}

/// 세션(실행 리스)이다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub product_id: String,
    pub device_id: String,
    pub generation: i64,
    pub lease_expires_at: String,
    pub heartbeat_sec: i64,
}

/// 세션 보유 증명 JWT와 그 만료(오프라인 유예의 끝)다.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseTokenInfo {
    pub token: String,
    pub expires_at: String,
}

pub(crate) fn read_session_response(json: &Value) -> Result<(SessionInfo, LicenseTokenInfo), Error> {
    let mut r = Reader::default();
    let o = r.object(json, "$");
    let s = r.object(f(o, "session"), "session");
    let t = r.object(f(o, "licenseToken"), "licenseToken");
    let session = SessionInfo {
        id: r.str(f(s, "id"), "session.id"),
        product_id: r.str(f(s, "productId"), "session.productId"),
        device_id: r.str(f(s, "deviceId"), "session.deviceId"),
        generation: r.int(f(s, "generation"), "session.generation"),
        lease_expires_at: r.str(f(s, "leaseExpiresAt"), "session.leaseExpiresAt"),
        heartbeat_sec: r.int(f(s, "heartbeatSec"), "session.heartbeatSec"),
    };
    let token = LicenseTokenInfo {
        token: r.str(f(t, "token"), "licenseToken.token"),
        expires_at: r.str(f(t, "expiresAt"), "licenseToken.expiresAt"),
    };
    r.finish((session, token))
}

pub(crate) struct Discovery {
    pub issuer: String,
    pub jwks_uri: String,
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
}

pub(crate) fn read_discovery(json: &Value) -> Result<Discovery, Error> {
    let mut r = Reader::default();
    let d = r.object(json, "$");
    let out = Discovery {
        issuer: r.str(f(d, "issuer"), "issuer"),
        jwks_uri: r.str(f(d, "jwks_uri"), "jwks_uri"),
        device_authorization_endpoint: r.str(f(d, "device_authorization_endpoint"), "device_authorization_endpoint"),
        token_endpoint: r.str(f(d, "token_endpoint"), "token_endpoint"),
        revocation_endpoint: r.str(f(d, "revocation_endpoint"), "revocation_endpoint"),
    };
    r.finish(out)
}

/// 검증된 licenseToken 클레임이다(명세 9절).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LicenseClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub product_id: String,
    pub device_id: String,
    pub sid: String,
    pub generation: i64,
    pub iat: i64,
    pub exp: i64,
    /// 세션을 얻을 때 앱이 보낸 대상 · 버전으로 서버가 확정한 빌드다(ADR-0049). 확정하지 못했으면 `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
}

pub(crate) fn read_license_claims(json: &Value) -> Result<LicenseClaims, Error> {
    let mut r = Reader::default();
    let c = r.object(json, "claims");
    let out = LicenseClaims {
        iss: r.str(f(c, "iss"), "claims.iss"),
        sub: r.str(f(c, "sub"), "claims.sub"),
        aud: r.str(f(c, "aud"), "claims.aud"),
        product_id: r.str(f(c, "product_id"), "claims.product_id"),
        device_id: r.str(f(c, "device_id"), "claims.device_id"),
        sid: r.str(f(c, "sid"), "claims.sid"),
        generation: r.int(f(c, "generation"), "claims.generation"),
        iat: r.int(f(c, "iat"), "claims.iat"),
        exp: r.int(f(c, "exp"), "claims.exp"),
        build_id: r.opt_str(f(c, "build_id"), "claims.build_id"),
    };
    r.finish(out)
}

/// 검증된 access_token 클레임이다(명세 12절).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

pub(crate) fn read_access_claims(json: &Value) -> Result<AccessClaims, Error> {
    let mut r = Reader::default();
    let c = r.object(json, "claims");
    let out = AccessClaims {
        iss: r.str(f(c, "iss"), "claims.iss"),
        sub: r.str(f(c, "sub"), "claims.sub"),
        aud: r.str(f(c, "aud"), "claims.aud"),
        client_id: r.str(f(c, "client_id"), "claims.client_id"),
        scope: r.str(f(c, "scope"), "claims.scope"),
        iat: r.int(f(c, "iat"), "claims.iat"),
        exp: r.int(f(c, "exp"), "claims.exp"),
        jti: r.str(f(c, "jti"), "claims.jti"),
    };
    r.finish(out)
}
