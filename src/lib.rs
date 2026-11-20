//! 데브 라이선스 API의 공식 Rust SDK.
//!
//! 디바이스 로그인 · refresh_token 회전 · 세션 리스(하트비트) · licenseToken 검증 · 업데이트 확인을 `sdks/spec` 동작 명세대로 한다.
//! API는 블로킹이다(스레드 · 타이머) — 비동기 앱(Tauri 등)은 `spawn_blocking`에서 부른다. 이용 가능 여부를 참/거짓 하나로 알리지 않는다 —
//! 세션 상태와 검증된 토큰의 클레임을 쓴다.

mod api;
mod client;
mod defaults;
mod errors;
#[rustfmt::skip]
mod generated;
mod login;
mod models;
mod platform;
mod ports;
mod read;
mod server;
mod session;
mod time;
mod tokens;
mod verify;

pub use client::{Client, Config};
pub use defaults::{CryptoRandom, MemoryStore, NopLogger, SystemClock, ThreadScheduler, UreqTransport};
pub use errors::Error;
pub use generated::*;
pub use login::{LoginAttempt, LoginResult};
pub use models::{
    AccessClaims, Device, DevicePage, DeviceRelease, EntitledUpdate, Entitlement, EntitlementSubscription,
    EntitlementTerm, ExternalChannel, LicenseClaims, LicensePolicy, LicenseTokenInfo, ProductInstall, Profile,
    SessionInfo, UpdateCheck, UpdateCoverage, UpdateLatest, UpdateRelease,
};
#[cfg(feature = "keyring")]
pub use platform::KeyringCredentialStore;
pub use platform::{
    FileCredentialStore, OsFingerprintSource, app_data_dir, default_credential_store, system_device_info,
};
pub use ports::{
    BoxError, Cancel, Clock, CredentialRecord, CredentialStore, FingerprintSource, HttpRequest, HttpResponse, Logger,
    Ports, Random, Scheduler, Signal, Task, Transport,
};
pub use server::{ServerVerifier, WebhookVerification, verify_webhook};
pub use session::{
    ActiveSession, ActiveState, AppInfo, DegradedState, DeviceInfo, ErrorView, LockedState, NeedsDecisionState,
    Session, SessionState, Subscription,
};
pub use time::{format_iso, parse_iso};

/// User-Agent(`bydev-rust/<판>`)에 실린다.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 모든 요청에 싣는 값이다(명세 3.1).
pub const USER_AGENT: &str = concat!("bydev-rust/", env!("CARGO_PKG_VERSION"));
