# 데브 SDK: Rust

데브 라이선스 API의 공식 Rust SDK입니다. [공통 동작 명세](https://github.com/developedby-dev/sdk-spec/blob/main/spec/README.md)를 따르며, [적합성 시험 시나리오](https://github.com/developedby-dev/sdk-spec/tree/main/conformance/scenarios)를 모두 통과합니다.

C/C++ SDK는 이 크레이트 위에 C ABI를 얹어 만든 것입니다.

| 지원 | 버전 |
|---|---|
| 동작 명세 | 1.2.0 |
| API | v1 |
| Rust | 1.85 이상(에디션 2024), Windows, macOS, Linux |

크레이트 이름은 `bydev`입니다. 1.0.0부터는 판 규칙(SemVer)을 지켜, 호환되지 않는 변경은 주 판(2.0.0 등)을 올릴 때만 합니다. 0.x 판은 이름을 먼저
등록하려고 낸 미리보기이니 1.0.0 이상을 써 주세요.

**블로킹 API입니다.** 스레드와 타이머로 동작하므로 tokio 같은 비동기 런타임이 필요 없습니다.

Tauri 명령처럼 비동기로 도는 코드에서는 `spawn_blocking` 안에서
호출해 주세요.

## 빠른 시작

```rust
use std::sync::Arc;
use bydev::{AppInfo, Client, Config, Ports, SessionState, OsFingerprintSource};

let client = Client::new(Config {
    base_url: "https://api.developedby.dev".into(),
    client_id: "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW".into(), // 판매자 콘솔에서 제품마다 발급받습니다
    product_id: "prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD".into(),
    scopes: vec!["entitlement.read".into(), "session.write".into(), "version.read".into()],
    device: Some(bydev::system_device_info()),
    app: Some(AppInfo { target: "WINDOWS_X64".into(), version: "1.4.0".into() }), // 콘솔에 업로드한 빌드의 버전과 같게
    ports: Ports {
        store: Some(bydev::default_credential_store("MyApp", "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", None)),
        fingerprint: Some(Arc::new(OsFingerprintSource::new(Some(bydev::app_data_dir("MyApp").join("install-id"))))),
        ..Ports::default()
    },
})?;

if !client.has_credentials()? {
    let login = client.start_login()?;
    show_code(&login.user_code, &login.verification_uri_complete); // 화면에 코드와 QR 코드를 보여 줍니다
    login.wait()?; // 사용자가 브라우저에서 승인할 때까지 기다립니다
}

let session = client.session()?;
let _subscription = session.subscribe(|state| match state {
    SessionState::Active(s) => enable_features(&s.claims), // exp와 sid는 기능 코드에서 쓰고, 참/거짓 하나로만 판단하지 마세요
    SessionState::Degraded(s) => enable_features(&s.active.claims), // offline_until까지는 계속 쓸 수 있습니다
    SessionState::NeedsDecision(s) => ask_user(s), // DEVICE_IN_USE: "여기서 사용할까요?"에 동의하면 session.take_over()를 부릅니다
    SessionState::Locked(s) => lock_app(&s.code, s.correlation_id.as_deref()), // 오류 화면에 correlation_id를 보여 주세요
    _ => {}
});
session.start();
// 앱을 끌 때
session.stop();
```

구독 함수는 SDK의 스레드에서 불립니다. egui, Slint, Tauri처럼 UI 스레드가 따로 있는 프레임워크를 사용한다면, 받은 상태를 그 스레드로 넘겨 처리해 주세요.

## 기능(Cargo features)

| 기능 | 기본 | 설명 |
|---|---|---|
| `rustls` | ✓ | TLS를 순수 Rust로 처리합니다(암호 연산은 ring) |
| `native-tls` | | 운영체제의 TLS를 씁니다(SChannel, Security.framework, OpenSSL) |
| `platform-verifier` | | 서버 인증서를 운영체제의 신뢰 저장소로 확인합니다. 사내 프록시의 루트 인증서를 믿어야 할 때 쓰며, `rustls`와 함께 켭니다. |
| `keyring` | | `KeyringCredentialStore`를 제공합니다. macOS 키체인, Windows 자격 증명 관리자(DPAPI로 보호), Linux Secret Service(순수 Rust 구현이라 libdbus가 필요 없음)에 저장합니다. |

## 포트

| 포트 | 기본 구현 | 직접 구현하거나 설정할 항목 |
|---|---|---|
| `transport` | `UreqTransport`. 시간 초과는 30초이고, 리다이렉트를 따라가지 않습니다. | 프록시나 인증서 고정이 필요할 때 |
| `store` | **메모리**. 앱을 끄면 로그인이 사라집니다. | `default_credential_store`(`keyring` 기능을 켜면 운영체제 보안 저장소, 아니면 0600 파일과 경고), `FileCredentialStore`, `KeyringCredentialStore` |
| `fingerprint` | 없음. 실행할 때마다 새 기기로 보일 수 있습니다(경고 로그를 남깁니다) | `OsFingerprintSource`. MachineGuid, IOPlatformUUID, machine-id를 읽고, 못 읽으면 설치 ID 파일을 씁니다. |
| `clock`, `scheduler`, `random` | 시스템 시계, `ThreadScheduler`, 운영체제 난수 | 시험할 때 교체합니다. SDK는 시간이 지나기를 기다리거나 다른 작업을 기다릴 때 `Scheduler::sleep`과 `wait`만 씁니다. |
| `logger` | 로그 기록 없음 | 토큰과 기기 지문 원본은 로그로 넘어오지 않습니다. |

Windows 자격 증명 관리자는 **비밀번호로 로그인한 세션**에서만 열립니다. Windows 서비스나 SSH 키로 로그인한 세션에서는 `ERROR_NO_SUCH_LOGON_SESSION` 때문에
`STORAGE_FAILED`가 납니다.

사용자가 로그인한 화면에서 도는 데스크톱 앱은 문제없이 동작합니다. 그런 환경에서 돌리는 도구라면 `FileCredentialStore`를 넘겨 주세요.

## 판매자 서버

```rust
// 웹훅은 받은 본문을 그대로 넣어 검증합니다. 파싱했다가 다시 만든 바이트로는 서명이 맞지 않습니다.
// 시크릿을 교체하는 중이면 두 시크릿을 모두 넘기세요
let headers = request.headers().iter().filter_map(|(k, v)| Some((k.as_str(), v.to_str().ok()?)));
let event = bydev::verify_webhook(&[secret], headers, &raw_body, None)?;

// 앱이 보낸 access_token이나 licenseToken을 검증합니다. JWKS는 받아서 캐시해 둡니다
let verifier = bydev::ServerVerifier::new("https://api.developedby.dev", client_id, bydev::Ports::default());
let claims = verifier.verify_access_token(token)?;
```

## 사용 조건

- **업데이트**: `check_for_update(target, current_version)`가 반환한 `update_status()`가 `REQUIRED`이면, 업데이트하기 전까지 앱 실행을 막아 주세요. 받은
  파일은 설치하기 전에 `verify_download(&bytes, sha256)`로 확인해 주세요. `sha256`은 `ProductInstall::Hosted { sha256, .. }`에 들어 있습니다.
  업데이트 제공 기한이 있는 구매자는 결과에 `entitled`가 들어 있습니다. 그때는 최상위 대신 `entitled.release`를 따라 주세요.
  최상위 최신 버전은 그 구매자가 실행할 수 없는 버전일 수 있고, `entitled.release`가 비어 있으면 그 대상에 제공 범위 안의 버전이 없습니다.
- **오류**: `Error::code()`로 분기해 주세요. 코드 값은 생성된 `codes` 상수에 있습니다. `message()`는 화면에 보여 주는 용도로만 사용해 주세요. `is_transient()`가 참이면
  다시 시도해 볼 만한 오류입니다.
- **모르는 값**: 열거 값은 `String`입니다. 그래서 이 버전의 SDK가 모르는 새 값도 그대로 담깁니다.

  이미 알려진 값은 `entitlement_status::ACTIVE` 같은 상수
  모듈에 있습니다.
- 라이선스: MIT 또는 Apache-2.0.

## 출처 확인

이 꾸러미는 공개 저장소 `developedby-dev/sdk-rust`의 GitHub Actions가 판 태그에서 짓고 올립니다. crates.io에 올린 `.crate`에는 GitHub 출처 증명이 있습니다. 받은 파일을 `gh attestation verify <파일> --repo developedby-dev/sdk-rust`로 확인할 수 있습니다.
첫 판 0.1.0만은 예외입니다. crates.io의 신뢰 게시는 크레이트가 생긴 뒤에만 걸 수 있어 손으로 올렸고, 증명이 없습니다.

## 개발

| 명령 | 하는 일 |
|---|---|
| `cargo test --workspace` | 단위 시험과 통합 시험입니다. 실제 전송은 적합성 시험용 가짜 서버(HTTP 모드)를 node로 띄워 확인합니다. 쓸 node는 `BYDEV_NODE`로 바꿀 수 있습니다. |
| `pnpm sdk:check rust` | rustfmt, clippy(모든 기능), Windows와 Linux 대상 검사, 시험, 적합성 시나리오 48개를 확인합니다. |

`src/generated.rs`는 생성된 파일이며 `pnpm --filter @bydev/sdk-codegen generate`로 다시 만듭니다. rustfmt가 건드리지 않도록 `#[rustfmt::skip]`이 붙어 있습니다.
