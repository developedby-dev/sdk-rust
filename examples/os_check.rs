//! 운영체제 포트 실제 확인 — Windows · Linux 기기에서 돌린다(launch-checklist A31 · ADR-0040 ⚠ 20 · 51). 사용자 보안 저장소를 건드리므로
//! `BYDEV_KEYCHAIN_CHECK=1`일 때만 — `BYDEV_KEYCHAIN_CHECK=1 cargo run --example os_check --no-default-features --features keyring`
//! (TLS를 쓰지 않는다 — 기본 기능 rustls의 ring은 Windows에서 C 컴파일러를 요구해 뺀다).
//!
//! 기본 저장소(`default_credential_store` — `keyring` 기능이면 Windows 자격 증명 관리자 · Linux Secret Service)에 항목 하나(계정
//! `bydev-keychain-check`)를 넣고 · 고치고 · 읽고 · 지운다. 보안 저장소 대신 0600 파일로 떨어지면(경고 로그 — `keyring` 기능 없이 지었을 때도)
//! 실패다. 지문 출처(`OsFingerprintSource` — MachineGuid · machine-id)가 설치 ID 파일 없이 운영체제 값을 읽고 두 번 읽어도 같은지 본다.
use std::process::ExitCode;
use std::sync::Mutex;

use bydev::{
    BoxError, CredentialRecord, FingerprintSource, Logger, OsFingerprintSource, app_data_dir, default_credential_store,
    system_device_info,
};

const APP: &str = "bydev-os-check";
const ACCOUNT: &str = "bydev-keychain-check";

#[derive(Default)]
struct Warnings(Mutex<Vec<String>>);

impl Logger for Warnings {
    fn debug(&self, _: &str) {}
    fn info(&self, _: &str) {}
    fn warn(&self, message: &str) {
        if let Ok(mut seen) = self.0.lock() {
            seen.push(message.to_owned());
        }
    }
}

fn main() -> ExitCode {
    if std::env::var("BYDEV_KEYCHAIN_CHECK").as_deref() != Ok("1") {
        println!("BYDEV_KEYCHAIN_CHECK=1이 아니라 건너뛴다 — 사용자 보안 저장소를 건드린다");
        return ExitCode::SUCCESS;
    }
    let os = std::env::consts::OS;
    if os != "windows" && os != "linux" {
        println!("{os}는 대상이 아니다 — Windows · Linux에서 돌린다");
        return ExitCode::SUCCESS;
    }
    let mut failures: Vec<String> = Vec::new();
    let device = system_device_info();
    println!("기기 {} · {}", device.name, device.platform);

    let fingerprint = OsFingerprintSource::new(None);
    match (fingerprint.read(), fingerprint.read()) {
        (Ok(Some(first)), Ok(Some(again))) if first == again && !first.is_empty() => {
            println!("✓ 지문 출처 — 운영체제 값(길이 {})을 읽었고 두 번 같다", first.len());
        }
        (Ok(Some(_)), Ok(Some(_))) => failures.push("지문 — 두 번 읽은 값이 다르다".into()),
        (first, again) => failures.push(format!("지문 — 운영체제 값을 읽지 못했다(설치 ID 없이): {first:?} {again:?}")),
    }

    let logger = Warnings::default();
    let store = default_credential_store(APP, ACCOUNT, Some(&logger));
    let record = CredentialRecord {
        version: 1,
        refresh_token: "rt_node_test_00000000001".into(),
        scope: "entitlement.read".into(),
        saved_at: "2026-10-06T13:00:00Z".into(),
    };
    let rotated = CredentialRecord { refresh_token: "rt_keychain_rotated_000001".into(), ..record.clone() };
    let result = (|| -> Result<Vec<String>, BoxError> {
        let mut found = Vec::new();
        store.clear()?;
        if store.load()?.is_some() {
            found.push("저장소 — 지운 뒤에도 항목이 있다".to_owned());
        }
        for want in [&record, &rotated] {
            store.save(want)?;
            if store.load()?.as_ref() != Some(want) {
                found.push("저장소 — 넣은 것을 읽지 못했다".to_owned());
            }
        }
        store.clear()?;
        if store.load()?.is_some() {
            found.push("저장소 — 지운 항목이 남았다".to_owned());
        }
        Ok(found)
    })();
    let _ = store.clear();
    let _ = std::fs::remove_dir_all(app_data_dir(APP));
    let warnings = logger.0.lock().map(|seen| seen.clone()).unwrap_or_default();
    match result {
        Err(e) => failures.push(format!("저장소 — {e}")),
        Ok(found) if !found.is_empty() => failures.extend(found),
        Ok(_) if !warnings.is_empty() => {
            failures.push(format!("저장소 — 보안 저장소가 아니라 파일로 떨어졌다: {}", warnings.join(" / ")));
        }
        Ok(_) => {
            let kind = if os == "windows" { "자격 증명 관리자" } else { "Secret Service" };
            println!("✓ 기본 저장소({kind}) — 넣기 · 고치기 · 읽기 · 지우기");
        }
    }
    for failure in &failures {
        println!("✗ {failure}");
    }
    if failures.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
