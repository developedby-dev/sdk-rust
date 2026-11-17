//! 운영체제 보안 저장소 실제 확인 — `BYDEV_KEYCHAIN_CHECK=1`일 때만(사용자 키체인을 건드린다 — launch-checklist A31). macOS 키체인 · Windows 자격 증명
//! 관리자 · Linux Secret Service에 항목 하나(서비스 `dev.developedby.sdk` · 계정 `bydev-keychain-check`)를 넣고 · 고치고 · 읽고 · 지운다.
#![cfg(feature = "keyring")]

use bydev::{CredentialRecord, CredentialStore, KeyringCredentialStore};

#[test]
fn real_keyring() {
    if std::env::var("BYDEV_KEYCHAIN_CHECK").as_deref() != Ok("1") {
        eprintln!("BYDEV_KEYCHAIN_CHECK=1이 아니라 건너뛴다");
        return;
    }
    let store = KeyringCredentialStore::new("bydev-keychain-check").expect("저장소를 만들지 못했다");
    store.clear().expect("시작 전 지우기");
    let record = CredentialRecord {
        version: 1,
        refresh_token: "rt_node_test_00000000001".into(),
        scope: "entitlement.read".into(),
        saved_at: "2026-10-06T13:00:00Z".into(),
    };
    let result = (|| -> Result<(), bydev::BoxError> {
        assert_eq!(store.load()?, None);
        store.save(&record)?;
        assert_eq!(store.load()?, Some(record.clone()));
        let rotated = CredentialRecord { refresh_token: "rt_keychain_rotated_000001".into(), ..record.clone() };
        store.save(&rotated)?;
        assert_eq!(store.load()?, Some(rotated));
        store.clear()?;
        assert_eq!(store.load()?, None);
        Ok(())
    })();
    store.clear().expect("끝난 뒤 지우기");
    result.expect("운영체제 보안 저장소");
}
