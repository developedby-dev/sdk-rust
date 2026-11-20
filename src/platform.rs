//! 명세 2절 표 — 운영체제별 기본 구현. 원본 지문 · 토큰을 명령 줄 인자로 넘기지 않는다. 클라이언트의 기본 저장소는 메모리다 — 앱이 이 중에서 고른다
//! ([`default_credential_store`]).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::defaults::CryptoRandom;
use crate::generated::{device_platform, rules};
use crate::ports::{BoxError, CredentialRecord, CredentialStore, FingerprintSource, Logger, Random};
use crate::session::DeviceInfo;

/// 명령 실행 · 파일 — 단위 시험이 바꿔 끼운다.
pub(crate) trait Os: Send + Sync {
    fn name(&self) -> &str;
    fn exec(&self, program: &str, args: &[&str]) -> Result<String, BoxError>;
    fn read_file(&self, path: &Path) -> Result<Option<String>, BoxError>;
    fn write_file(&self, path: &Path, content: &str) -> Result<(), BoxError>;
    fn remove(&self, path: &Path) -> Result<(), BoxError>;
    fn new_id(&self) -> String;
    /// 지문 출처를 다시 읽기 전 기다림(명세 10절) — 단위 시험은 기다리지 않게 바꿔 끼운다
    fn sleep(&self, duration: std::time::Duration) {
        std::thread::sleep(duration);
    }
}

pub(crate) struct RealOs;

impl Os for RealOs {
    fn name(&self) -> &str {
        std::env::consts::OS
    }

    fn exec(&self, program: &str, args: &[&str]) -> Result<String, BoxError> {
        let out = Command::new(program).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(format!("{program}가 {}로 끝났다", out.status).into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn read_file(&self, path: &Path) -> Result<Option<String>, BoxError> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// 사용자만 읽는 권한(0600) · 임시 파일 뒤 이름 바꾸기(반쯤 쓴 파일이 남지 않게)
    fn write_file(&self, path: &Path, content: &str) -> Result<(), BoxError> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
        let temp = dir.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("bydev"),
            self.new_id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let result = (|| -> Result<(), BoxError> {
            let mut file = options.open(&temp)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    fn remove(&self, path: &Path) -> Result<(), BoxError> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    fn new_id(&self) -> String {
        CryptoRandom.uuid()
    }
}

/// 운영체제 · 앱 이름별 데이터 폴더다.
pub fn app_data_dir(app_name: &str) -> PathBuf {
    app_data_dir_for(app_name, std::env::consts::OS)
}

fn app_data_dir_for(app_name: &str, os: &str) -> PathBuf {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = env("HOME").or_else(|| env("USERPROFILE")).unwrap_or_else(|| PathBuf::from("."));
    match os {
        "windows" => env("APPDATA").unwrap_or_else(|| home.join("AppData").join("Roaming")).join(app_name),
        "macos" => home.join("Library").join("Application Support").join(app_name),
        _ => env("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")).join(app_name),
    }
}

/// `Config::device`의 기본값이다 — 호스트 이름(64자까지)과 운영체제.
pub fn system_device_info() -> DeviceInfo {
    device_info_for(&RealOs)
}

fn device_info_for(os: &dyn Os) -> DeviceInfo {
    let platform = match os.name() {
        "windows" => device_platform::WINDOWS,
        "macos" => device_platform::MACOS,
        "linux" => device_platform::LINUX,
        _ => device_platform::OTHER,
    };
    let host = if os.name() == "windows" {
        std::env::var("COMPUTERNAME").ok()
    } else {
        os.exec("hostname", &[]).ok().or_else(|| os.read_file(Path::new("/etc/hostname")).ok().flatten())
    };
    let name: String = host.map(|h| h.trim().to_owned()).filter(|h| !h.is_empty()).unwrap_or_else(|| "PC".to_owned());
    DeviceInfo { name: name.chars().take(64).collect(), platform: platform.to_owned() }
}

/// 명세 10절 · 2절 표의 지문 출처다 — Windows `MachineGuid` · macOS `IOPlatformUUID` · Linux `/etc/machine-id`. 읽지 못하면 `install_id_file`의
/// 설치 ID(없으면 만든다). 파일 자리가 없으면 `None`(SDK가 클라이언트 수명 동안의 난수 ID로 물러난다).
pub struct OsFingerprintSource {
    install_id_file: Option<PathBuf>,
    os: Arc<dyn Os>,
}

impl OsFingerprintSource {
    pub fn new(install_id_file: Option<PathBuf>) -> Self {
        Self { install_id_file, os: Arc::new(RealOs) }
    }

    #[cfg(test)]
    pub(crate) fn with_os(install_id_file: Option<PathBuf>, os: Arc<dyn Os>) -> Self {
        Self { install_id_file, os }
    }
}

fn after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.find(marker).map(|i| &text[i + marker.len()..])
}

fn machine_id(os: &dyn Os) -> Option<String> {
    let value = match os.name() {
        "windows" => {
            let out = os.exec("reg", &["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]).ok()?;
            after(&out, "REG_SZ")?.split_whitespace().next().map(str::to_owned)
        }
        "macos" => {
            let out = os.exec("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).ok()?;
            let rest = after(&out, "\"IOPlatformUUID\"")?;
            let rest = after(rest, "\"")?;
            rest.split('"').next().map(str::to_owned)
        }
        _ => ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .find_map(|p| os.read_file(Path::new(p)).ok().flatten().filter(|v| !v.trim().is_empty())),
    };
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

impl FingerprintSource for OsFingerprintSource {
    /// 실패하거나 빈 값이면 설치 ID로 물러나기 전에 다시 읽는다(명세 10절) — 일시적인 실패 하나로 같은 PC가 다른 기기가 되지 않게.
    fn read(&self) -> Result<Option<String>, BoxError> {
        for attempt in 0..rules::FINGERPRINT_SOURCE_READ_ATTEMPTS.max(1) {
            if attempt > 0 {
                self.os.sleep(std::time::Duration::from_millis(rules::FINGERPRINT_SOURCE_READ_RETRY_DELAY_MS as u64));
            }
            if let Some(value) = machine_id(self.os.as_ref()) {
                return Ok(Some(value));
            }
        }
        let Some(file) = &self.install_id_file else { return Ok(None) };
        if let Some(existing) = self.os.read_file(file)?.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
            return Ok(Some(existing));
        }
        let created = self.os.new_id();
        self.os.write_file(file, &created)?;
        Ok(Some(created))
    }
}

fn parse_record(text: Option<String>) -> Result<Option<CredentialRecord>, BoxError> {
    let Some(text) = text.filter(|t| !t.trim().is_empty()) else { return Ok(None) };
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let Ok(record) = serde_json::from_value::<CredentialRecord>(value) else { return Ok(None) };
    Ok((record.version == rules::STORAGE_RECORD_VERSION && !record.refresh_token.is_empty()).then_some(record))
}

/// 사용자 전용 권한(0600) 파일이다 — **암호화하지 않는다.** 같은 사용자로 도는 프로그램은 읽을 수 있다. 운영체제 보안 저장소를 쓸 수 없을 때만
/// (명세 2절 — warn 로그).
pub struct FileCredentialStore {
    path: PathBuf,
    os: Arc<dyn Os>,
}

impl FileCredentialStore {
    pub fn new(path: impl Into<PathBuf>, logger: Option<&dyn Logger>) -> Self {
        Self::with_os(path.into(), logger, Arc::new(RealOs))
    }

    pub(crate) fn with_os(path: PathBuf, logger: Option<&dyn Logger>, os: Arc<dyn Os>) -> Self {
        if let Some(logger) = logger {
            logger
                .warn("로그인 기록을 암호화하지 않은 사용자 전용 파일에 둔다 — 운영체제 보안 저장소를 쓸 수 없는 환경");
        }
        Self { path, os }
    }
}

impl CredentialStore for FileCredentialStore {
    fn load(&self) -> Result<Option<CredentialRecord>, BoxError> {
        parse_record(self.os.read_file(&self.path)?)
    }

    fn save(&self, record: &CredentialRecord) -> Result<(), BoxError> {
        self.os.write_file(&self.path, &serde_json::to_string(record)?)
    }

    fn clear(&self) -> Result<(), BoxError> {
        self.os.remove(&self.path)
    }
}

/// 운영체제 보안 저장소 — macOS 키체인 · Windows 자격 증명 관리자(DPAPI로 보호) · Linux Secret Service. 서비스 이름 `rules::STORAGE_SERVICE`,
/// 계정은 clientId(명세 2절). `keyring` 기능.
#[cfg(feature = "keyring")]
pub struct KeyringCredentialStore {
    entry: keyring::Entry,
}

#[cfg(feature = "keyring")]
impl KeyringCredentialStore {
    pub fn new(account: &str) -> Result<Self, BoxError> {
        Ok(Self { entry: keyring::Entry::new(rules::STORAGE_SERVICE, account)? })
    }
}

#[cfg(feature = "keyring")]
impl CredentialStore for KeyringCredentialStore {
    fn load(&self) -> Result<Option<CredentialRecord>, BoxError> {
        match self.entry.get_password() {
            Ok(text) => parse_record(Some(text)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, record: &CredentialRecord) -> Result<(), BoxError> {
        Ok(self.entry.set_password(&serde_json::to_string(record)?)?)
    }

    fn clear(&self) -> Result<(), BoxError> {
        match self.entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// 운영체제에 맞는 기본 저장소다 — `keyring` 기능이면 운영체제 보안 저장소(만들지 못하면 0600 파일 + warn), 아니면 0600 파일 + warn.
/// `account`는 clientId.
pub fn default_credential_store(
    app_name: &str,
    account: &str,
    logger: Option<&dyn Logger>,
) -> Arc<dyn CredentialStore> {
    #[cfg(feature = "keyring")]
    if let Ok(store) = KeyringCredentialStore::new(account) {
        return Arc::new(store);
    }
    let _ = account;
    Arc::new(FileCredentialStore::new(app_data_dir(app_name).join("bydev-credentials"), logger))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    struct FakeOs {
        name: &'static str,
        answers: HashMap<&'static str, Result<&'static str, &'static str>>,
        files: Mutex<HashMap<PathBuf, String>>,
        calls: Mutex<Vec<String>>,
        /// 있으면 명령마다 차례로 꺼내 쓴다(마지막 값을 되풀이)
        sequence: Mutex<Vec<Result<&'static str, &'static str>>>,
        slept: Mutex<Vec<std::time::Duration>>,
    }

    impl FakeOs {
        fn new(name: &'static str, answers: &[(&'static str, Result<&'static str, &'static str>)]) -> Arc<Self> {
            Arc::new(Self {
                name,
                answers: answers.iter().cloned().collect(),
                files: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                sequence: Mutex::new(Vec::new()),
                slept: Mutex::new(Vec::new()),
            })
        }

        fn with_sequence(name: &'static str, sequence: &[Result<&'static str, &'static str>]) -> Arc<Self> {
            let os = Self::new(name, &[]);
            *os.sequence.lock().unwrap() = sequence.to_vec();
            os
        }
    }

    impl Os for FakeOs {
        fn name(&self) -> &str {
            self.name
        }
        fn exec(&self, program: &str, args: &[&str]) -> Result<String, BoxError> {
            self.calls.lock().unwrap().push(format!("{program} {}", args.join(" ")));
            let mut sequence = self.sequence.lock().unwrap();
            if !sequence.is_empty() {
                let answer = if sequence.len() > 1 { sequence.remove(0) } else { sequence[0] };
                return answer.map(str::to_owned).map_err(Into::into);
            }
            drop(sequence);
            match self.answers.get(program) {
                Some(Ok(out)) => Ok((*out).to_owned()),
                Some(Err(e)) => Err((*e).into()),
                None => Err("없음".into()),
            }
        }
        fn read_file(&self, path: &Path) -> Result<Option<String>, BoxError> {
            Ok(self.files.lock().unwrap().get(path).cloned())
        }
        fn write_file(&self, path: &Path, content: &str) -> Result<(), BoxError> {
            self.files.lock().unwrap().insert(path.to_owned(), content.to_owned());
            Ok(())
        }
        fn remove(&self, path: &Path) -> Result<(), BoxError> {
            self.files.lock().unwrap().remove(path);
            Ok(())
        }
        fn new_id(&self) -> String {
            "00000000-0000-4000-8000-00000000abcd".to_owned()
        }
        fn sleep(&self, duration: std::time::Duration) {
            self.slept.lock().unwrap().push(duration);
        }
    }

    /// 1.2.0 — 2026-11-20 Windows에서 MachineGuid 읽기가 한 번 실패해 설치 ID로 등록됐다(같은 PC가 다른 기기)
    #[test]
    fn fingerprint_retries_before_install_id() {
        let guid = "    MachineGuid    REG_SZ    3f1e9a2b-1111-2222-3333-444455556666\r\n";
        let win = FakeOs::with_sequence("windows", &[Err("잠시 실패"), Ok(""), Ok(guid)]);
        let source = OsFingerprintSource::with_os(Some(PathBuf::from("/app/install-id")), win.clone());
        assert_eq!(source.read().unwrap().as_deref(), Some("3f1e9a2b-1111-2222-3333-444455556666"));
        assert!(win.files.lock().unwrap().is_empty(), "설치 ID를 만들지 않는다");
        assert_eq!(win.calls.lock().unwrap().len(), 3);
        let delay = std::time::Duration::from_millis(rules::FINGERPRINT_SOURCE_READ_RETRY_DELAY_MS as u64);
        assert_eq!(*win.slept.lock().unwrap(), vec![delay, delay]);

        let failing = FakeOs::with_sequence("windows", &[Err("계속 실패")]);
        let source = OsFingerprintSource::with_os(Some(PathBuf::from("/app/install-id")), failing.clone());
        assert_eq!(source.read().unwrap().as_deref(), Some("00000000-0000-4000-8000-00000000abcd"));
        assert_eq!(failing.calls.lock().unwrap().len() as i64, rules::FINGERPRINT_SOURCE_READ_ATTEMPTS);
    }

    #[test]
    fn fingerprint_per_os() {
        let win = FakeOs::new(
            "windows",
            &[(
                "reg",
                Ok(
                    "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    3f1e9a2b-1111-2222-3333-444455556666\r\n",
                ),
            )],
        );
        assert_eq!(
            OsFingerprintSource::with_os(None, win).read().unwrap().as_deref(),
            Some("3f1e9a2b-1111-2222-3333-444455556666")
        );
        let mac =
            FakeOs::new("macos", &[("ioreg", Ok("  \"IOPlatformUUID\" = \"A1B2C3D4-0000-1111-2222-333344445555\""))]);
        assert_eq!(
            OsFingerprintSource::with_os(None, mac).read().unwrap().as_deref(),
            Some("A1B2C3D4-0000-1111-2222-333344445555")
        );
        let linux = FakeOs::new("linux", &[]);
        linux
            .files
            .lock()
            .unwrap()
            .insert("/var/lib/dbus/machine-id".into(), "0123456789abcdef0123456789abcdef\n".into());
        assert_eq!(
            OsFingerprintSource::with_os(None, linux).read().unwrap().as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn fingerprint_install_id_fallback() {
        let os = FakeOs::new("macos", &[("ioreg", Err("권한 없음"))]);
        let source = OsFingerprintSource::with_os(Some("/app/install-id".into()), os.clone());
        assert_eq!(source.read().unwrap().as_deref(), Some("00000000-0000-4000-8000-00000000abcd"));
        os.files.lock().unwrap().insert("/app/install-id".into(), "kept-install-id\n".into());
        assert_eq!(source.read().unwrap().as_deref(), Some("kept-install-id"));
        assert_eq!(OsFingerprintSource::with_os(None, os).read().unwrap(), None);
    }

    #[test]
    fn file_store_real_disk() {
        let dir = std::env::temp_dir().join(format!("bydev-rust-test-{}", CryptoRandom.uuid()));
        let path = dir.join("sub").join("bydev-credentials");
        struct Warns(Mutex<u32>);
        impl Logger for Warns {
            fn debug(&self, _: &str) {}
            fn info(&self, _: &str) {}
            fn warn(&self, _: &str) {
                *self.0.lock().unwrap() += 1;
            }
        }
        let warns = Warns(Mutex::new(0));
        let store = FileCredentialStore::new(&path, Some(&warns));
        assert_eq!(*warns.0.lock().unwrap(), 1, "암호화하지 않는다는 warn");
        assert_eq!(store.load().unwrap(), None);
        let record = CredentialRecord {
            version: 1,
            refresh_token: "rt_rust_test_00000000001".into(),
            scope: "entitlement.read".into(),
            saved_at: "2026-10-06T13:00:00Z".into(),
        };
        store.save(&record).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(store.load().unwrap(), Some(record));
        std::fs::write(&path, r#"{"version":99,"refreshToken":"x","scope":"","savedAt":""}"#).unwrap();
        assert_eq!(store.load().unwrap(), None, "모르는 판은 없는 것으로");
        store.clear().unwrap();
        store.clear().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn device_info_and_dirs() {
        let mac = FakeOs::new("macos", &[("hostname", Ok("my-mac.local\n"))]);
        assert_eq!(device_info_for(mac.as_ref()), DeviceInfo { name: "my-mac.local".into(), platform: "MACOS".into() });
        assert!(app_data_dir_for("App", "macos").ends_with("Library/Application Support/App"));
    }

    #[test]
    fn this_machine_fingerprint() {
        if matches!(std::env::consts::OS, "macos" | "linux" | "windows") {
            assert!(OsFingerprintSource::new(None).read().unwrap().is_some(), "이 기기의 지문 출처를 읽지 못했다");
        }
    }
}
