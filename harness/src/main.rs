//! Rust SDK의 적합성 하네스(sdks/spec/harness-protocol.md). 표준 입출력 JSON 줄로 실행기와 이야기하며 SDK를 가상 시계 · 가상 스케줄러 ·
//! 대리 전송으로 몬다.
//!
//! 블로킹 언어의 정착 판정: SDK 일을 하는 스레드 수(`running`)를 세고, 전송 · `sleep` · `wait`에서 기다리는 스레드는 그 기다림의 신호를 등록한다.
//! `running`이 0이고, 답을 기다리는 요청이 없고, 등록된 신호가 하나도 켜지지 않았으면(깨어날 스레드가 없으면) 할 일이 없다.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bydev::{
    AppInfo, BoxError, Cancel, Client, Clock, Config, CredentialRecord, CredentialStore, DeviceInfo, Error,
    FingerprintSource, HttpRequest, HttpResponse, Logger, LoginAttempt, Ports, Random, Scheduler, Signal, Task,
    Transport,
};
use serde_json::{Value, json};

struct Timer {
    due: i64,
    seq: u64,
    task: Option<Task>,
    cancelled: Arc<Mutex<bool>>,
}

struct Exchange {
    done: Signal,
    response: Option<HttpResponse>,
}

#[derive(Default)]
struct State {
    now: i64,
    timers: Vec<Timer>,
    seq: u64,
    running: i64,
    waiters: HashMap<u64, Signal>,
    waiter_id: u64,
    pending: HashMap<String, Arc<Mutex<Exchange>>>,
    randoms: Vec<f64>,
    uuids: u64,
    http_seq: u64,
    record: Option<CredentialRecord>,
    fail_load: bool,
    fail_save: bool,
    fail_clear: bool,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));
static OUT: Mutex<()> = Mutex::new(());
static CLIENT: LazyLock<Mutex<Option<Client>>> = LazyLock::new(|| Mutex::new(None));
static LOGIN: LazyLock<Mutex<Option<LoginAttempt>>> = LazyLock::new(|| Mutex::new(None));

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn emit(message: Value) {
    let _guard = OUT.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{message}");
    let _ = out.flush();
}

fn fatal(message: impl Into<String>) -> ! {
    emit(json!({ "type": "fatal", "message": message.into() }));
    std::process::exit(1);
}

fn now_ms() -> i64 {
    state().now
}

/// SDK 스레드가 포트에서 기다리는 동안 `running`에서 빠지고 신호를 등록한다.
fn block(done: &Signal) {
    let id = {
        let mut s = state();
        s.running -= 1;
        s.waiter_id += 1;
        let id = s.waiter_id;
        s.waiters.insert(id, done.clone());
        id
    };
    done.block();
    let mut s = state();
    s.waiters.remove(&id);
    s.running += 1;
}

// ── 포트 ──────────────────────────────────────────────────────

struct VirtualClock;

impl Clock for VirtualClock {
    fn now_ms(&self) -> i64 {
        now_ms()
    }
}

struct VirtualScheduler;

impl Scheduler for VirtualScheduler {
    fn after(&self, delay: Duration, task: Task) -> Cancel {
        let cancelled = Arc::new(Mutex::new(false));
        let mut s = state();
        let timer =
            Timer { due: s.now + delay.as_millis() as i64, seq: s.seq, task: Some(task), cancelled: cancelled.clone() };
        s.seq += 1;
        s.timers.push(timer);
        Cancel::new(move || *cancelled.lock().unwrap_or_else(|e| e.into_inner()) = true)
    }

    fn sleep(&self, delay: Duration) {
        let done = Signal::new();
        let fire = done.clone();
        let _ = self.after(delay, Box::new(move || fire.fire()));
        block(&done);
    }

    fn wait(&self, done: &Signal) {
        block(done);
    }
}

struct ScenarioRandom;

impl Random for ScenarioRandom {
    fn float(&self) -> f64 {
        let mut s = state();
        if s.randoms.is_empty() {
            drop(s);
            fatal("시나리오의 random 값을 다 썼다 — random에 더 적는다");
        }
        s.randoms.remove(0)
    }

    fn uuid(&self) -> String {
        let mut s = state();
        s.uuids += 1;
        format!("00000000-0000-4000-8000-{:012x}", s.uuids)
    }
}

struct ProxyTransport;

impl Transport for ProxyTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, BoxError> {
        let exchange = Arc::new(Mutex::new(Exchange { done: Signal::new(), response: None }));
        let (id, at, done) = {
            let mut s = state();
            s.http_seq += 1;
            let id = format!("h{}", s.http_seq);
            s.pending.insert(id.clone(), exchange.clone());
            let done = exchange.lock().unwrap_or_else(|e| e.into_inner()).done.clone();
            (id, s.now, done)
        };
        let headers: BTreeMap<String, String> =
            request.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
        let body = request
            .body
            .as_ref()
            .map(|b| Value::String(String::from_utf8_lossy(b).into_owned()))
            .unwrap_or(Value::Null);
        emit(json!({
            "type": "http.request", "id": id, "now": at,
            "request": { "method": request.method, "url": request.url, "headers": headers, "body": body },
        }));
        block(&done);
        let response = exchange.lock().unwrap_or_else(|e| e.into_inner()).response.take();
        response.ok_or_else(|| "대리 전송 실패".into())
    }
}

struct ScenarioStore;

impl CredentialStore for ScenarioStore {
    fn load(&self) -> Result<Option<CredentialRecord>, BoxError> {
        let s = state();
        if s.fail_load {
            return Err("저장소 읽기 실패(시험)".into());
        }
        Ok(s.record.clone())
    }

    fn save(&self, record: &CredentialRecord) -> Result<(), BoxError> {
        let at = {
            let mut s = state();
            if s.fail_save {
                return Err("저장소 쓰기 실패(시험)".into());
            }
            s.record = Some(record.clone());
            s.now
        };
        emit(json!({ "type": "event", "now": at, "event": { "kind": "storage", "op": "save", "record": record } }));
        Ok(())
    }

    fn clear(&self) -> Result<(), BoxError> {
        let at = {
            let mut s = state();
            if s.fail_clear {
                return Err("저장소 지우기 실패(시험)".into());
            }
            s.record = None;
            s.now
        };
        emit(json!({ "type": "event", "now": at, "event": { "kind": "storage", "op": "clear" } }));
        Ok(())
    }
}

struct ScenarioFingerprint(Option<String>);

impl FingerprintSource for ScenarioFingerprint {
    fn read(&self) -> Result<Option<String>, BoxError> {
        Ok(self.0.clone())
    }
}

struct StderrLogger;

impl Logger for StderrLogger {
    fn debug(&self, _: &str) {}
    fn info(&self, _: &str) {}
    fn warn(&self, message: &str) {
        eprintln!("warn: {message}");
    }
}

// ── 정착 ──────────────────────────────────────────────────────

fn quiet(s: &State) -> bool {
    s.running == 0 && s.pending.is_empty() && !s.waiters.values().any(Signal::is_fired)
}

fn wait_quiet() {
    loop {
        if quiet(&state()) {
            return;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
}

/// `limit`까지 온, 취소되지 않은 가장 이른 예약을 꺼낸다.
fn take_timer(s: &mut State, limit: i64) -> Option<Task> {
    s.timers.retain(|t| !*t.cancelled.lock().unwrap_or_else(|e| e.into_inner()));
    let index = s
        .timers
        .iter()
        .enumerate()
        .filter(|(_, t)| t.due <= limit)
        .min_by_key(|(_, t)| (t.due, t.seq))
        .map(|(i, _)| i)?;
    let mut timer = s.timers.remove(index);
    timer.task.take()
}

fn next_due(s: &mut State, limit: i64) -> Option<i64> {
    s.timers.retain(|t| !*t.cancelled.lock().unwrap_or_else(|e| e.into_inner()));
    s.timers.iter().filter(|t| t.due <= limit).map(|t| t.due).min()
}

/// 지금 시각까지 온 예약 작업을 하나씩 — 앞 작업이 끝나거나 기다릴 때까지 — 돌린다.
fn settle() {
    loop {
        wait_quiet();
        let task = {
            let mut s = state();
            let now = s.now;
            let task = take_timer(&mut s, now);
            if task.is_some() {
                s.running += 1;
            }
            task
        };
        let Some(task) = task else { return };
        std::thread::spawn(move || {
            task();
            state().running -= 1;
        });
    }
}

fn advance(ms: i64) {
    let target = now_ms() + ms;
    loop {
        settle();
        let mut s = state();
        let Some(due) = next_due(&mut s, target) else { break };
        s.now = due;
    }
    state().now = target;
    settle();
}

// ── 호출 ──────────────────────────────────────────────────────

fn error_json(e: &Error) -> Value {
    json!({
        "code": e.code(), "message": e.message(), "httpStatus": e.http_status(), "correlationId": e.correlation_id(),
        "retryAfterSec": e.retry_after_sec(), "details": e.details(),
    })
}

fn client() -> Client {
    CLIENT.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| fatal("init 전에 호출했다"))
}

fn arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or_else(|| fatal(format!("인자 {key}가 문자열이 아니다")))
}

fn to_json<T: serde::Serialize>(r: Result<T, Error>) -> Result<Value, Error> {
    r.map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
}

fn invoke(method: &str, args: &Value) -> Result<Value, Error> {
    let c = client();
    let session = || c.session().unwrap_or_else(|e| fatal(format!("세션: {e}")));
    match method {
        "login.start" => {
            let attempt = c.start_login()?;
            let value = json!({
                "userCode": attempt.user_code, "verificationUri": attempt.verification_uri,
                "verificationUriComplete": attempt.verification_uri_complete, "expiresAt": attempt.expires_at,
            });
            *LOGIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(attempt);
            Ok(value)
        }
        "login.wait" => {
            let attempt = LOGIN.lock().unwrap_or_else(|e| e.into_inner()).clone();
            to_json(attempt.unwrap_or_else(|| fatal("login.start 전에 login.wait")).wait())
        }
        "login.cancel" => {
            if let Some(attempt) = LOGIN.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                attempt.cancel();
            }
            Ok(Value::Null)
        }
        "hasCredentials" => to_json(c.has_credentials()),
        "entitlement" => to_json(c.entitlement()),
        "devices" => {
            let cursor = args.get("cursor").and_then(Value::as_str);
            let limit = args.get("limit").and_then(Value::as_u64).map(|n| n as u32);
            to_json(c.devices(cursor, limit))
        }
        "releaseDevice" => to_json(c.release_device(arg(args, "deviceId"))),
        "profile" => to_json(c.profile()),
        "checkForUpdate" => to_json(c.check_for_update(arg(args, "target"), arg(args, "currentVersion"))),
        "verifyDownload" => {
            let data = STANDARD.decode(arg(args, "dataBase64")).unwrap_or_else(|e| fatal(format!("dataBase64: {e}")));
            c.verify_download(&data, arg(args, "sha256")).map(|()| Value::Null)
        }
        "verifyToken" => to_json(c.verify_token(arg(args, "token"))),
        "logout" => c.logout().map(|revoked| json!({ "serverRevoked": revoked })),
        "session.start" => {
            session().start();
            Ok(Value::Null)
        }
        "session.takeOver" => {
            session().take_over();
            Ok(Value::Null)
        }
        "session.retry" => {
            session().retry();
            Ok(Value::Null)
        }
        "session.stop" => {
            session().stop();
            Ok(Value::Null)
        }
        "session.state" => to_json(Ok(session().state())),
        other => fatal(format!("모르는 호출 {other}")),
    }
}

fn start_call(id: String, method: String, args: Value) {
    state().running += 1;
    std::thread::spawn(move || {
        let result = invoke(&method, &args);
        let at = now_ms();
        match result {
            Ok(value) => emit(json!({ "type": "result", "id": id, "now": at, "ok": true, "value": value })),
            Err(e) => emit(json!({ "type": "result", "id": id, "now": at, "ok": false, "error": error_json(&e) })),
        }
        state().running -= 1;
    });
}

// ── 명령 ──────────────────────────────────────────────────────

fn init(message: &Value) {
    let config = &message["config"];
    let text = |v: &Value, key: &str| v[key].as_str().unwrap_or_else(|| fatal(format!("init.{key}"))).to_owned();
    let started = bydev::parse_iso(message["now"].as_str().unwrap_or("")).unwrap_or_else(|| fatal("init.now"));
    {
        let mut s = state();
        s.now = started;
        s.randoms =
            message["random"].as_array().map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
        s.record = serde_json::from_value(message["storage"].clone()).ok();
    }
    let device = &config["device"];
    let client = Client::new(Config {
        base_url: text(config, "baseUrl"),
        client_id: text(config, "clientId"),
        product_id: text(config, "productId"),
        scopes: config["scopes"]
            .as_array()
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect())
            .unwrap_or_default(),
        device: Some(DeviceInfo { name: text(device, "name"), platform: text(device, "platform") }),
        // 시나리오가 적을 때만 온다
        app: match &config["app"] {
            Value::Null => None,
            app => Some(AppInfo { target: text(app, "target"), version: text(app, "version") }),
        },
        ports: Ports {
            transport: Some(Arc::new(ProxyTransport)),
            store: Some(Arc::new(ScenarioStore)),
            clock: Some(Arc::new(VirtualClock)),
            scheduler: Some(Arc::new(VirtualScheduler)),
            random: Some(Arc::new(ScenarioRandom)),
            fingerprint: Some(Arc::new(ScenarioFingerprint(device["fingerprintSource"].as_str().map(str::to_owned)))),
            logger: Some(Arc::new(StderrLogger)),
        },
    })
    .unwrap_or_else(|e| fatal(format!("Client::new: {e}")));
    let session = client.session().unwrap_or_else(|e| fatal(format!("세션: {e}")));
    let _subscription = session.subscribe(|s| {
        let value = serde_json::to_value(s).unwrap_or(Value::Null);
        emit(json!({ "type": "event", "now": now_ms(), "event": { "kind": "session.state", "state": value } }));
    });
    *CLIENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(client);
}

fn on_http_response(message: &Value) {
    let id = message["id"].as_str().unwrap_or("");
    // 지우기와 켜기를 한 잠금 안에서 — 둘 사이에 "할 일 없음"으로 보이는 틈이 없게
    let mut s = state();
    let Some(exchange) = s.pending.remove(id) else {
        drop(s);
        fatal(format!("모르는 http.response id {id}"));
    };
    let mut x = exchange.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = message.get("response").filter(|r| !r.is_null()) {
        let headers = r["headers"]
            .as_object()
            .map(|h| h.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.as_str().unwrap_or("").to_owned())).collect())
            .unwrap_or_default();
        x.response = Some(HttpResponse {
            status: r["status"].as_u64().unwrap_or(0) as u16,
            headers,
            body: r["body"].as_str().unwrap_or("").as_bytes().to_vec(),
        });
    }
    x.done.fire();
}

fn main() {
    emit(json!({ "type": "ready", "sdk": "rust", "version": bydev::SDK_VERSION, "specVersion": bydev::SPEC_VERSION }));
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            let message: Value =
                serde_json::from_str(&line).unwrap_or_else(|_| fatal(format!("JSON이 아닌 입력: {line}")));
            if message["type"] == "http.response" {
                on_http_response(&message);
            } else if tx.send(message).is_err() {
                break;
            }
        }
    });
    for message in rx {
        match message["type"].as_str().unwrap_or("") {
            "init" => {
                init(&message);
                settle();
            }
            "call" => {
                for c in message["calls"].as_array().cloned().unwrap_or_default() {
                    let id = c["id"].as_str().unwrap_or("").to_owned();
                    let method = c["method"].as_str().unwrap_or("").to_owned();
                    let args = if c["args"].is_object() { c["args"].clone() } else { json!({}) };
                    start_call(id, method, args);
                }
                settle();
            }
            "advance" => advance(message["ms"].as_i64().unwrap_or(0)),
            "set" => {
                let value = message["value"].as_bool().unwrap_or(false);
                {
                    let mut s = state();
                    match message["key"].as_str().unwrap_or("") {
                        "storage.failLoad" => s.fail_load = value,
                        "storage.failSave" => s.fail_save = value,
                        "storage.failClear" => s.fail_clear = value,
                        _ => {}
                    }
                }
                settle();
            }
            "end" => std::process::exit(0),
            other => fatal(format!("모르는 명령 {other}")),
        }
        emit(json!({ "type": "idle", "now": now_ms() }));
    }
}
