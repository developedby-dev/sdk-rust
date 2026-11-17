//! 명세 9절 — 토큰 검증 · JWKS 캐시 · 세대번호 단조 확인.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

use crate::api::{Api, Req, Single, lock};
use crate::errors::Error;
use crate::generated::{codes, rules};
use crate::models::{AccessClaims, LicenseClaims, read_access_claims, read_license_claims};
use crate::read::Reader;

struct KeySet {
    keys: HashMap<String, VerifyingKey>,
    fetched_at_ms: i64,
    expires_at_ms: i64,
}

pub(crate) struct Expectation<'a> {
    pub sid: &'a str,
    pub device_id: &'a str,
    pub generation: i64,
}

pub(crate) struct Verifier {
    api: Arc<Api>,
    client_id: String,
    track_generations: bool,
    set: Mutex<Option<Arc<KeySet>>>,
    fetching: Single<Arc<KeySet>>,
    generations: Mutex<HashMap<String, i64>>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(codes::TOKEN_INVALID, message)
}

fn regressed(got: i64, seen: i64) -> Error {
    Error::new(codes::GENERATION_REGRESSED, format!("세대번호 {got} < 이미 본 {seen}"))
}

impl Verifier {
    pub fn new(api: Arc<Api>, client_id: &str, track_generations: bool) -> Self {
        Self {
            api,
            client_id: client_id.to_owned(),
            track_generations,
            set: Mutex::new(None),
            fetching: Single::new(),
            generations: Mutex::new(HashMap::new()),
        }
    }

    /// 9절 1 ~ 4. 페이로드를 돌려준다.
    fn verify_signed(&self, token: &str, typ: &str) -> Result<Value, Error> {
        let parts: Vec<&str> = token.split('.').collect();
        let [head, body, sig] = parts[..] else {
            return Err(invalid("JWT 형식이 아니다"));
        };
        let decode = |p: &str| URL_SAFE_NO_PAD.decode(p).ok();
        let (Some(head_raw), Some(body_raw), Some(sig_raw)) = (decode(head), decode(body), decode(sig)) else {
            return Err(invalid("JWT를 읽지 못했다"));
        };
        let (Ok(Value::Object(header)), Ok(payload @ Value::Object(_))) =
            (serde_json::from_slice::<Value>(&head_raw), serde_json::from_slice::<Value>(&body_raw))
        else {
            return Err(invalid("JWT를 읽지 못했다"));
        };
        if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(invalid(format!("alg {}", header.get("alg").unwrap_or(&Value::Null))));
        }
        if header.get("typ").and_then(Value::as_str) != Some(typ) {
            return Err(invalid(format!("typ {}", header.get("typ").unwrap_or(&Value::Null))));
        }
        let Some(kid) = header.get("kid").and_then(Value::as_str) else {
            return Err(invalid("kid가 없다"));
        };
        let key = self.key_for(kid)?;
        let signature = Signature::from_slice(&sig_raw).map_err(|_| invalid("서명이 맞지 않는다"))?;
        if key.verify(format!("{head}.{body}").as_bytes(), &signature).is_err() {
            return Err(invalid("서명이 맞지 않는다"));
        }
        let doc = self.api.discovery()?;
        if payload.get("iss").and_then(Value::as_str) != Some(doc.issuer.as_str()) {
            return Err(invalid("iss가 다르다"));
        }
        if payload.get("aud").and_then(Value::as_str) != Some(self.client_id.as_str()) {
            return Err(invalid("aud가 이 client_id가 아니다"));
        }
        let now_sec = self.api.ports.clock.now_ms() as f64 / 1000.0;
        match payload.get("exp").and_then(Value::as_f64) {
            Some(exp) if exp > now_sec - rules::TOKEN_CLOCK_LEEWAY_SEC as f64 => Ok(payload),
            _ => Err(invalid("만료된 토큰")),
        }
    }

    pub fn verify_license(
        &self,
        token: &str,
        expect: Option<Expectation<'_>>,
        min_generation: i64,
    ) -> Result<LicenseClaims, Error> {
        let payload = self.verify_signed(token, "license+jwt")?;
        let claims = read_license_claims(&payload).map_err(|_| invalid("클레임 모양이 다르다"))?;
        if let Some(expect) = expect {
            if claims.sid != expect.sid {
                return Err(invalid("sid가 세션과 다르다"));
            }
            if claims.device_id != expect.device_id {
                return Err(invalid("device_id가 세션과 다르다"));
            }
            if claims.generation != expect.generation {
                return Err(invalid("generation이 세션과 다르다"));
            }
        }
        if min_generation > 0 && claims.generation < min_generation {
            return Err(regressed(claims.generation, min_generation));
        }
        if self.track_generations {
            let slot = format!("{}|{}", claims.sub, claims.device_id);
            let mut seen = lock(&self.generations);
            match seen.get(&slot) {
                Some(&s) if claims.generation < s => return Err(regressed(claims.generation, s)),
                Some(&s) if claims.generation <= s => {}
                _ => {
                    seen.insert(slot, claims.generation);
                }
            }
        }
        Ok(claims)
    }

    pub fn verify_access(&self, token: &str) -> Result<AccessClaims, Error> {
        let payload = self.verify_signed(token, "at+jwt")?;
        read_access_claims(&payload).map_err(|_| invalid("클레임 모양이 다르다"))
    }

    /// 9.1절. 지난 캐시는 쓰지 않는다 · 모르는 kid는 1분에 한 번만 다시 받는다.
    fn key_for(&self, kid: &str) -> Result<VerifyingKey, Error> {
        let now = self.api.ports.clock.now_ms();
        let current = lock(&self.set).clone();
        let set = match current {
            Some(set) if now < set.expires_at_ms => set,
            _ => self.fetch_keys()?,
        };
        if let Some(key) = set.keys.get(kid) {
            return Ok(*key);
        }
        if now - set.fetched_at_ms < rules::JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC * 1000 {
            return Err(invalid(format!("모르는 kid {kid}")));
        }
        let set = self.fetch_keys()?;
        set.keys.get(kid).copied().ok_or_else(|| invalid(format!("모르는 kid {kid}")))
    }

    fn fetch_keys(&self) -> Result<Arc<KeySet>, Error> {
        self.fetching.run(&self.api.ports, || {
            let doc = self.api.discovery()?;
            let res = self.api.send(Req { method: "GET", url: doc.jwks_uri.clone(), ..Req::default() })?;
            let mut r = Reader::default();
            let root: &Map<String, Value> = r.object(&res.json, "$");
            let mut keys = HashMap::new();
            for item in r.array(root.get("keys").unwrap_or(&Value::Null), "keys") {
                let Some(jwk) = item.as_object() else { continue };
                if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
                    || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
                {
                    continue;
                }
                let kid = jwk.get("kid").and_then(Value::as_str).unwrap_or("");
                let raw = jwk.get("x").and_then(Value::as_str).and_then(|x| URL_SAFE_NO_PAD.decode(x).ok());
                let key = raw
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .and_then(|b| VerifyingKey::from_bytes(&b).ok());
                match key {
                    Some(key) if !kid.is_empty() => {
                        keys.insert(kid.to_owned(), key);
                    }
                    _ => self.api.ports.logger.warn("JWKS 키를 읽지 못했다"),
                }
            }
            r.finish(())?;
            let age = res
                .headers
                .get("cache-control")
                .and_then(|v| v.split(',').find_map(|part| part.trim().strip_prefix("max-age=")?.parse::<i64>().ok()))
                .unwrap_or(rules::JWKS_DEFAULT_MAX_AGE_SEC);
            let fetched = self.api.ports.clock.now_ms();
            let set = Arc::new(KeySet { keys, fetched_at_ms: fetched, expires_at_ms: fetched + age * 1000 });
            *lock(&self.set) = Some(set.clone());
            Ok(set)
        })
    }
}
