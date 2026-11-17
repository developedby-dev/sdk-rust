//! 관대한 읽기(명세 0절 5) — 필요한 필드는 확인하고, 모르는 필드는 버리고, 모르는 열거 값은 문자열 그대로. 어긋나면 `PROTOCOL_ERROR`.

use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::errors::Error;
use crate::generated::codes;

static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);
static NULL: Value = Value::Null;

#[derive(Default)]
pub(crate) struct Reader {
    err: Option<Error>,
}

impl Reader {
    fn fail(&mut self, path: &str, want: &str, got: &Value) {
        if self.err.is_none() {
            self.err = Some(Error::new(codes::PROTOCOL_ERROR, format!("응답의 {path}가 {want}가 아니다 ({got})")));
        }
    }

    pub fn object<'a>(&mut self, v: &'a Value, path: &str) -> &'a Map<String, Value> {
        match v {
            Value::Object(m) => m,
            other => {
                self.fail(path, "객체", other);
                &EMPTY
            }
        }
    }

    pub fn str(&mut self, v: &Value, path: &str) -> String {
        match v {
            Value::String(s) => s.clone(),
            other => {
                self.fail(path, "문자열", other);
                String::new()
            }
        }
    }

    pub fn int(&mut self, v: &Value, path: &str) -> i64 {
        if let Some(i) = v.as_i64() {
            return i;
        }
        if let Some(f) = v.as_f64()
            && f.fract() == 0.0
            && f.abs() < 9.0e15
        {
            return f as i64;
        }
        self.fail(path, "정수", v);
        0
    }

    pub fn bool(&mut self, v: &Value, path: &str) -> bool {
        match v {
            Value::Bool(b) => *b,
            other => {
                self.fail(path, "참/거짓", other);
                false
            }
        }
    }

    pub fn array<'a>(&mut self, v: &'a Value, path: &str) -> &'a [Value] {
        match v {
            Value::Array(a) => a,
            other => {
                self.fail(path, "배열", other);
                &[]
            }
        }
    }

    pub fn opt_str(&mut self, v: &Value, path: &str) -> Option<String> {
        if v.is_null() { None } else { Some(self.str(v, path)) }
    }

    pub fn opt_int(&mut self, v: &Value, path: &str) -> Option<i64> {
        if v.is_null() { None } else { Some(self.int(v, path)) }
    }

    pub fn finish<T>(self, value: T) -> Result<T, Error> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(value),
        }
    }
}

/// 객체의 필드 — 없으면 null.
pub(crate) fn field<'a>(m: &'a Map<String, Value>, key: &str) -> &'a Value {
    m.get(key).unwrap_or(&NULL)
}
