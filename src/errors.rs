use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::generated::{codes, rules};

/// SDK의 에러 하나다(명세 3.3). `code()`로 분기하고 `message()`는 보여 주기만 한다. 앱의 오류 화면에 `correlation_id()`를 보이면 문의를 바로
/// 찾는다.
#[derive(Clone, Debug)]
pub struct Error(Box<Inner>);

#[derive(Clone, Debug)]
pub(crate) struct Inner {
    pub code: String,
    pub message: String,
    pub http_status: Option<u16>,
    pub correlation_id: Option<String>,
    pub retry_after_sec: Option<u64>,
    pub details: Option<Map<String, Value>>,
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self(Box::new(Inner {
            code: code.to_owned(),
            message: message.into(),
            http_status: None,
            correlation_id: None,
            retry_after_sec: None,
            details: None,
            cause: None,
        }))
    }

    pub(crate) fn caused(
        code: &str,
        message: impl Into<String>,
        cause: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        let mut e = Self::new(code, message);
        e.0.cause = Some(Arc::from(cause.into()));
        e
    }

    /// 이 크레이트 위에 지은 다른 언어 SDK(C)가 자기 경계에서 에러를 만들 때.
    #[doc(hidden)]
    pub fn from_code(code: &str, message: &str) -> Self {
        Self::new(code, message)
    }

    /// API 응답의 HTTP 사실을 싣는다.
    pub(crate) fn inner_mut(&mut self) -> &mut Inner {
        &mut self.0
    }

    /// 에러 코드 — 생성된 `codes` 상수와 비교한다.
    pub fn code(&self) -> &str {
        &self.0.code
    }

    /// 보여 주기만 하는 설명(한국어). 분기에 쓰지 않는다.
    pub fn message(&self) -> &str {
        &self.0.message
    }

    pub fn http_status(&self) -> Option<u16> {
        self.0.http_status
    }

    pub fn correlation_id(&self) -> Option<&str> {
        self.0.correlation_id.as_deref()
    }

    pub fn retry_after_sec(&self) -> Option<u64> {
        self.0.retry_after_sec
    }

    pub fn details(&self) -> Option<&Map<String, Value>> {
        self.0.details.as_ref()
    }

    /// 일시적 실패인지다(명세 3.4). 아는 코드는 그 뜻대로 — 429인 한도 초과 코드는 끝난 실패 — 모르는 코드만 HTTP 상태로 나눈다.
    pub fn is_transient(&self) -> bool {
        let code = self.code();
        if rules::TRANSIENT_CODES.contains(&code) {
            return true;
        }
        let known = codes::API_HTTP_STATUS.iter().any(|(c, _)| *c == code) || codes::SDK.contains(&code);
        if known {
            return false;
        }
        let Some(status) = self.http_status().map(i64::from) else {
            return false;
        };
        rules::TRANSIENT_UNKNOWN_CODE_STATUSES.contains(&status)
            || rules::TRANSIENT_UNKNOWN_CODE_STATUS_RANGES.iter().any(|(lo, hi)| status >= *lo && status <= *hi)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.cause.as_deref().map(|c| c as &(dyn std::error::Error + 'static))
    }
}

/// 포트가 낸 에러 — 이미 SDK 에러면 그대로, 아니면 `code`로 감싼다.
pub(crate) fn wrap(error: Box<dyn std::error::Error + Send + Sync>, code: &str, message: &str) -> Error {
    match error.downcast::<Error>() {
        Ok(e) => *e,
        Err(other) => Error::caused(code, message, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(code: &str, status: Option<u16>) -> Error {
        let mut e = Error::new(code, "");
        e.inner_mut().http_status = status;
        e
    }

    /// 명세 3.4 — 일시적 실패 분류.
    #[test]
    fn transient() {
        assert!(with(codes::RATE_LIMITED, Some(429)).is_transient());
        assert!(with(codes::INTERNAL_ERROR, Some(503)).is_transient());
        assert!(with(codes::NETWORK_ERROR, None).is_transient());
        // 429인 한도 초과 코드는 끝난 실패다
        assert!(!with(codes::TAKEOVER_LIMIT_EXCEEDED, Some(429)).is_transient());
        assert!(!with(codes::DEVICE_RELEASE_LIMIT_EXCEEDED, Some(429)).is_transient());
        // 모르는 코드만 HTTP 상태로
        assert!(with("FUTURE_THROTTLE", Some(429)).is_transient());
        assert!(with("FUTURE_OUTAGE", Some(502)).is_transient());
        assert!(!with("FUTURE_FORBIDDEN", Some(403)).is_transient());
        assert!(!with("FUTURE_NOTHING", None).is_transient());
        assert!(!with(codes::STORAGE_FAILED, None).is_transient());
    }
}
