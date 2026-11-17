//! UTC 시각 ↔ ISO 8601. 의존성 없이 — 날짜 계산은 H. Hinnant의 civil 알고리즘.

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

/// SDK가 만드는 시각 — 밀리초가 0이면 떼는 UTC ISO 8601(`2026-10-06T13:00:00Z` · `…:00.250Z`).
pub fn format_iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    if millis == 0 {
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    } else {
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
    }
}

/// RFC 3339(`Z` 또는 `±hh:mm`, 소수 초 허용) → Unix 밀리초. 읽지 못하면 `None`.
pub fn parse_iso(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = text.get(from..from + len)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d, h, mi, s) = (num(0, 4)?, num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut i = 19;
    let mut millis = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let digits = &text[start..i];
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        millis = first3.parse::<i64>().ok()?;
    }
    let offset_min = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let v = num(i + 1, 2)? * 60 + num(i + 4, 2)?;
            if *sign == b'+' { v } else { -v }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    Some(((days * 86_400 + h * 3600 + mi * 60 + s - offset_min * 60) * 1000) + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = parse_iso("2026-10-06T13:00:00Z").unwrap();
        assert_eq!(t, 1_791_291_600_000);
        assert_eq!(format_iso(t), "2026-10-06T13:00:00Z");
        assert_eq!(format_iso(t + 250), "2026-10-06T13:00:00.250Z");
        assert_eq!(parse_iso("2026-10-06T22:00:00.5+09:00"), Some(t + 500));
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(format_iso(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(parse_iso("2026-10-06 13:00:00Z"), None);
        assert_eq!(parse_iso("2026-10-06T13:00:00"), None);
    }
}
