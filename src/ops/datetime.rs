//! Datetime ops: parse / delta / translate.
//!
//! All three ops normalize input through a shared parser covering the most
//! common machine-readable datetime formats. Naive datetimes and Unix epochs
//! are interpreted as UTC so deltas are deterministic and display-friendly.

use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

use super::{ArgSpec, Op};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:datetime:parse",
            "analyze",
            "op.datetime.parse.desc",
            &[],
            datetime_parse
        ),
        op!(
            "dpa:datetime:delta",
            "analyze",
            "op.datetime.delta.desc",
            &[ArgSpec {
                name: "operation",
                required: false,
                description: "op.datetime.delta.arg.operation",
                format: crate::ops::ArgFormat::Utf8,
            },],
            datetime_delta
        ),
        op!(
            "dpa:datetime:translate",
            "analyze",
            "op.datetime.translate.desc",
            &[ArgSpec {
                name: "format",
                required: true,
                description: "op.datetime.translate.arg.format",
                format: crate::ops::ArgFormat::Utf8,
            },],
            datetime_translate
        ),
    ]
}

/// Parse one line through the supported formats and normalize to UTC.
/// Supported: RFC3339, RFC2822, "%Y-%m-%d %H:%M:%S [%z]", "%Y/%m/%d %H:%M:%S [%z]",
/// naive "%Y-%m-%d[T ]%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", and Unix epoch seconds.
fn parse_to_utc(line: &str) -> Option<DateTime<Utc>> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // Offset-aware formats.
    if let Ok(dt) = DateTime::parse_from_rfc3339(line) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(line) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S %z", "%Y/%m/%d %H:%M:%S %z"] {
        if let Ok(dt) = DateTime::parse_from_str(line, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // Naive formats (treated as UTC).
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(line, fmt) {
            return Some(Utc.from_utc_datetime(&dt));
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(line, "%Y-%m-%d") {
        if let Some(t) = d.and_hms_opt(0, 0, 0) {
            return Some(Utc.from_utc_datetime(&t));
        }
    }
    // Unix epoch seconds.
    if let Ok(secs) = line.parse::<i64>() {
        if let Some(dt) = Utc.timestamp_opt(secs, 0).single() {
            return Some(dt);
        }
    }
    None
}

fn parse_line(line: &str) -> anyhow::Result<DateTime<Utc>> {
    parse_to_utc(line)
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.datetime_parse_failed", &[line.trim()])))
}

fn datetime_parse(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let dt = parse_line(line)?;
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    Ok(out.into_bytes())
}

/// Parse a human-friendly delta such as "1d 2h 3m 4s", "2 days 6 hours",
/// "90 minutes", "-1h30m". Returns the total in seconds (negative allowed).
fn parse_delta_seconds(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("{}", i18n::t("err.datetime_delta_bad"));
    }
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let mut total: i64 = 0;
    let mut any = false;
    for raw in s.split_whitespace() {
        let tok = raw.trim_end_matches(',');
        let split = tok
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(tok.len());
        let (num, unit) = tok.split_at(split);
        if num.is_empty() {
            anyhow::bail!("{}", i18n::tf("err.datetime_delta_bad", &[s]));
        }
        let v: f64 = num
            .parse()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.datetime_delta_bad", &[s])))?;
        let mult = match unit.to_ascii_lowercase().as_str() {
            "d" | "day" | "days" => 86400.0,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
            "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
            "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
            _ => anyhow::bail!("{}", i18n::tf("err.datetime_delta_bad", &[s])),
        };
        total += (v * mult).round() as i64;
        any = true;
    }
    if !any {
        anyhow::bail!("{}", i18n::tf("err.datetime_delta_bad", &[s]));
    }
    Ok(if neg { -total } else { total })
}

fn datetime_delta(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() != 2 {
        anyhow::bail!("{}", i18n::t("err.datetime_delta_two_lines"));
    }
    let op = args.get("operation").map(|s| s.as_str()).unwrap_or("diff");
    let a = parse_line(lines[0])?;
    if op == "delta" {
        // Input: one datetime + one delta ("1d 2h"), output the shifted time.
        let secs = parse_delta_seconds(lines[1])?;
        let dt = a + chrono::Duration::seconds(secs);
        return Ok(dt
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .into_bytes());
    }
    let b = parse_line(lines[1])?;
    let secs = b.signed_duration_since(a).num_seconds();
    let sign = if secs < 0 { "-" } else { "" };
    let abs = secs.unsigned_abs();
    let days = abs / 86400;
    let hours = (abs % 86400) / 3600;
    let minutes = (abs % 3600) / 60;
    let seconds = abs % 60;
    let human = if days > 0 {
        format!(
            "{} days {} hours {} minutes {} seconds",
            days, hours, minutes, seconds
        )
    } else if hours > 0 {
        format!("{} hours {} minutes {} seconds", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{} minutes {} seconds", minutes, seconds)
    } else {
        format!("{} seconds", seconds)
    };
    Ok(format!("{}{} seconds ({})", sign, abs, human).into_bytes())
}

fn datetime_translate(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let fmt = args
        .get("format")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_format")))?;
    let text = String::from_utf8_lossy(input);
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let dt = parse_line(line)?;
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&dt.format(fmt).to_string());
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalizes_common_formats() {
        // RFC3339 stays normalized with Z for UTC.
        assert_eq!(
            datetime_parse(b"2024-01-02T03:04:05Z", &HashMap::new()).unwrap(),
            b"2024-01-02T03:04:05Z"
        );
        // Offset is converted to UTC.
        assert_eq!(
            datetime_parse(b"2024-01-02T11:04:05+08:00", &HashMap::new()).unwrap(),
            b"2024-01-02T03:04:05Z"
        );
        // Naive datetime is treated as UTC.
        assert_eq!(
            datetime_parse(b"2024-01-02 03:04:05", &HashMap::new()).unwrap(),
            b"2024-01-02T03:04:05Z"
        );
        // Date-only -> midnight UTC.
        assert_eq!(
            datetime_parse(b"2024-01-02", &HashMap::new()).unwrap(),
            b"2024-01-02T00:00:00Z"
        );
        // RFC2822.
        assert_eq!(
            datetime_parse(b"Tue, 2 Jan 2024 03:04:05 GMT", &HashMap::new()).unwrap(),
            b"2024-01-02T03:04:05Z"
        );
        // Unix epoch seconds.
        assert_eq!(
            datetime_parse(b"0", &HashMap::new()).unwrap(),
            b"1970-01-01T00:00:00Z"
        );
        // Multiple lines are processed independently.
        assert_eq!(
            datetime_parse(b"2024-01-01\n2024-01-02T00:00:00Z", &HashMap::new()).unwrap(),
            b"2024-01-01T00:00:00Z\n2024-01-02T00:00:00Z"
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(datetime_parse(b"not a date", &HashMap::new()).is_err());
        // Empty input is pipeline-friendly: empty in, empty out.
        assert!(datetime_parse(b"", &HashMap::new()).unwrap().is_empty());
    }

    #[test]
    fn delta_days_and_sign() {
        assert_eq!(
            datetime_delta(b"2024-01-01\n2024-01-02", &HashMap::new()).unwrap(),
            b"86400 seconds (1 days 0 hours 0 minutes 0 seconds)"
        );
        // Negative delta keeps the sign.
        assert_eq!(
            datetime_delta(b"2024-01-02\n2024-01-01", &HashMap::new()).unwrap(),
            b"-86400 seconds (1 days 0 hours 0 minutes 0 seconds)"
        );
        // Sub-minute delta.
        assert_eq!(
            datetime_delta(
                b"2024-01-01T00:00:00Z\n2024-01-01T00:00:45Z",
                &HashMap::new()
            )
            .unwrap(),
            b"45 seconds (45 seconds)"
        );
    }

    #[test]
    fn delta_requires_two_lines() {
        assert!(datetime_delta(b"2024-01-01", &HashMap::new()).is_err());
        assert!(datetime_delta(b"2024-01-01\n2024-01-02\n2024-01-03", &HashMap::new()).is_err());
    }

    #[test]
    fn translate_formats_to_strftime() {
        let args = HashMap::from([("format".to_string(), "%Y-%m-%d".to_string())]);
        assert_eq!(
            datetime_translate(b"2024-01-02T03:04:05Z", &args).unwrap(),
            b"2024-01-02"
        );
        let args = HashMap::from([("format".to_string(), "%d/%m/%Y %H:%M".to_string())]);
        assert_eq!(
            datetime_translate(b"2024-01-02T03:04:05Z", &args).unwrap(),
            b"02/01/2024 03:04"
        );
        // Per-line translation.
        let args = HashMap::from([("format".to_string(), "%Y".to_string())]);
        assert_eq!(
            datetime_translate(b"2023-06-01\n2024-07-01", &args).unwrap(),
            b"2023\n2024"
        );
    }

    #[test]
    fn delta_operation_shifts_time() {
        // operation=delta: second line is a delta, output the shifted time.
        let args = HashMap::from([("operation".to_string(), "delta".to_string())]);
        assert_eq!(
            datetime_delta(b"2024-01-01T00:00:00Z\n1d 2h", &args).unwrap(),
            b"2024-01-02T02:00:00Z"
        );
        // Negative delta shifts backwards.
        assert_eq!(
            datetime_delta(b"2024-01-01T00:00:00Z\n-1h 30m", &args).unwrap(),
            b"2023-12-31T22:30:00Z"
        );
        // operation=diff (default): two datetimes, output seconds + human text.
        let args = HashMap::from([("operation".to_string(), "diff".to_string())]);
        let out = String::from_utf8(
            datetime_delta(b"2024-01-02T00:00:00Z\n2024-01-01T00:00:00Z", &args).unwrap(),
        )
        .unwrap();
        assert!(out.starts_with("-86400 seconds"), "{out}");
        assert!(out.contains("1 days"), "{out}");
        // Default (no operation) is diff.
        let out2 = String::from_utf8(
            datetime_delta(
                b"2024-01-01T00:00:00Z\n2024-01-01T01:02:03Z",
                &HashMap::new(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(out2.starts_with("3723 seconds"), "{out2}");
    }
}
