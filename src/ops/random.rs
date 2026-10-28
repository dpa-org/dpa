//! Generation ops: timestamp / UUID / random bytes.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{Rng, RngCore};

use super::{ArgSpec, Op};
use crate::i18n;

/// Return `args[name]` or `default` when absent / empty.
fn opt_arg<'a>(args: &'a HashMap<String, String>, name: &str, default: &'a str) -> &'a str {
    match args.get(name) {
        Some(v) if !v.trim().is_empty() => v,
        _ => default,
    }
}

/// Error messages for single-value ops must not echo the whole
/// input back - a multi-line or huge input would amplify stderr without bound
/// and flood the terminal with the offending bytes. Show at most 64 bytes
/// plus the total length so logs stay bounded while the user still sees enough
/// context to spot the bad value.
fn brief_input(s: &str) -> String {
    const MAX: usize = 64;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes total)", &s[..end], s.len())
}

/// RFC 4122 namespace UUIDs (DNS / URL / OID / X500), reused by UUID v3/v5.
const NAMESPACES: &[(&str, &str)] = &[
    ("dns", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
    ("url", "6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
    ("oid", "6ba7b812-9dad-11d1-80b4-00c04fd430c8"),
    ("x500", "6ba7b814-9dad-11d1-80b4-00c04fd430c8"),
];

pub fn ops() -> Vec<Op> {
    let ops = vec![
        op!(
            "dpa:timestamp",
            "generate",
            "op.timestamp.desc",
            &[ArgSpec {
                name: "unit",
                required: false,
                description: "op.timestamp.arg.unit",
                format: crate::ops::ArgFormat::Utf8,
            },],
            timestamp
        ),
        op!(
            "dpa:timestamp:to:date",
            "generate",
            "op.timestamp.to.date.desc",
            &[ArgSpec {
                name: "unit",
                required: false,
                description: "op.timestamp.to.date.arg.unit",
                format: crate::ops::ArgFormat::Utf8,
            },],
            timestamp_to_date
        ),
        op!(
            "dpa:filetime",
            "generate",
            "op.filetime.desc",
            &[ArgSpec {
                name: "format",
                required: false,
                description: "op.filetime.arg.format",
                format: crate::ops::ArgFormat::Utf8,
            },],
            filetime
        ),
        op!(
            "dpa:filetime:from:unix",
            "generate",
            "op.filetime.from.unix.desc",
            &[
                ArgSpec {
                    name: "unit",
                    required: false,
                    description: "op.filetime.from.unix.arg.unit",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "format",
                    required: false,
                    description: "op.filetime.from.unix.arg.format",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            filetime_from_unix
        ),
        op!(
            "dpa:filetime:to:date",
            "generate",
            "op.filetime.to.date.desc",
            &[ArgSpec {
                name: "unit",
                required: false,
                description: "op.filetime.to.date.arg.unit",
                format: crate::ops::ArgFormat::Utf8,
            },],
            filetime_to_date
        ),
        op!(
            "dpa:uuid",
            "generate",
            "op.uuid.desc",
            &[
                ArgSpec {
                    name: "version",
                    required: false,
                    description: "op.uuid.arg.version",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "namespace",
                    required: false,
                    description: "op.uuid.arg.namespace",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "name",
                    required: false,
                    description: "op.uuid.arg.name",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            uuid4
        ),
        op!(
            "dpa:uuid4",
            "generate",
            "op.uuid4.desc",
            &[
                ArgSpec {
                    name: "version",
                    required: false,
                    description: "op.uuid4.arg.version",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "namespace",
                    required: false,
                    description: "op.uuid4.arg.namespace",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "name",
                    required: false,
                    description: "op.uuid4.arg.name",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            uuid4
        ),
        op!(
            "dpa:random",
            "generate",
            "op.random.desc",
            &[ArgSpec {
                name: "bytes",
                required: false,
                description: "op.random.arg.bytes",
                format: crate::ops::ArgFormat::Utf8,
            },],
            random_bytes
        ),
        op!(
            "dpa:random:hex",
            "generate",
            "op.random.hex.desc",
            &[ArgSpec {
                name: "bytes",
                required: false,
                description: "op.random.hex.arg.bytes",
                format: crate::ops::ArgFormat::Utf8,
            },],
            random_bytes_hex
        ),
        // generate family additions (De Bruijn / prime / HOTP / TOTP)
        op!(
            "dpa:de:bruijn",
            "generate",
            "op.de.bruijn.desc",
            &[
                ArgSpec {
                    name: "size",
                    required: false,
                    description: "op.de.bruijn.arg.size",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "order",
                    required: false,
                    description: "op.de.bruijn.arg.order",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            de_bruijn
        ),
        op!(
            "dpa:prime",
            "generate",
            "op.prime.desc",
            &[
                ArgSpec {
                    name: "bits",
                    required: false,
                    description: "op.prime.arg.bits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "grade",
                    required: false,
                    description: "op.prime.arg.grade",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "rounds",
                    required: false,
                    description: "op.prime.arg.rounds",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "format",
                    required: false,
                    description: "op.prime.arg.format",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            prime
        ),
        op!(
            "dpa:hotp",
            "generate",
            "op.hotp.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: false,
                    description: "op.hotp.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "digits",
                    required: false,
                    description: "op.hotp.arg.digits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "counter",
                    required: false,
                    description: "op.hotp.arg.counter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "algo",
                    required: false,
                    description: "op.hotp.arg.algo",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            hotp
        ),
        op!(
            "dpa:totp",
            "generate",
            "op.totp.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: false,
                    description: "op.totp.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "digits",
                    required: false,
                    description: "op.totp.arg.digits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "period",
                    required: false,
                    description: "op.totp.arg.period",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "epoch",
                    required: false,
                    description: "op.totp.arg.epoch",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "time",
                    required: false,
                    description: "op.totp.arg.time",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "algo",
                    required: false,
                    description: "op.totp.arg.algo",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            totp
        ),
    ];

    // `dpa:random:hex` is a composite shortcut (`random` -> `hex:encode`);
    // its Shortcut mark is applied centrally in ops::mod (apply_shortcut_marks).
    ops
}

fn timestamp(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
        anyhow::anyhow!("{}", i18n::tf("err.system_time", &[e.to_string().as_str()]))
    })?;
    let unit = args.get("unit").map(String::as_str).unwrap_or("s");
    let out = match unit {
        "s" => now.as_secs().to_string(),
        "ms" => now.as_millis().to_string(),
        "us" => now.as_micros().to_string(),
        "ns" => now.as_nanos().to_string(),
        other => anyhow::bail!("{}", i18n::tf("err.unknown_unit", &[other])),
    };
    Ok(out.into_bytes())
}

/// Days-to-civil-date conversion (Howard Hinnant's algorithm), UTC-only.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format a UNIX timestamp (seconds) as `YYYY-MM-DD HH:MM:SS` in UTC.
fn unix_to_utc(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

fn timestamp_to_date(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input).trim().to_string();
    let ts: i64 = s.parse().map_err(|_| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.not_unix_time", &[brief_input(&s).as_str()])
        )
    })?;
    // `unit` selects the input granularity: s (default) / ms / us / ns.
    let secs = match args.get("unit").map(|u| u.as_str()).unwrap_or("s") {
        "s" | "secs" | "seconds" => ts,
        "ms" | "millis" | "milliseconds" => ts.div_euclid(1_000),
        "us" | "micros" | "microseconds" => ts.div_euclid(1_000_000),
        "ns" | "nanos" | "nanoseconds" => ts.div_euclid(1_000_000_000),
        _ => anyhow::bail!("{}", i18n::t("err.timestamp_bad_unit")),
    };
    Ok(unix_to_utc(secs).into_bytes())
}

fn filetime(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
        anyhow::anyhow!("{}", i18n::tf("err.system_time", &[e.to_string().as_str()]))
    })?;
    // FILETIME = 100ns ticks since 1601-01-01 UTC.
    let ticks = (now.as_secs() as i64 + 11_644_473_600i64) * 10_000_000i64
        + (now.subsec_nanos() as i64) / 100;
    let fmt = args.get("format").map(|s| s.as_str()).unwrap_or("hex");
    if fmt == "dec" {
        Ok(ticks.to_string().into_bytes())
    } else {
        Ok(hex::encode(ticks.to_le_bytes()).into_bytes())
    }
}

fn filetime_from_unix(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input).trim().to_string();
    let secs: i64 = s.parse().map_err(|_| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
        )
    })?;
    // Support s (default) / ms / us inputs, scaled to whole seconds.
    let scaled = match args.get("unit").map(|u| u.as_str()).unwrap_or("s") {
        "s" | "secs" | "seconds" => secs,
        "ms" | "millis" | "milliseconds" => secs.checked_div(1_000).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?,
        "us" | "micros" | "microseconds" => secs.checked_div(1_000_000).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?,
        _ => anyhow::bail!("{}", i18n::t("err.filetime_bad_unit")),
    };
    // FILETIME = 100ns ticks since 1601-01-01 UTC.
    let ticks = scaled
        .checked_add(11_644_473_600i64)
        .and_then(|v| v.checked_mul(10_000_000i64))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?;
    let fmt = args.get("format").map(|s| s.as_str()).unwrap_or("hex");
    if fmt == "dec" {
        Ok(ticks.to_string().into_bytes())
    } else {
        Ok(hex::encode(ticks.to_le_bytes()).into_bytes())
    }
}

fn filetime_to_date(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input).trim().to_string();
    let ticks: i64 = if let Some(hex_s) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let bytes = hex::decode(hex_s).map_err(|_| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?;
        let arr: [u8; 8] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?;
        i64::from_le_bytes(arr)
    } else {
        s.parse().map_err(|_| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
            )
        })?
    };
    // The input may be expressed in FILETIME ticks (default), microseconds,
    // milliseconds or whole seconds. Scale back to 100ns ticks before converting.
    let scale = match args.get("unit").map(|u| u.as_str()).unwrap_or("ticks") {
        "ticks" => 1i64,
        "us" | "micros" | "microseconds" => 10i64,
        "ms" | "millis" | "milliseconds" => 10_000i64,
        "s" | "secs" | "seconds" => 10_000_000i64,
        _ => anyhow::bail!("{}", i18n::t("err.filetime_bad_unit")),
    };
    let scaled = ticks.checked_mul(scale).ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.not_filetime", &[brief_input(&s).as_str()])
        )
    })?;
    let unix_secs = scaled / 10_000_000 - 11_644_473_600i64;
    Ok(unix_to_utc(unix_secs).into_bytes())
}

fn format_uuid(b: &[u8; 16]) -> Vec<u8> {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
    .into_bytes()
}

/// Parse an RFC 4122 namespace UUID (with or without dashes) into 16 raw bytes.
fn parse_namespace(ns: &str) -> anyhow::Result<[u8; 16]> {
    let compact: String = ns.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        anyhow::bail!("{}", i18n::tf("err.uuid_bad_namespace", &[ns]));
    }
    let bytes = hex::decode(&compact)
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.uuid_bad_namespace", &[ns])))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.uuid_bad_namespace", &[ns])))
}

/// RFC 4122 UUID generator. Supports versions 1 (time+node), 3/5 (name-based
/// MD5/SHA-1) and 4 (random, the default).
fn uuid4(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let version = args.get("version").map(|s| s.as_str()).unwrap_or("4");
    let mut b = [0u8; 16];
    match version {
        "1" => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
                anyhow::anyhow!("{}", i18n::tf("err.system_time", &[e.to_string().as_str()]))
            })?;
            // 100ns ticks since 1582-10-15 (Gregorian reform) in UTC.
            let ts_100ns =
                now.as_secs() * 10_000_000 + (now.subsec_nanos() as u64) / 100 + 0x01B21DD213814000;
            b[0..4].copy_from_slice(&((ts_100ns & 0xFFFF_FFFF) as u32).to_be_bytes());
            b[4..6].copy_from_slice(&(((ts_100ns >> 32) & 0xFFFF) as u16).to_be_bytes());
            let time_hi = (ts_100ns >> 48) & 0x0FFF;
            b[6] = ((time_hi >> 8) as u8 & 0x0F) | 0x10;
            b[7] = time_hi as u8;
            let clock_seq: u16 = rand::rng().random();
            b[8] = ((clock_seq >> 8) as u8 & 0x3F) | 0x80;
            b[9] = clock_seq as u8;
            // Random multicast node (48 bits, least-significant bit set).
            rand::rng().fill_bytes(&mut b[10..16]);
            b[10] |= 0x01;
        }
        "3" | "5" => {
            let ns = args
                .get("namespace")
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.uuid_need_namespace")))?;
            let name = args
                .get("name")
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.uuid_need_name")))?;
            // Allow the four well-known namespaces by short alias.
            let ns_full = NAMESPACES
                .iter()
                .find(|(alias, _)| *alias == ns)
                .map(|(_, full)| *full)
                .unwrap_or(ns.as_str());
            let ns_bytes = parse_namespace(ns_full)?;
            let mut data = Vec::with_capacity(16 + name.len());
            data.extend_from_slice(&ns_bytes);
            data.extend_from_slice(name.as_bytes());
            if version == "3" {
                use md5::{Digest, Md5};
                b.copy_from_slice(&Md5::digest(&data)[..]);
            } else {
                use sha1::{Digest, Sha1};
                b.copy_from_slice(&Sha1::digest(&data)[..16]);
            }
            b[6] = (b[6] & 0x0F) | if version == "3" { 0x30 } else { 0x50 };
            b[8] = (b[8] & 0x3F) | 0x80;
        }
        _ => {
            // Version 4: fully random.
            rand::rng().fill_bytes(&mut b);
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
        }
    }
    Ok(format_uuid(&b))
}

fn random_bytes(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = args
        .get("bytes")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.bytes_not_num", &[e.to_string().as_str()])
            )
        })?
        .unwrap_or(16);
    if n == 0 || n > 1_000_000 {
        anyhow::bail!("{}", i18n::tf("err.bytes_range", &[n.to_string().as_str()]));
    }
    let mut out = vec![0u8; n];
    rand::rng().fill_bytes(&mut out);
    Ok(out)
}

fn random_bytes_hex(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(hex::encode(random_bytes(input, args)?).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_decimal() {
        let out = timestamp(b"", &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.parse::<u64>().unwrap() > 1_700_000_000,
            "timestamp error: {}",
            s
        );
    }

    #[test]
    fn uuid4_format_and_version() {
        let out = uuid4(b"", &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.len(), 36);
        assert_eq!(&s[14..15], "4", "UUID version bits should be 4: {}", s);
        let v = u8::from_str_radix(&s[19..20], 16).unwrap();
        assert!(v & 0b1100 == 0b1000, "UUID variant bits are wrong: {}", s);
    }

    #[test]
    fn random_bytes_len() {
        let mut a = HashMap::new();
        a.insert("bytes".into(), "32".into());
        assert_eq!(random_bytes(b"", &a).unwrap().len(), 32);
        assert_eq!(random_bytes(b"", &HashMap::new()).unwrap().len(), 16);
        a.insert("bytes".into(), "0".into());
        assert!(random_bytes(b"", &a).is_err());
    }

    #[test]
    fn timestamp_units() {
        let mut a = HashMap::new();
        let s = String::from_utf8(timestamp(b"", &HashMap::new()).unwrap()).unwrap();
        assert!(
            s.parse::<u64>().unwrap() > 1_700_000_000,
            "timestamp: {}",
            s
        );
        for (unit, min_len) in [("ms", 12), ("us", 15), ("ns", 18)] {
            a.insert("unit".into(), unit.into());
            let out = String::from_utf8(timestamp(b"", &a).unwrap()).unwrap();
            assert!(out.len() >= min_len, "unit {unit}: {out}");
        }
        a.insert("unit".into(), "fortnight".into());
        assert!(timestamp(b"", &a).is_err());
    }

    #[test]
    fn timestamp_to_date_known_vectors() {
        assert_eq!(
            String::from_utf8(timestamp_to_date(b"0", &HashMap::new()).unwrap()).unwrap(),
            "1970-01-01 00:00:00"
        );
        assert_eq!(
            String::from_utf8(timestamp_to_date(b"1700000000", &HashMap::new()).unwrap()).unwrap(),
            "2023-11-14 22:13:20"
        );
        assert_eq!(
            String::from_utf8(timestamp_to_date(b" 2000000000 ", &HashMap::new()).unwrap())
                .unwrap(),
            "2033-05-18 03:33:20"
        );
        assert!(timestamp_to_date(b"abc", &HashMap::new()).is_err());
    }

    #[test]
    fn filetime_le_hex_format() {
        let out = String::from_utf8(filetime(b"", &HashMap::new()).unwrap()).unwrap();
        assert_eq!(out.len(), 16, "filetime hex: {out}");
        let ticks = i64::from_le_bytes(hex::decode(&out).unwrap().try_into().unwrap());
        // Unix 0 (1970) => 116444736000000000 ticks (LE hex 00803ed5deb19d01)
        assert!(ticks > 116444736000000000, "filetime ticks: {ticks}");
    }

    #[test]
    fn filetime_to_date_known_vectors() {
        // Unix 0 -> FILETIME ticks 116444736000000000 -> LE hex 00803ed5deb19d01
        let cases = [
            ("0x0000000000000000", "1601-01-01 00:00:00"),
            ("0x00803ed5deb19d01", "1970-01-01 00:00:00"),
            ("0x00006dc64717da01", "2023-11-14 22:13:20"),
            ("116444736000000000", "1970-01-01 00:00:00"),
        ];
        for (input, expected) in cases {
            let out =
                String::from_utf8(filetime_to_date(input.as_bytes(), &HashMap::new()).unwrap())
                    .unwrap();
            assert_eq!(out, expected, "input {input}");
        }
        assert!(filetime_to_date(b"zzz", &HashMap::new()).is_err());
        assert!(filetime_to_date(b"0x0102", &HashMap::new()).is_err());
    }

    #[test]
    fn filetime_format_and_unit() {
        // format=dec outputs decimal ticks.
        let args = HashMap::from([("format".to_string(), "dec".to_string())]);
        let out = String::from_utf8(filetime(b"", &args).unwrap()).unwrap();
        let val: i64 = out.parse().unwrap();
        assert!(val > 116444736000000000, "ticks {val}");
        // unit=s: input is whole Unix seconds, 11644473600 == 1970-01-01.
        let args = HashMap::from([("unit".to_string(), "s".to_string())]);
        let out = String::from_utf8(filetime_to_date(b"11644473600", &args).unwrap()).unwrap();
        assert_eq!(out, "1970-01-01 00:00:00");
        // unit=ms: same instant in milliseconds.
        let args = HashMap::from([("unit".to_string(), "ms".to_string())]);
        let out = String::from_utf8(filetime_to_date(b"11644473600000", &args).unwrap()).unwrap();
        assert_eq!(out, "1970-01-01 00:00:00");
        // unit=us: same instant in microseconds.
        let args = HashMap::from([("unit".to_string(), "us".to_string())]);
        let out =
            String::from_utf8(filetime_to_date(b"11644473600000000", &args).unwrap()).unwrap();
        assert_eq!(out, "1970-01-01 00:00:00");
        // Unknown unit errors.
        let args = HashMap::from([("unit".to_string(), "ns".to_string())]);
        assert!(filetime_to_date(b"0", &args).is_err());
    }

    #[test]
    fn uuid_versions_and_namespaces() {
        let out = String::from_utf8(uuid4(b"", &HashMap::new()).unwrap()).unwrap();
        assert_eq!(out.len(), 36);
        assert_eq!(out.chars().nth(14), Some('4'));
        // v1: version nibble 1, valid hyphen layout.
        let args = HashMap::from([("version".to_string(), "1".to_string())]);
        let out1 = String::from_utf8(uuid4(b"", &args).unwrap()).unwrap();
        assert_eq!(out1.chars().nth(14), Some('1'));
        assert_eq!(out1.chars().nth(8), Some('-'));
        // v3 (MD5, DNS namespace) is deterministic.
        let v3 = HashMap::from([
            ("version".to_string(), "3".to_string()),
            ("namespace".to_string(), "dns".to_string()),
            ("name".to_string(), "www.example.org".to_string()),
        ]);
        let a = String::from_utf8(uuid4(b"", &v3).unwrap()).unwrap();
        let b = String::from_utf8(uuid4(b"", &v3).unwrap()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.chars().nth(14), Some('3'));
        // v5 (SHA-1, URL namespace) is deterministic.
        let v5 = HashMap::from([
            ("version".to_string(), "5".to_string()),
            ("namespace".to_string(), "url".to_string()),
            ("name".to_string(), "example.com".to_string()),
        ]);
        let a5 = String::from_utf8(uuid4(b"", &v5).unwrap()).unwrap();
        assert_eq!(a5.chars().nth(14), Some('5'));
        // v3/v5 require namespace and name.
        let only_v = HashMap::from([("version".to_string(), "3".to_string())]);
        assert!(uuid4(b"", &only_v).is_err());
        let no_name = HashMap::from([
            ("version".to_string(), "3".to_string()),
            ("namespace".to_string(), "dns".to_string()),
        ]);
        assert!(uuid4(b"", &no_name).is_err());
        // Bad namespace errors.
        let bad_ns = HashMap::from([
            ("version".to_string(), "3".to_string()),
            ("namespace".to_string(), "not-a-uuid".to_string()),
            ("name".to_string(), "x".to_string()),
        ]);
        assert!(uuid4(b"", &bad_ns).is_err());
    }
}

// ========================= generate family additions =========================

/// RFC 4648 base32 decoder (alphabet A-Z2-7; tolerant of spaces and padding).
fn base32_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in s.chars() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '=' {
            break;
        }
        let up = ch.to_ascii_uppercase();
        let v = match up {
            'A'..='Z' => up as u32 - b'A' as u32,
            '2'..='7' => up as u32 - b'2' as u32 + 26,
            _ => anyhow::bail!("{}", i18n::tf("err.base32_invalid", &[])),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

/// HMAC over `data` with `key` for the OTP family (RFC 4226 / RFC 6238).
fn otp_hmac(algo: &str, key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    macro_rules! run {
        ($t:ty) => {{
            let mut mac = <$t as Mac>::new_from_slice(key).map_err(|e| {
                anyhow::anyhow!("{}", i18n::tf("err.hmac_init", &[e.to_string().as_str()]))
            })?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algo {
        "sha1" => run!(Hmac<sha1::Sha1>),
        "sha256" => run!(Hmac<sha2::Sha256>),
        "sha512" => run!(Hmac<sha2::Sha512>),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_algo", &[other, "sha1 / sha256 / sha512"])
        ),
    }
}

/// HOTP core (RFC 4226): HMAC over a 64-bit big-endian counter, dynamic truncation.
fn otp_code(algo: &str, key: &[u8], counter: u64, digits: usize) -> anyhow::Result<Vec<u8>> {
    let msg = counter.to_be_bytes();
    let hs = otp_hmac(algo, key, &msg)?;
    let off = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([hs[off], hs[off + 1], hs[off + 2], hs[off + 3]]) & 0x7fff_ffff;
    let code = (bin as u64) % 10u64.pow(digits as u32);
    Ok(format!("{code:0width$}", width = digits).into_bytes())
}

/// RFC 4648 base32 encoder (uppercase, no padding) for OTP secret display.
fn base32_encode_std(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(acc >> bits) as usize] as char);
            acc &= (1u32 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Parse an integer argument within [lo, hi]; empty -> default.
fn range_arg(
    args: &HashMap<String, String>,
    name: &str,
    default: i64,
    lo: i64,
    hi: i64,
) -> anyhow::Result<i64> {
    let raw = args.get(name).map(|s| s.as_str()).unwrap_or("");
    let val = if raw.is_empty() {
        default
    } else {
        raw.parse::<i64>().map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.int_invalid", &[e.to_string().as_str()]))
        })?
    };
    if val < lo || val > hi {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.range",
                &[
                    lo.to_string().as_str(),
                    hi.to_string().as_str(),
                    val.to_string().as_str()
                ]
            )
        );
    }
    Ok(val)
}

/// FKM Lyndon-word construction of a De Bruijn sequence B(k, n).
#[allow(clippy::needless_range_loop)]
fn db_visit(t: usize, p: usize, k: usize, n: usize, a: &mut [usize], seq: &mut Vec<u8>) {
    if t > n {
        if !n.is_multiple_of(p) {
            return;
        }
        for j in 1..=p {
            seq.push(b'0' + a[j] as u8);
        }
        return;
    }
    a[t] = a[t - p];
    db_visit(t + 1, p, k, n, a, seq);
    for j in (a[t - p] + 1)..k {
        a[t] = j;
        db_visit(t + 1, t, k, n, a, seq);
    }
}

fn de_bruijn(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let k = range_arg(args, "size", 2, 2, 9)? as usize;
    let n = range_arg(args, "order", 3, 2, 1_000_000)? as usize;
    let total = k
        .checked_pow(n as u32)
        .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    if total > 50_000 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.range", &["1", "50000", &total.to_string()])
        );
    }
    let mut a = vec![0usize; k * n];
    let mut seq = Vec::with_capacity(total);
    db_visit(1, 1, k, n, &mut a, &mut seq);
    Ok(seq)
}

/// Uniform random BigUint of exactly `bits` bits (MSB set, odd).
fn rand_odd_bigint(bits: usize) -> num_bigint::BigUint {
    let nbytes = bits.div_ceil(8);
    let mut buf = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut buf);
    // Mask out stray bits above the requested width so the value
    // has exactly `bits` bits instead of bits..bits+7.
    let hi = (bits - 1) % 8;
    buf[0] &= ((1u16 << (hi + 1)) - 1) as u8;
    buf[0] |= 1u8 << hi;
    buf[nbytes - 1] |= 1u8;
    num_bigint::BigUint::from_bytes_be(&buf)
}

/// Miller-Rabin primality test with `rounds` random bases.
fn is_probable_prime(n: &num_bigint::BigUint, rounds: usize) -> bool {
    use num_traits::{One, Zero};
    if *n < 2u32.into() {
        return false;
    }
    if *n == 2u32.into() || *n == 3u32.into() {
        return true;
    }
    if n.bit(0) {
        // odd - proceed with Miller-Rabin
    } else {
        return false;
    }
    // n - 1 = d * 2^r
    let one = num_bigint::BigUint::one();
    let two = num_bigint::BigUint::from(2u32);
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while (&d % &two).is_zero() {
        d /= &two;
        r += 1;
    }
    let n_minus_2 = n - &two;
    for _ in 0..rounds {
        let bits = n.bits() as usize;
        let a = loop {
            let cand = rand_odd_bigint(bits.saturating_sub(1).max(2));
            if cand >= two && cand <= n_minus_2 {
                break cand;
            }
        };
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..r {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

fn prime(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    // Reject bit widths below 64 (err.range reports 64..=4096).
    let bits = range_arg(args, "bits", 512, 64, 4096)? as usize;
    let grade = args.get("grade").map(|s| s.as_str()).unwrap_or("false") == "true";
    let fmt = args.get("format").map(|s| s.as_str()).unwrap_or("decimal");
    // grade=false defaults to 24 rounds (was 7); an explicit
    // `rounds` argument always overrides the grade-based default.
    let rounds = match args
        .get("rounds")
        .map(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        Some(raw) => raw.parse::<usize>().map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.int_invalid", &[e.to_string().as_str()]))
        })?,
        None => {
            if grade {
                40
            } else {
                24
            }
        }
    };
    let mut candidate = rand_odd_bigint(bits);
    let mut attempts = 0u32;
    while !is_probable_prime(&candidate, rounds) {
        candidate = rand_odd_bigint(bits);
        attempts += 1;
        if attempts > 10_000 {
            anyhow::bail!("failed to find a probable prime after 10000 attempts");
        }
    }
    let out = match fmt {
        "decimal" => candidate.to_str_radix(10),
        "hex" => format!("0x{}", candidate.to_str_radix(16)),
        _ => anyhow::bail!("{}", i18n::tf("err.unknown_output_format", &[fmt])),
    };
    Ok(out.into_bytes())
}

fn hotp(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let algo = opt_arg(args, "algo", "sha1").to_string();
    let key_raw = args.get("key").map(|s| s.as_str()).unwrap_or("");
    let (key, secret_b32, generated) = if key_raw.is_empty() {
        let mut k = vec![0u8; 20];
        rand::rng().fill_bytes(&mut k);
        let b32 = base32_encode_std(&k);
        (k, b32, true)
    } else {
        (base32_decode(key_raw)?, String::new(), false)
    };
    let digits = range_arg(args, "digits", 6, 6, 8)? as usize;
    let counter = range_arg(args, "counter", 0, 0, i64::MAX)? as u64;
    let code = otp_code(&algo, &key, counter, digits)?;
    if generated {
        let uri = format!(
            "otpauth://hotp/dpa:{}?digits={digits}&counter={counter}&secret={secret_b32}",
            secret_b32
        );
        let mut out = format!(
            "secret: {secret_b32}\n{uri}\ncode: {}\n",
            String::from_utf8_lossy(&code)
        );
        out.push_str(
            "note: random secret generated for demo only; re-run produces a different secret",
        );
        Ok(out.into_bytes())
    } else {
        Ok(code)
    }
}

fn totp(_input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let algo = opt_arg(args, "algo", "sha1").to_string();
    let key_raw = args.get("key").map(|s| s.as_str()).unwrap_or("");
    let (key, secret_b32, generated) = if key_raw.is_empty() {
        let mut k = vec![0u8; 20];
        rand::rng().fill_bytes(&mut k);
        let b32 = base32_encode_std(&k);
        (k, b32, true)
    } else {
        (base32_decode(key_raw)?, String::new(), false)
    };
    let digits = range_arg(args, "digits", 6, 6, 8)? as usize;
    let period = range_arg(args, "period", 30, 1, 86_400)? as u64;
    let epoch = range_arg(args, "epoch", 0, 0, i64::MAX)? as u64;
    let time: u64 = match args.get("time") {
        Some(s) if !s.is_empty() => s.parse().map_err(|e: std::num::ParseIntError| {
            anyhow::anyhow!("{}", i18n::tf("err.int_invalid", &[e.to_string().as_str()]))
        })?,
        _ => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                anyhow::anyhow!("{}", i18n::tf("err.system_time", &[e.to_string().as_str()]))
            })?
            .as_secs(),
    };
    if time < epoch {
        anyhow::bail!(
            "{}",
            i18n::tf("err.range", &["0", "now", &time.to_string()])
        );
    }
    let counter = (time - epoch) / period;
    let code = otp_code(&algo, &key, counter, digits)?;
    if generated {
        let uri = format!(
            "otpauth://totp/dpa:{}?digits={digits}&period={period}&secret={secret_b32}",
            secret_b32
        );
        let mut out = format!(
            "secret: {secret_b32}\n{uri}\ncode: {}\n",
            String::from_utf8_lossy(&code)
        );
        out.push_str(
            "note: random secret generated for demo only; re-run produces a different secret",
        );
        Ok(out.into_bytes())
    } else {
        Ok(code)
    }
}

#[cfg(test)]
mod generate_tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn base32_decode_vectors() {
        // RFC 4648 test vectors (no padding).
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        // Lowercase accepted, spaces and padding tolerated.
        assert_eq!(base32_decode("mzxw6ytboi======").unwrap(), b"foobar");
        // Invalid character errors.
        assert!(base32_decode("MZXW6YTB0I").is_err());
        assert!(base32_decode("MZXW6YTBO1").is_err());
    }

    #[test]
    fn debruijn_known_sequences() {
        // FKM B(2,2) / B(2,3) / B(3,2).
        let b22 =
            String::from_utf8(de_bruijn(b"", &args(&[("size", "2"), ("order", "2")])).unwrap())
                .unwrap();
        assert_eq!(b22, "0011");
        let b23 =
            String::from_utf8(de_bruijn(b"", &args(&[("size", "2"), ("order", "3")])).unwrap())
                .unwrap();
        assert_eq!(b23, "00010111");
        let b32 =
            String::from_utf8(de_bruijn(b"", &args(&[("size", "3"), ("order", "2")])).unwrap())
                .unwrap();
        assert_eq!(b32, "001021122");
        // Length equals k^n for a valid range.
        let b = de_bruijn(b"", &args(&[("size", "4"), ("order", "3")])).unwrap();
        assert_eq!(b.len(), 64);
    }

    #[test]
    fn debruijn_bounds() {
        assert!(de_bruijn(b"", &args(&[("size", "1")])).is_err());
        assert!(de_bruijn(b"", &args(&[("size", "10")])).is_err());
        assert!(de_bruijn(b"", &args(&[("order", "1")])).is_err());
        // 2^16 = 65536 > 50000 rejected.
        assert!(de_bruijn(b"", &args(&[("size", "2"), ("order", "16")])).is_err());
    }

    #[test]
    fn prime_min_bits_64() {
        // Bit widths below 64 are rejected outright.
        for bad in ["1", "8", "16", "63", "0", "-1"] {
            assert!(
                prime(b"", &args(&[("bits", bad)])).is_err(),
                "bits={bad} should be rejected"
            );
        }
        // At the new lower bound 64, the value is in [2^63, 2^64).
        let out = String::from_utf8(prime(b"", &args(&[("bits", "64")])).unwrap()).unwrap();
        let n: u64 = out.parse().unwrap();
        assert!(((1u64 << 63)..=u64::MAX).contains(&n), "n={n}");
        assert!(is_probable_prime(&num_bigint::BigUint::from(n), 24));
        // 5000 still above the upper bound.
        assert!(prime(b"", &args(&[("bits", "5000")])).is_err());
        // hex format at the new lower bound.
        let hex =
            String::from_utf8(prime(b"", &args(&[("bits", "64"), ("format", "hex")])).unwrap())
                .unwrap();
        assert!(hex.starts_with("0x"));
        assert!(u64::from_str_radix(&hex[2..], 16).is_ok());
    }

    #[test]
    fn prime_exact_bit_length() {
        // Requested bits must be exact (high bits masked), not
        // bits..bits+7 as the old random top-byte left the window open.
        for &bits in &[64usize, 100, 257] {
            for _ in 0..4 {
                let out =
                    String::from_utf8(prime(b"", &args(&[("bits", &bits.to_string())])).unwrap())
                        .unwrap();
                let n = num_bigint::BigUint::parse_bytes(out.as_bytes(), 10).unwrap();
                assert_eq!(
                    n.bits() as usize,
                    bits,
                    "requested {bits} bits, got {}",
                    n.bits()
                );
            }
        }
    }

    #[test]
    fn prime_rounds_default_and_override() {
        // grade=false defaults to 24 rounds; explicit `rounds`
        // overrides the grade-based default.
        let out = String::from_utf8(prime(b"", &args(&[("bits", "64")])).unwrap()).unwrap();
        let n = num_bigint::BigUint::parse_bytes(out.as_bytes(), 10).unwrap();
        assert!(is_probable_prime(&n, 24));
        // Explicit rounds=2 overrides the default (fast path, still valid).
        let out2 =
            String::from_utf8(prime(b"", &args(&[("bits", "64"), ("rounds", "2")])).unwrap())
                .unwrap();
        let n2 = num_bigint::BigUint::parse_bytes(out2.as_bytes(), 10).unwrap();
        assert!(is_probable_prime(&n2, 2));
        // Invalid rounds value is rejected; 0 rounds is tolerated (no checks).
        assert!(prime(b"", &args(&[("bits", "64"), ("rounds", "abc")])).is_err());
        assert!(prime(b"", &args(&[("bits", "64"), ("rounds", "-3")])).is_err());
        assert!(prime(b"", &args(&[("bits", "64"), ("rounds", "0")])).is_ok());
        // Empty rounds string falls back to the default.
        assert!(prime(b"", &args(&[("bits", "64"), ("rounds", "")])).is_ok());
    }

    #[test]
    fn hotp_rfc4226_vectors() {
        // RFC 4226 Appendix D: ASCII seed "12345678901234567890" in base32.
        let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (c, exp) in expected.iter().enumerate() {
            let out = String::from_utf8(
                hotp(b"", &args(&[("key", key), ("counter", &c.to_string())])).unwrap(),
            )
            .unwrap();
            assert_eq!(&out, exp, "counter={c}");
        }
        // 8 digits.
        let out8 = String::from_utf8(
            hotp(
                b"",
                &args(&[("key", key), ("counter", "0"), ("digits", "8")]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(out8, "84755224");
        // digits out of range.
        assert!(hotp(b"", &args(&[("key", key), ("digits", "5")])).is_err());
        assert!(hotp(b"", &args(&[("key", key), ("digits", "9")])).is_err());
        // Empty key generates a random 20-byte secret: output carries the
        // base32 secret, otpauth URI and a 6-digit code (demo-only note).
        let r1 = String::from_utf8(hotp(b"", &HashMap::new()).unwrap()).unwrap();
        assert!(r1.starts_with("secret: "), "got {r1:?}");
        assert!(r1.contains("otpauth://hotp/dpa:"), "got {r1:?}");
        assert!(
            r1.lines().any(|l| l.starts_with("code: ") && l.len() == 12),
            "got {r1:?}"
        );
        let r2 = String::from_utf8(hotp(b"", &HashMap::new()).unwrap()).unwrap();
        assert!(
            r2.starts_with("secret: ") && r2.contains("otpauth://hotp/dpa:"),
            "got {r2:?}"
        );
    }

    #[test]
    fn totp_rfc6238_vectors() {
        // RFC 6238 Appendix B: SHA-1, 8 digits, period 30, epoch 0.
        let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
        ];
        for (t, exp) in cases {
            let out = String::from_utf8(
                totp(
                    b"",
                    &args(&[("key", key), ("digits", "8"), ("time", &t.to_string())]),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(&out, exp, "time={t}");
        }
        // epoch offset shifts the window: T0=30 with time=59 -> counter 0.
        let out = String::from_utf8(
            totp(
                b"",
                &args(&[
                    ("key", key),
                    ("digits", "8"),
                    ("time", "59"),
                    ("epoch", "30"),
                ]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(out, "84755224");
        // Default digits 6.
        let out6 =
            String::from_utf8(totp(b"", &args(&[("key", key), ("time", "59")])).unwrap()).unwrap();
        assert_eq!(out6.len(), 6);
        // period bounds.
        assert!(totp(b"", &args(&[("period", "0")])).is_err());
    }
}
