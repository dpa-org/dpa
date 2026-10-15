//! Protocol parsing ops (single-packet level; deliberately no pcap capture).
//!
//! - `dpa:parse:ethernet` / `ipv4` / `ipv6` / `tcp` / `udp` / `tls`: emit a JSON summary.
//! - `dpa:strip:ethernet` / `ipv4` / `ipv6` / `tcp` / `udp`: drop the header, keep the payload.
//!
//! All parsers are hand-rolled byte readers (no external crates, wasm32-safe).

use std::collections::HashMap;

use serde_json::json;

use super::{ArgSpec, Op};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:parse:ethernet",
            "analyze",
            "op.parse.ethernet.desc",
            &[ArgSpec {
                name: "input_type",
                required: false,
                description: "op.parse.ethernet.arg.input_type",
                format: crate::ops::ArgFormat::Utf8,
            },],
            parse_ethernet
        ),
        op!(
            "dpa:parse:ipv4",
            "analyze",
            "op.parse.ipv4.desc",
            &[ArgSpec {
                name: "input_type",
                required: false,
                description: "op.parse.ipv4.arg.input_type",
                format: crate::ops::ArgFormat::Utf8,
            },],
            parse_ipv4
        ),
        op!(
            "dpa:parse:ipv6",
            "analyze",
            "op.parse.ipv6.desc",
            &[],
            parse_ipv6
        ),
        op!(
            "dpa:parse:tcp",
            "analyze",
            "op.parse.tcp.desc",
            &[ArgSpec {
                name: "input_type",
                required: false,
                description: "op.parse.tcp.arg.input_type",
                format: crate::ops::ArgFormat::Utf8,
            },],
            parse_tcp
        ),
        op!(
            "dpa:parse:udp",
            "analyze",
            "op.parse.udp.desc",
            &[ArgSpec {
                name: "input_type",
                required: false,
                description: "op.parse.udp.arg.input_type",
                format: crate::ops::ArgFormat::Utf8,
            },],
            parse_udp
        ),
        op!(
            "dpa:parse:tls",
            "analyze",
            "op.parse.tls.desc",
            &[],
            parse_tls
        ),
        op!(
            "dpa:strip:ethernet",
            "transform",
            "op.strip.ethernet.desc",
            &[],
            strip_ethernet
        ),
        op!(
            "dpa:strip:ipv4",
            "transform",
            "op.strip.ipv4.desc",
            &[],
            strip_ipv4
        ),
        op!(
            "dpa:strip:ipv6",
            "transform",
            "op.strip.ipv6.desc",
            &[],
            strip_ipv6
        ),
        op!(
            "dpa:strip:tcp",
            "transform",
            "op.strip.tcp.desc",
            &[],
            strip_tcp
        ),
        op!(
            "dpa:strip:udp",
            "transform",
            "op.strip.udp.desc",
            &[],
            strip_udp
        ),
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn need(input: &[u8], n: usize, what: &str) -> anyhow::Result<()> {
    if input.len() < n {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.proto_truncated",
                &[
                    what,
                    n.to_string().as_str(),
                    input.len().to_string().as_str()
                ]
            )
        );
    }
    Ok(())
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode a packet input according to the `input_type` argument.
///
/// - `raw`: use bytes as-is (default when the argument is absent).
/// - `hex`: decode the input as a hex string.
/// - `auto`: decode as hex only when the whole input is a valid even-length
///   hex string; otherwise fall back to raw bytes.
fn decode_packet_input(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let t = args.get("input_type").map(|s| s.as_str()).unwrap_or("raw");
    match t {
        "hex" => hex::decode(String::from_utf8_lossy(input).trim())
            .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.proto_bad_hex"))),
        "auto" => {
            let owned = String::from_utf8_lossy(input);
            let s = owned.trim();
            if s.len() % 2 == 0 && !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(s).map_err(|_| anyhow::anyhow!("{}", i18n::t("err.proto_bad_hex")))
            } else {
                Ok(input.to_vec())
            }
        }
        // "raw" or any unknown value: keep the raw bytes.
        _ => Ok(input.to_vec()),
    }
}

fn mac_str(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipv4_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ipv6_str(b: &[u8]) -> String {
    // RFC 5952-ish: lowercase, compress the longest run of zero groups (>= 2).
    let groups: Vec<u16> = b.chunks_exact(2).map(be16).collect();
    let mut best_start = None;
    let mut best_len = 0usize;
    let mut i = 0usize;
    while i < groups.len() {
        if groups[i] == 0 {
            let s = i;
            while i < groups.len() && groups[i] == 0 {
                i += 1;
            }
            let l = i - s;
            if l >= 2 && l > best_len {
                best_start = Some(s);
                best_len = l;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    if let Some(s) = best_start {
        for (idx, g) in groups.iter().enumerate() {
            if idx == s {
                out.push_str("::");
                continue;
            }
            if idx >= s && idx < s + best_len {
                continue;
            }
            if !out.is_empty() && !out.ends_with("::") {
                out.push(':');
            }
            out.push_str(&format!("{:x}", g));
        }
    } else {
        for (idx, g) in groups.iter().enumerate() {
            if idx > 0 {
                out.push(':');
            }
            out.push_str(&format!("{:x}", g));
        }
    }
    out
}

fn ethertype_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "VLAN tag",
        0x88cc => "LLDP",
        0x88a8 => "QinQ",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        _ => "unknown",
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "unknown",
    }
}

fn tls_content_type(ct: u8) -> &'static str {
    match ct {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat",
        25 => "EarlyApplicationData",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Parse ops
// ---------------------------------------------------------------------------

fn parse_ethernet(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let input = decode_packet_input(input, args)?;
    need(&input, 14, "Ethernet")?;
    let ethertype = be16(&input[12..14]);
    let payload = &input[14..];
    let out = json!({
        "dst_mac": mac_str(&input[0..6]),
        "src_mac": mac_str(&input[6..12]),
        "ethertype": format!("0x{:04x}", ethertype),
        "ethertype_name": ethertype_name(ethertype),
        "payload_bytes": payload.len(),
    });
    Ok(serde_json::to_vec(&out)?)
}

fn parse_ipv4(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let input = decode_packet_input(input, args)?;
    need(&input, 20, "IPv4")?;
    let vihl = input[0];
    let version = vihl >> 4;
    if version != 4 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.proto_bad_ipv4", &[version.to_string().as_str()])
        );
    }
    let ihl = (vihl & 0x0f) as usize * 4;
    need(&input, ihl, "IPv4")?;
    let frag = be16(&input[6..8]);
    let flags = frag >> 13;
    let out = json!({
        "version": 4,
        "ihl": ihl,
        "tos": input[1],
        "total_length": be16(&input[2..4]),
        "identification": be16(&input[4..6]),
        "flags": {
            "reserved": (flags >> 2) & 1,
            "df": (flags >> 1) & 1,
            "mf": flags & 1,
        },
        "fragment_offset": frag & 0x1fff,
        "ttl": input[8],
        "protocol": format!("{} ({})", proto_name(input[9]), input[9]),
        "header_checksum": format!("0x{:04x}", be16(&input[10..12])),
        "src": ipv4_str(&input[12..16]),
        "dst": ipv4_str(&input[16..20]),
        "options_bytes": ihl - 20,
        "payload_bytes": input.len() - ihl,
    });
    Ok(serde_json::to_vec(&out)?)
}

fn parse_ipv6(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 40, "IPv6")?;
    let first = be32(&input[0..4]);
    let version = first >> 28;
    if version != 6 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.proto_bad_ipv6", &[version.to_string().as_str()])
        );
    }
    let traffic_class = ((first >> 20) & 0xff) as u8;
    let flow_label = first & 0x000f_ffff;
    let out = json!({
        "version": 6,
        "traffic_class": traffic_class,
        "flow_label": flow_label,
        "payload_length": be16(&input[4..6]),
        "next_header": format!("{} ({})", proto_name(input[6]), input[6]),
        "hop_limit": input[7],
        "src": ipv6_str(&input[8..24]),
        "dst": ipv6_str(&input[24..40]),
        "payload_bytes": input.len() - 40,
    });
    Ok(serde_json::to_vec(&out)?)
}

fn parse_tcp(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let input = decode_packet_input(input, args)?;
    need(&input, 20, "TCP")?;
    let data_offset = (input[12] >> 4) as usize * 4;
    if data_offset < 20 {
        anyhow::bail!("{}", i18n::t("err.proto_bad_tcp"));
    }
    need(&input, data_offset, "TCP")?;
    let flags = input[13];
    let out = json!({
        "src_port": be16(&input[0..2]),
        "dst_port": be16(&input[2..4]),
        "sequence": be32(&input[4..8]),
        "acknowledgment": be32(&input[8..12]),
        "data_offset": data_offset,
        "flags": {
            "ns": input[12] & 0x01,
            "cwr": (flags >> 7) & 1,
            "ece": (flags >> 6) & 1,
            "urg": (flags >> 5) & 1,
            "ack": (flags >> 4) & 1,
            "psh": (flags >> 3) & 1,
            "rst": (flags >> 2) & 1,
            "syn": (flags >> 1) & 1,
            "fin": flags & 1,
        },
        "window": be16(&input[14..16]),
        "checksum": format!("0x{:04x}", be16(&input[16..18])),
        "urgent_pointer": be16(&input[18..20]),
        "options_bytes": data_offset - 20,
        "payload_bytes": input.len() - data_offset,
    });
    Ok(serde_json::to_vec(&out)?)
}

fn parse_udp(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let input = decode_packet_input(input, args)?;
    need(&input, 8, "UDP")?;
    let out = json!({
        "src_port": be16(&input[0..2]),
        "dst_port": be16(&input[2..4]),
        "length": be16(&input[4..6]),
        "checksum": format!("0x{:04x}", be16(&input[6..8])),
        "payload_bytes": input.len().saturating_sub(8),
    });
    Ok(serde_json::to_vec(&out)?)
}

fn parse_tls(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut records = Vec::new();
    let mut off = 0usize;
    while off < input.len() {
        if input.len() - off < 5 {
            anyhow::bail!("{}", i18n::t("err.proto_bad_tls"));
        }
        let ct = input[off];
        let version = be16(&input[off + 1..off + 3]);
        let len = be16(&input[off + 3..off + 5]) as usize;
        off += 5;
        if off + len > input.len() {
            anyhow::bail!("{}", i18n::t("err.proto_bad_tls"));
        }
        records.push(json!({
            "content_type": tls_content_type(ct),
            "content_type_code": ct,
            "version": format!("0x{:04x}", version),
            "record_length": len,
        }));
        off += len;
    }
    let out = json!({ "records": records, "record_count": records.len() });
    Ok(serde_json::to_vec(&out)?)
}

// ---------------------------------------------------------------------------
// Strip ops (keep payload bytes)
// ---------------------------------------------------------------------------

fn strip_ethernet(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 14, "Ethernet")?;
    Ok(input[14..].to_vec())
}

fn strip_ipv4(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 20, "IPv4")?;
    let vihl = input[0];
    let version = vihl >> 4;
    if version != 4 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.proto_bad_ipv4", &[version.to_string().as_str()])
        );
    }
    let ihl = (vihl & 0x0f) as usize * 4;
    need(input, ihl, "IPv4")?;
    Ok(input[ihl..].to_vec())
}

fn strip_ipv6(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 40, "IPv6")?;
    let version = input[0] >> 4;
    if version != 6 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.proto_bad_ipv6", &[version.to_string().as_str()])
        );
    }
    Ok(input[40..].to_vec())
}

fn strip_tcp(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 20, "TCP")?;
    let data_offset = (input[12] >> 4) as usize * 4;
    if data_offset < 20 {
        anyhow::bail!("{}", i18n::t("err.proto_bad_tcp"));
    }
    need(input, data_offset, "TCP")?;
    Ok(input[data_offset..].to_vec())
}

fn strip_udp(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    need(input, 8, "UDP")?;
    Ok(input[8..].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_parse_and_strip() {
        // dst=aa:bb:cc:dd:ee:ff src=00:11:22:33:44:55 EtherType=0x0800 payload=4 bytes
        let mut f = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ];
        let j: serde_json::Value =
            serde_json::from_slice(&parse_ethernet(&f, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["dst_mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(j["src_mac"], "00:11:22:33:44:55");
        assert_eq!(j["ethertype"], "0x0800");
        assert_eq!(j["ethertype_name"], "IPv4");
        assert_eq!(j["payload_bytes"], 4);
        assert_eq!(
            strip_ethernet(&f, &HashMap::new()).unwrap(),
            b"\xde\xad\xbe\xef"
        );
        f.clear();
        assert!(parse_ethernet(&f, &HashMap::new()).is_err());
    }

    #[test]
    fn ipv4_parse_and_strip() {
        // Standard 20-byte IPv4 header: src=192.168.1.1 dst=10.0.0.1 proto=TCP(6) ttl=64
        let mut p = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            10, 0, 0, 1, 0x41, 0x42,
        ];
        let j: serde_json::Value =
            serde_json::from_slice(&parse_ipv4(&p, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["version"], 4);
        assert_eq!(j["ihl"], 20);
        assert_eq!(j["total_length"], 40);
        assert_eq!(j["flags"]["df"], 1);
        assert_eq!(j["ttl"], 64);
        assert_eq!(j["protocol"], "TCP (6)");
        assert_eq!(j["src"], "192.168.1.1");
        assert_eq!(j["dst"], "10.0.0.1");
        assert_eq!(strip_ipv4(&p, &HashMap::new()).unwrap(), b"\x41\x42");
        // Bad version
        p[0] = 0x65;
        assert!(parse_ipv4(&p, &HashMap::new()).is_err());
        assert!(strip_ipv4(&p, &HashMap::new()).is_err());
    }

    #[test]
    fn ipv6_parse_and_strip() {
        let mut p = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40];
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // 2001:db8::1
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // 2001:db8::2
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let j: serde_json::Value =
            serde_json::from_slice(&parse_ipv6(&p, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["version"], 6);
        assert_eq!(j["next_header"], "TCP (6)");
        assert_eq!(j["hop_limit"], 64);
        assert_eq!(j["src"], "2001:db8::1");
        assert_eq!(j["dst"], "2001:db8::2");
        assert_eq!(
            strip_ipv6(&p, &HashMap::new()).unwrap(),
            b"\xde\xad\xbe\xef"
        );
        p[0] = 0x50;
        assert!(parse_ipv6(&p, &HashMap::new()).is_err());
    }

    #[test]
    fn tcp_parse_and_strip() {
        // 20-byte TCP header with options-free payload: src 1234 dst 80, seq=1 ack=2, SYN+ACK
        let t = vec![
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x12,
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00,
        ];
        let j: serde_json::Value =
            serde_json::from_slice(&parse_tcp(&t, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["src_port"], 1234);
        assert_eq!(j["dst_port"], 80);
        assert_eq!(j["sequence"], 1);
        assert_eq!(j["acknowledgment"], 2);
        assert_eq!(j["flags"]["syn"], 1);
        assert_eq!(j["flags"]["ack"], 1);
        assert_eq!(strip_tcp(&t, &HashMap::new()).unwrap(), b"\x7b\x00");
        // Truncated
        assert!(parse_tcp(&t[..10], &HashMap::new()).is_err());
    }

    #[test]
    fn udp_parse_and_strip() {
        let u = vec![
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef,
        ];
        let j: serde_json::Value =
            serde_json::from_slice(&parse_udp(&u, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["src_port"], 1234);
        assert_eq!(j["dst_port"], 53);
        assert_eq!(j["length"], 12);
        assert_eq!(strip_udp(&u, &HashMap::new()).unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn tls_parse_multiple_records() {
        // Two TLS records: Handshake(22) 0x0303 len 4; ApplicationData(23) 0x0301 len 2
        let mut t = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
        t.extend_from_slice(&[0x17, 0x03, 0x01, 0x00, 0x02, 0x01, 0x02]);
        let j: serde_json::Value =
            serde_json::from_slice(&parse_tls(&t, &HashMap::new()).unwrap()).unwrap();
        assert_eq!(j["record_count"], 2);
        assert_eq!(j["records"][0]["content_type"], "Handshake");
        assert_eq!(j["records"][0]["record_length"], 4);
        assert_eq!(j["records"][1]["content_type"], "ApplicationData");
        assert_eq!(j["records"][1]["record_length"], 2);
        // Truncated record body
        assert!(parse_tls(&t[..12], &HashMap::new()).is_err());
    }

    #[test]
    fn ipv6_formatting_compresses_zero_run() {
        let addr: Vec<u8> = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].to_vec();
        assert_eq!(ipv6_str(&addr), "fe80::1");
    }

    #[test]
    fn packet_input_type_hex_and_auto() {
        let hex_in = "aabbccddeeff0011223344550800deadbeef";
        // hex mode: hex string decodes to bytes then parses.
        let args = HashMap::from([("input_type".to_string(), "hex".to_string())]);
        let j: serde_json::Value =
            serde_json::from_slice(&parse_ethernet(hex_in.as_bytes(), &args).unwrap()).unwrap();
        assert_eq!(j["dst_mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(j["ethertype"], "0x0800");
        // auto mode: valid even-length hex decodes.
        let auto = HashMap::from([("input_type".to_string(), "auto".to_string())]);
        let j2: serde_json::Value =
            serde_json::from_slice(&parse_ethernet(hex_in.as_bytes(), &auto).unwrap()).unwrap();
        assert_eq!(j2["dst_mac"], "aa:bb:cc:dd:ee:ff");
        // auto mode: non-hex input falls back to raw bytes (dst_mac is ASCII hex).
        let raw = b"0123456789abcdefghijklmn";
        let j3: serde_json::Value =
            serde_json::from_slice(&parse_ethernet(raw, &auto).unwrap()).unwrap();
        assert_eq!(j3["dst_mac"], "30:31:32:33:34:35");
        // hex mode with invalid hex errors.
        assert!(parse_ethernet(b"zz", &args).is_err());
        // default (no input_type) is raw: ASCII bytes are kept as-is.
        let j4: serde_json::Value =
            serde_json::from_slice(&parse_ethernet(hex_in.as_bytes(), &HashMap::new()).unwrap())
                .unwrap();
        assert_eq!(j4["dst_mac"], "61:61:62:62:63:63");
        // raw input too short for an Ethernet header errors.
        assert!(parse_ethernet(b"aa", &HashMap::new()).is_err());
    }
}
