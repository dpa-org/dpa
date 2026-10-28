//! Public-key analysis ops (analysis-only domain: format bridge + certificate
//! parsing). Deliberately NO encryption/signing/decryption - standard public-key
//! crypto operations belong to openssl/gmssl, not to a data-processing tool.
//!
//! - `dpa:pem`  : PEM envelope encode/decode (PEM <-> raw DER bytes).
//! - `dpa:x509` : parse an X.509 certificate (PEM or DER) into a JSON summary.

use std::collections::HashMap;

use pem::Pem;

use super::crypto::opt_arg;
use super::{ArgSpec, Op, parse_bool};

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:pem",
            "codec",
            "op.pem.desc",
            &[
                ArgSpec {
                    name: "action",
                    required: false,
                    description: "op.pem.arg.action",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "label",
                    required: false,
                    description: "op.pem.arg.label",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            pem_conv
        ),
        op!(
            "dpa:x509",
            "analyze",
            "op.x509.desc",
            &[ArgSpec {
                name: "raw",
                required: false,
                description: "op.x509.arg.raw",
                format: crate::ops::ArgFormat::Bool,
            },],
            x509_parse
        ),
        op!(
            "dpa:pkcs1:to:pkcs8",
            "codec",
            "op.pkcs1.to.pkcs8.desc",
            &[],
            pkcs1_to_pkcs8
        ),
        op!(
            "dpa:pkcs8:to:pkcs1",
            "codec",
            "op.pkcs8.to.pkcs1.desc",
            &[],
            pkcs8_to_pkcs1
        ),
        op!(
            "dpa:pem:to:jwk",
            "codec",
            "op.pem.to.jwk.desc",
            &[],
            pem_to_jwk
        ),
        op!(
            "dpa:jwk:to:pem",
            "codec",
            "op.jwk.to.pem.desc",
            &[],
            jwk_to_pem
        ),
        op!(
            "dpa:rsa:verify",
            "crypto",
            "op.rsa.verify.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.rsa.verify.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.rsa.verify.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "digest",
                    required: false,
                    description: "op.rsa.verify.arg.digest",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "signature",
                    required: true,
                    description: "op.rsa.verify.arg.signature",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sig_format",
                    required: false,
                    description: "op.rsa.verify.arg.sig_format",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            rsa_verify
        ),
        op!(
            "dpa:ecdsa:verify",
            "crypto",
            "op.ecdsa.verify.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.ecdsa.verify.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "digest",
                    required: false,
                    description: "op.ecdsa.verify.arg.digest",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "signature",
                    required: true,
                    description: "op.ecdsa.verify.arg.signature",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sig_format",
                    required: false,
                    description: "op.ecdsa.verify.arg.sig_format",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sig_type",
                    required: false,
                    description: "op.ecdsa.verify.arg.sig_type",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            ecdsa_verify
        ),
        op!(
            "dpa:csr:parse",
            "analyze",
            "op.csr.parse.desc",
            &[],
            csr_parse
        ),
        op!(
            "dpa:pubkey:extract",
            "codec",
            "op.pubkey.extract.desc",
            &[],
            pubkey_extract
        ),
        op!(
            "dpa:ssh:parse",
            "analyze",
            "op.ssh.parse.desc",
            &[ArgSpec {
                name: "input_format",
                required: false,
                description: "op.ssh.parse.arg.input_format",
                format: crate::ops::ArgFormat::Utf8,
            },],
            ssh_parse
        ),
        op!(
            "dpa:asn1:parse",
            "analyze",
            "op.asn1.parse.desc",
            &[],
            asn1_parse
        ),
        op!(
            "dpa:sm2:parse",
            "analyze",
            "op.sm2.parse.desc",
            &[ArgSpec {
                name: "raw",
                required: false,
                description: "op.sm2.parse.arg.raw",
                format: crate::ops::ArgFormat::Bool,
            },],
            sm2_parse
        ),
        op!(
            "dpa:sm2:pubkey:extract",
            "codec",
            "op.sm2.pubkey.extract.desc",
            &[],
            sm2_pubkey_extract
        ),
        op!(
            "dpa:sm2:key:parse",
            "analyze",
            "op.sm2.key.parse.desc",
            &[],
            sm2_key_parse
        ),
        op!(
            "dpa:sm2:verify",
            "crypto",
            "op.sm2.verify.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.sm2.verify.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "digest",
                    required: false,
                    description: "op.sm2.verify.arg.digest",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "signature",
                    required: true,
                    description: "op.sm2.verify.arg.signature",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sig_format",
                    required: false,
                    description: "op.sm2.verify.arg.sig_format",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sig_type",
                    required: false,
                    description: "op.sm2.verify.arg.sig_type",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "distid",
                    required: false,
                    description: "op.sm2.verify.arg.distid",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sm2_verify
        ),
    ]
}

/// `dpa:pem` - strip or add a PEM envelope. decode reads the first PEM block and
/// returns its raw DER contents; encode wraps input bytes in a PEM block with the
/// requested type tag.
fn pem_conv(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let action = opt_arg(args, "action", "decode");
    match action {
        "decode" => {
            let parsed = pem::parse(input).map_err(|e| {
                anyhow::anyhow!("PEM decode failed: {e} (input length {})", input.len())
            })?;
            Ok(parsed.contents().to_vec())
        }
        "encode" => {
            let label = opt_arg(args, "label", "PUBLIC KEY");
            let block = Pem::new(label.to_string(), input.to_vec());
            let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
            Ok(pem::encode_config(&block, config).into_bytes())
        }
        other => Err(anyhow::anyhow!(
            "unknown action '{other}' (expected decode or encode)"
        )),
    }
}

/// `dpa:x509` - parse a certificate (PEM or DER) and emit a JSON summary of the
/// fields a data analyst most often needs. Output is a pretty-printed JSON text.
fn x509_parse(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use x509_parser::parse_x509_certificate;

    // Accept both PEM and DER: strip a PEM envelope first when present, otherwise
    // treat the input as raw DER.
    let der: Vec<u8> = match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => input.to_vec(),
    };

    // Raw mode: emit the certificate DER as hex instead of the parsed JSON
    // summary (align CyberChef Parse X.509 Certificate "Raw" output).
    if let Some(v) = args.get("raw")
        && parse_bool(v)?
    {
        return Ok(hex::encode(&der).into_bytes());
    }

    let (_, cert) = parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("not a valid PEM or DER X.509 certificate: {e}"))?;

    let pki = &cert.subject_pki;
    let alg_oid = pki.algorithm.algorithm.to_string();
    // Real certificate signature algorithm (e.g. SM2-with-SM3 for SM2 certs).
    let sig_oid = cert.signature_algorithm.oid().to_string();

    // Enrich the subject public key with curve details when the SPKI carries
    // an EC/SM2 key. SM2 point validity is checked by the same sm2.rs path
    // used by `dpa:sm2:verify` (RustCrypto sm2 0.14, default GM/T distid).
    let spk_oid = spki_algorithm_oid(pki);
    let mut spk_json = serde_json::json!({
        "algorithm_oid": alg_oid,
        "der_hex": hex::encode(pki.subject_public_key.clone()),
    });
    match spk_oid.as_str() {
        OID_EC_P256 => {
            spk_json["curve_oid"] = serde_json::Value::String(OID_EC_P256.to_string());
            spk_json["curve"] = serde_json::Value::String("nistp256".to_string());
            spk_json["bits"] = serde_json::Value::from(256);
        }
        OID_EC_P384 => {
            spk_json["curve_oid"] = serde_json::Value::String(OID_EC_P384.to_string());
            spk_json["curve"] = serde_json::Value::String("nistp384".to_string());
            spk_json["bits"] = serde_json::Value::from(384);
        }
        OID_EC_SECP256K1 => {
            spk_json["curve_oid"] = serde_json::Value::String(OID_EC_SECP256K1.to_string());
            spk_json["curve"] = serde_json::Value::String("secp256k1".to_string());
            spk_json["bits"] = serde_json::Value::from(256);
        }
        OID_EC_SM2 => {
            use sm2::dsa::VerifyingKey;
            let point_valid = VerifyingKey::from_sec1_bytes(
                SM2_DEFAULT_DISTID,
                pki.subject_public_key.data.as_ref(),
            )
            .is_ok();
            spk_json["curve_oid"] = serde_json::Value::String(OID_EC_SM2.to_string());
            spk_json["curve"] = serde_json::Value::String("sm2".to_string());
            spk_json["bits"] = serde_json::Value::from(256);
            spk_json["point_valid"] = serde_json::Value::from(point_valid);
        }
        _ => {}
    }

    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => {
            use x509_parser::extensions::GeneralName;
            let items: Vec<serde_json::Value> = ext
                .value
                .general_names
                .iter()
                .map(|gn| match gn {
                    GeneralName::DNSName(s) => serde_json::Value::String(format!("DNS:{s}")),
                    GeneralName::RFC822Name(s) => serde_json::Value::String(format!("EMAIL:{s}")),
                    GeneralName::URI(s) => serde_json::Value::String(format!("URI:{s}")),
                    GeneralName::IPAddress(bytes) => {
                        let ip = match bytes.len() {
                            4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                                .to_string(),
                            16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap())
                                .to_string(),
                            _ => format!("IP:{}", String::from_utf8_lossy(bytes)),
                        };
                        serde_json::Value::String(format!("IP:{ip}"))
                    }
                    other => serde_json::Value::String(format!("{other:?}")),
                })
                .collect();
            serde_json::Value::Array(items)
        }
        _ => serde_json::Value::Null,
    };

    let json = serde_json::json!({
        "version": match cert.version().0 {
            0 => "V1",
            1 => "V2",
            _ => "V3",
        },
        "serial": format!("{:x}", cert.serial),
        "signature_algorithm": {
            "oid": sig_oid,
        },
        "issuer": cert.issuer().to_string(),
        "validity": {
            "not_before": cert
                .validity()
                .not_before
                .to_rfc2822()
                .map_err(|e| anyhow::anyhow!("invalid not_before: {e}"))?,
            "not_after": cert
                .validity()
                .not_after
                .to_rfc2822()
                .map_err(|e| anyhow::anyhow!("invalid not_after: {e}"))?,
        },
        "subject": cert.subject().to_string(),
        "subject_public_key": spk_json,
        "subject_alt_name": san,
    });

    Ok(serde_json::to_string_pretty(&json)?.into_bytes())
}

// ---------------------------------------------------------------------------
// Format bridge: PKCS#1 <-> PKCS#8 (RSA)
// ---------------------------------------------------------------------------

/// `dpa:pkcs1:to:pkcs8` - re-wrap an RSA PEM key from PKCS#1 into PKCS#8.
/// Accepts either a private key (`RSA PRIVATE KEY`) or a public key
/// (`RSA PUBLIC KEY`) and emits the PKCS#8 form (`PRIVATE KEY` / `PUBLIC KEY`).
fn pkcs1_to_pkcs8(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    let text =
        std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("input is not a PEM text"))?;
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs1_pem(text) {
        return Ok(k.to_pkcs8_pem(LineEnding::LF)?.as_bytes().to_vec());
    }
    if let Ok(k) = rsa::RsaPublicKey::from_pkcs1_pem(text) {
        return Ok(k.to_public_key_pem(LineEnding::LF)?.into_bytes());
    }
    anyhow::bail!("input is not a PKCS#1 RSA PEM key (expected RSA PRIVATE KEY or RSA PUBLIC KEY)")
}

/// `dpa:pkcs8:to:pkcs1` - re-wrap an RSA PEM key from PKCS#8 back into PKCS#1.
/// Accepts `PRIVATE KEY` (RSA) or `PUBLIC KEY` (RSA) and emits
/// `RSA PRIVATE KEY` / `RSA PUBLIC KEY`.
fn pkcs8_to_pkcs1(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, LineEnding};

    let text =
        std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("input is not a PEM text"))?;
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_pem(text) {
        return Ok(k.to_pkcs1_pem(LineEnding::LF)?.as_bytes().to_vec());
    }
    if let Ok(k) = rsa::RsaPublicKey::from_public_key_pem(text) {
        return Ok(k.to_pkcs1_pem(LineEnding::LF)?.as_bytes().to_vec());
    }
    anyhow::bail!(
        "input is not a PKCS#8 RSA PEM key (expected PRIVATE KEY or PUBLIC KEY with RSA algorithm)"
    )
}

// ---------------------------------------------------------------------------
// Format bridge: PEM <-> JWK
// ---------------------------------------------------------------------------

fn b64url_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("invalid base64url value: {e}"))
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
const OID_EC_P384: &str = "1.3.132.0.10";
const OID_EC_SECP256K1: &str = "1.3.132.0.34";
/// SM2 curve / algorithm OID (GB/T 32918): 1.2.156.10197.1.301.
pub(crate) const OID_EC_SM2: &str = "1.2.156.10197.1.301";

/// Resolve the *concrete* algorithm OID of an SPKI: RSA encodes rsaEncryption in
/// `algorithm`, while EC encodes id-ecPublicKey there and puts the named curve
/// OID in `algorithm.parameters`.
pub(crate) fn spki_algorithm_oid(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> String {
    use x509_parser::asn1_rs::{FromDer, Oid};
    let algo = spki.algorithm.algorithm.to_string();
    if algo != OID_EC {
        return algo;
    }
    // parameters is an optional ASN.1 ANY; the curve OID is its content.
    if let Some(any) = spki.algorithm.parameters.as_ref() {
        if let Ok(oid) = any.as_oid() {
            return oid.to_string();
        }
        if let Ok((_, oid)) = Oid::from_der(any.data) {
            return oid.to_string();
        }
    }
    algo
}

fn rsa_jwk(k: &rsa::RsaPublicKey) -> anyhow::Result<Vec<u8>> {
    use rsa::traits::PublicKeyParts;
    let json = serde_json::json!({
        "kty": "RSA",
        "n": b64url_encode(&k.n().to_bytes_be()),
        "e": b64url_encode(&k.e().to_bytes_be()),
    });
    Ok(serde_json::to_vec(&json)?)
}

fn ec_jwk(crv: &str, sec1: &[u8]) -> anyhow::Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::ToSec1Point as _;

    let (x, y): (Vec<u8>, Vec<u8>) = match crv {
        "P-256" => {
            let pk = p256::PublicKey::from_sec1_bytes(sec1)
                .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {e}"))?;
            let pt = pk.to_sec1_point(false);
            (
                pt.x()
                    .ok_or_else(|| anyhow::anyhow!("missing x coordinate"))?
                    .to_vec(),
                pt.y()
                    .ok_or_else(|| anyhow::anyhow!("missing y coordinate"))?
                    .to_vec(),
            )
        }
        "P-384" => {
            let pk = p384::PublicKey::from_sec1_bytes(sec1)
                .map_err(|e| anyhow::anyhow!("invalid P-384 public key: {e}"))?;
            let pt = pk.to_sec1_point(false);
            (
                pt.x()
                    .ok_or_else(|| anyhow::anyhow!("missing x coordinate"))?
                    .to_vec(),
                pt.y()
                    .ok_or_else(|| anyhow::anyhow!("missing y coordinate"))?
                    .to_vec(),
            )
        }
        "secp256k1" => {
            let pk = k256::PublicKey::from_sec1_bytes(sec1)
                .map_err(|e| anyhow::anyhow!("invalid secp256k1 public key: {e}"))?;
            let pt = pk.to_sec1_point(false);
            (
                pt.x()
                    .ok_or_else(|| anyhow::anyhow!("missing x coordinate"))?
                    .to_vec(),
                pt.y()
                    .ok_or_else(|| anyhow::anyhow!("missing y coordinate"))?
                    .to_vec(),
            )
        }
        "SM2" => {
            // Reuse the sm2.rs curve-point validation (RustCrypto sm2 0.14,
            // default GM/T 0003 distid) so x509/SPKI/jwk handling accepts the
            // same points as dpa:sm2:verify.
            use sm2::dsa::VerifyingKey;
            let vk = VerifyingKey::from_sec1_bytes(SM2_DEFAULT_DISTID, sec1)
                .map_err(|e| anyhow::anyhow!("invalid SM2 public key: {e}"))?;
            let pt = vk.to_sec1_point(false);
            (
                pt.x()
                    .ok_or_else(|| anyhow::anyhow!("missing x coordinate"))?
                    .to_vec(),
                pt.y()
                    .ok_or_else(|| anyhow::anyhow!("missing y coordinate"))?
                    .to_vec(),
            )
        }
        other => anyhow::bail!("unsupported EC curve OID '{other}'"),
    };
    let json = serde_json::json!({
        "kty": "EC",
        "crv": crv,
        "x": b64url_encode(&x),
        "y": b64url_encode(&y),
    });
    Ok(serde_json::to_vec(&json)?)
}

/// `dpa:pem:to:jwk` - convert a PEM public key (RSA or EC) into a JWK JSON object.
fn pem_to_jwk(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;

    let text =
        std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("input is not a PEM text"))?;

    // PKCS#1 RSA ("RSA PUBLIC KEY") straight to JWK.
    if let Ok(k) = rsa::RsaPublicKey::from_pkcs1_pem(text) {
        return rsa_jwk(&k);
    }

    // SPKI-based: strip an optional PEM envelope, then dispatch on algorithm OID.
    let der = match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => input.to_vec(),
    };
    use x509_parser::asn1_rs::FromDer;
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&der)
        .map_err(|e| anyhow::anyhow!("not a valid PEM or DER public key: {e}"))?;
    let oid = spki_algorithm_oid(&spki);
    match oid.as_str() {
        OID_RSA => {
            // SPKI subjectPublicKey is the PKCS#1 RSAPublicKey DER.
            let k = rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
                .map_err(|e| anyhow::anyhow!("invalid RSA public key: {e}"))?;
            rsa_jwk(&k)
        }
        OID_EC_P256 => ec_jwk("P-256", spki.subject_public_key.data.as_ref()),
        OID_EC_P384 => ec_jwk("P-384", spki.subject_public_key.data.as_ref()),
        OID_EC_SECP256K1 => ec_jwk("secp256k1", spki.subject_public_key.data.as_ref()),
        OID_EC_SM2 => ec_jwk("SM2", spki.subject_public_key.data.as_ref()),
        other => anyhow::bail!(
            "unsupported public key algorithm OID '{other}' (only RSA / P-256 / P-384 / secp256k1 / SM2)"
        ),
    }
}

/// `dpa:jwk:to:pem` - convert a JWK JSON object (RSA or EC public key) into a PEM public key.
fn jwk_to_pem(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::FromSec1Point as _;
    use k256::pkcs8::EncodePublicKey as _;
    use rsa::pkcs8::EncodePublicKey as _;

    let v: serde_json::Value = serde_json::from_slice(input)
        .map_err(|e| anyhow::anyhow!("input is not valid JWK JSON: {e}"))?;
    let kty = v["kty"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("JWK missing string field kty"))?;
    match kty {
        "RSA" => {
            let n_str = v["n"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("JWK missing field n"))?;
            let e_str = v["e"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("JWK missing field e"))?;
            let n = rsa::BigUint::from_bytes_be(&b64url_decode(n_str)?);
            let e = rsa::BigUint::from_bytes_be(&b64url_decode(e_str)?);
            let k = rsa::RsaPublicKey::new(n, e)
                .map_err(|err| anyhow::anyhow!("invalid RSA modulus/exponent: {err}"))?;
            Ok(k.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?
                .into_bytes())
        }
        "EC" => {
            let crv = v["crv"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("JWK missing field crv"))?;
            let x = b64url_decode(
                v["x"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("JWK missing field x"))?,
            )?;
            let y = b64url_decode(
                v["y"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("JWK missing field y"))?,
            )?;
            let pem = match crv {
                "P-256" => {
                    let pt = p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_affine_coordinates(
                        &p256::FieldBytes::try_from(x.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid p256::NistP256 x length"))?,
                        &p256::FieldBytes::try_from(y.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid p256::NistP256 y length"))?,
                        false,
                    );
                    let pk = p256::PublicKey::from_sec1_point(&pt)
                        .ok_or_else(|| anyhow::anyhow!("invalid P-256 point"))?;
                    pk.to_public_key_pem(p256::pkcs8::LineEnding::LF)?
                }
                "P-384" => {
                    let pt = p384::elliptic_curve::sec1::Sec1Point::<p384::NistP384>::from_affine_coordinates(
                        &p384::FieldBytes::try_from(x.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid p384::NistP384 x length"))?,
                        &p384::FieldBytes::try_from(y.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid p384::NistP384 y length"))?,
                        false,
                    );
                    let pk = p384::PublicKey::from_sec1_point(&pt)
                        .ok_or_else(|| anyhow::anyhow!("invalid P-384 point"))?;
                    pk.to_public_key_pem(p256::pkcs8::LineEnding::LF)?
                }
                "secp256k1" => {
                    let pt = k256::elliptic_curve::sec1::Sec1Point::<k256::Secp256k1>::from_affine_coordinates(
                        &k256::FieldBytes::try_from(x.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid k256::Secp256k1 x length"))?,
                        &k256::FieldBytes::try_from(y.as_slice())
                            .map_err(|_| anyhow::anyhow!("invalid k256::Secp256k1 y length"))?,
                        false,
                    );
                    let pk = k256::PublicKey::from_sec1_point(&pt)
                        .ok_or_else(|| anyhow::anyhow!("invalid secp256k1 point"))?;
                    pk.to_public_key_pem(p256::pkcs8::LineEnding::LF)?
                }
                other => anyhow::bail!(
                    "unsupported JWK crv '{other}' (expected P-256 / P-384 / secp256k1)"
                ),
            };
            Ok(pem.into_bytes())
        }
        other => anyhow::bail!("unsupported JWK kty '{other}' (expected RSA or EC)"),
    }
}

// ---------------------------------------------------------------------------
// Verify-only signature checking (analysis domain: no signing, no key creation)
// ---------------------------------------------------------------------------

pub(crate) fn req_arg<'a>(
    args: &'a HashMap<String, String>,
    name: &str,
) -> anyhow::Result<&'a str> {
    args.get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument '{name}'"))
}

pub(crate) fn decode_sig(s: &str, fmt: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    match fmt {
        "hex" => hex::decode(s).map_err(|e| anyhow::anyhow!("signature is not valid hex: {e}")),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| anyhow::anyhow!("signature is not valid base64: {e}")),
        other => anyhow::bail!("unknown sig_format '{other}' (expected hex or base64)"),
    }
}

pub(crate) fn hash_input(input: &[u8], algo: &str) -> anyhow::Result<Vec<u8>> {
    use sha2::Digest as _;
    Ok(match algo {
        "sha256" => sha2::Sha256::digest(input).to_vec(),
        "sha384" => sha2::Sha384::digest(input).to_vec(),
        "sha512" => sha2::Sha512::digest(input).to_vec(),
        "sm3" => sm3::Sm3::digest(input).to_vec(),
        other => {
            anyhow::bail!("unknown digest '{other}' (expected sha256 / sha384 / sha512 / sm3)")
        }
    })
}

/// `dpa:rsa:verify` - verify an RSA signature (PKCS#1 v1.5 or PSS) over the
/// input message. The public key is passed via the `key` argument as PEM.
/// Emits the UTF-8 text `true` / `false`.
fn rsa_verify(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::sha2::Digest as _;

    let key_pem = req_arg(args, "key")?;
    let padding = opt_arg(args, "padding", "pkcs1v15");
    let digest = opt_arg(args, "digest", "sha256");
    let sig = decode_sig(
        req_arg(args, "signature")?,
        opt_arg(args, "sig_format", "hex"),
    )?;

    let pubkey = rsa::RsaPublicKey::from_public_key_pem(key_pem)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(key_pem))
        .map_err(|e| anyhow::anyhow!("invalid RSA public key: {e}"))?;

    let hashed = match digest {
        "sha256" => rsa::sha2::Sha256::digest(input).to_vec(),
        "sha384" => rsa::sha2::Sha384::digest(input).to_vec(),
        "sha512" => rsa::sha2::Sha512::digest(input).to_vec(),
        other => anyhow::bail!("unknown digest '{other}' (expected sha256 / sha384 / sha512)"),
    };

    let ok = match (digest, padding) {
        ("sha256", "pkcs1v15") => pubkey
            .verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                &hashed,
                &sig,
            )
            .is_ok(),
        ("sha384", "pkcs1v15") => pubkey
            .verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha384>(),
                &hashed,
                &sig,
            )
            .is_ok(),
        ("sha512", "pkcs1v15") => pubkey
            .verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha512>(),
                &hashed,
                &sig,
            )
            .is_ok(),
        ("sha256", "pss") => pubkey
            .verify(rsa::pss::Pss::new::<rsa::sha2::Sha256>(), &hashed, &sig)
            .is_ok(),
        ("sha384", "pss") => pubkey
            .verify(rsa::pss::Pss::new::<rsa::sha2::Sha384>(), &hashed, &sig)
            .is_ok(),
        ("sha512", "pss") => pubkey
            .verify(rsa::pss::Pss::new::<rsa::sha2::Sha512>(), &hashed, &sig)
            .is_ok(),
        (d, p) => anyhow::bail!("unsupported digest/padding combination '{d}' + '{p}'"),
    };

    Ok(if ok {
        b"true\n".to_vec()
    } else {
        b"false\n".to_vec()
    })
}

/// `dpa:ecdsa:verify` - verify an ECDSA signature (DER or raw r||s) over the
/// input message with a PEM EC public key. Curve is detected from the SPKI OID.
/// Emits the UTF-8 text `true` / `false`.
fn ecdsa_verify(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key_pem = req_arg(args, "key")?;
    let digest = opt_arg(args, "digest", "sha256");
    let sig_type = opt_arg(args, "sig_type", "der");
    let sig = decode_sig(
        req_arg(args, "signature")?,
        opt_arg(args, "sig_format", "hex"),
    )?;

    let der = match pem::parse(key_pem.as_bytes()) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => key_pem.as_bytes().to_vec(),
    };
    use x509_parser::asn1_rs::FromDer;
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&der)
        .map_err(|e| anyhow::anyhow!("not a valid PEM or DER EC public key: {e}"))?;
    let oid = spki_algorithm_oid(&spki);
    let point = spki.subject_public_key.data.as_ref();
    let hashed = hash_input(input, digest)?;

    let ok = match oid.as_str() {
        OID_EC_P256 => ecdsa_verify_p256(point, &hashed, &sig, sig_type)?,
        OID_EC_P384 => ecdsa_verify_p384(point, &hashed, &sig, sig_type)?,
        OID_EC_SECP256K1 => ecdsa_verify_k256(point, &hashed, &sig, sig_type)?,
        other => anyhow::bail!(
            "unsupported EC public key OID '{other}' (only P-256 / P-384 / secp256k1)"
        ),
    };

    Ok(if ok {
        b"true\n".to_vec()
    } else {
        b"false\n".to_vec()
    })
}

fn ecdsa_verify_p256(
    point: &[u8],
    hashed: &[u8],
    sig: &[u8],
    sig_type: &str,
) -> anyhow::Result<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {e}"))?;
    let sig = match sig_type {
        "der" => {
            Signature::from_der(sig).map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?
        }
        "raw" => {
            if sig.len() != 64 {
                anyhow::bail!("raw P-256 signature must be exactly 64 bytes (r||s)");
            }
            let r = p256::FieldBytes::try_from(&sig[..32])
                .map_err(|_| anyhow::anyhow!("invalid r scalar"))?;
            let s = p256::FieldBytes::try_from(&sig[32..])
                .map_err(|_| anyhow::anyhow!("invalid s scalar"))?;
            Signature::from_scalars(r, s)
                .map_err(|e| anyhow::anyhow!("invalid raw signature: {e}"))?
        }
        other => anyhow::bail!("unknown sig_type '{other}' (expected der or raw)"),
    };
    Ok(vk.verify_prehash(hashed, &sig).is_ok())
}

fn ecdsa_verify_p384(
    point: &[u8],
    hashed: &[u8],
    sig: &[u8],
    sig_type: &str,
) -> anyhow::Result<bool> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    use p384::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| anyhow::anyhow!("invalid P-384 public key: {e}"))?;
    let sig = match sig_type {
        "der" => {
            Signature::from_der(sig).map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?
        }
        "raw" => {
            if sig.len() != 96 {
                anyhow::bail!("raw P-384 signature must be exactly 96 bytes (r||s)");
            }
            let r = p384::FieldBytes::try_from(&sig[..48])
                .map_err(|_| anyhow::anyhow!("invalid r scalar"))?;
            let s = p384::FieldBytes::try_from(&sig[48..])
                .map_err(|_| anyhow::anyhow!("invalid s scalar"))?;
            Signature::from_scalars(r, s)
                .map_err(|e| anyhow::anyhow!("invalid raw signature: {e}"))?
        }
        other => anyhow::bail!("unknown sig_type '{other}' (expected der or raw)"),
    };
    Ok(vk.verify_prehash(hashed, &sig).is_ok())
}

fn ecdsa_verify_k256(
    point: &[u8],
    hashed: &[u8],
    sig: &[u8],
    sig_type: &str,
) -> anyhow::Result<bool> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use k256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 public key: {e}"))?;
    let sig = match sig_type {
        "der" => {
            Signature::from_der(sig).map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?
        }
        "raw" => {
            if sig.len() != 64 {
                anyhow::bail!("raw secp256k1 signature must be exactly 64 bytes (r||s)");
            }
            let r = k256::FieldBytes::try_from(&sig[..32])
                .map_err(|_| anyhow::anyhow!("invalid r scalar"))?;
            let s = k256::FieldBytes::try_from(&sig[32..])
                .map_err(|_| anyhow::anyhow!("invalid s scalar"))?;
            Signature::from_scalars(r, s)
                .map_err(|e| anyhow::anyhow!("invalid raw signature: {e}"))?
        }
        other => anyhow::bail!("unknown sig_type '{other}' (expected der or raw)"),
    };
    Ok(vk.verify_prehash(hashed, &sig).is_ok())
}

// ---------------------------------------------------------------------------
// CSR parsing, public-key extraction, PEM<->hex, SSH host keys, ASN.1 hex
// ---------------------------------------------------------------------------

/// `dpa:csr:parse` - parse a PKCS#10 Certificate Signing Request and emit a
/// JSON summary (subject, public key, signature algorithm, signature validity).
fn csr_parse(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use x509_parser::asn1_rs::FromDer;
    use x509_parser::certification_request::X509CertificationRequest;

    let der: Vec<u8> = match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => input.to_vec(),
    };
    let (_, req) = X509CertificationRequest::from_der(&der)
        .map_err(|e| anyhow::anyhow!("not a valid PEM or DER PKCS#10 CSR: {e}"))?;

    let info = &req.certification_request_info;
    let pki = &info.subject_pki;
    let mut json = serde_json::json!({
        "subject": info.subject.to_string(),
        "subject_public_key": {
            "algorithm_oid": pki.algorithm.algorithm.to_string(),
            "der_hex": hex::encode(pki.raw),
        },
        "signature_algorithm": req.signature_algorithm.algorithm.to_string(),
    });
    let attr_oids: Vec<serde_json::Value> = info
        .attributes()
        .iter()
        .map(|a| serde_json::Value::String(a.oid.to_string()))
        .collect();
    if !attr_oids.is_empty() {
        json["attributes"] = serde_json::Value::Array(attr_oids);
    }
    Ok(serde_json::to_string_pretty(&json)?.into_bytes())
}

/// `dpa:pubkey:extract` - pull the SPKI out of a certificate or CSR and emit
/// it as a PEM PUBLIC KEY block.
fn pubkey_extract(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use x509_parser::asn1_rs::FromDer;
    use x509_parser::certification_request::X509CertificationRequest;

    let der: Vec<u8> = match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => input.to_vec(),
    };
    let spki: Vec<u8> = if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) {
        cert.subject_pki.raw.to_vec()
    } else if let Ok((_, req)) = X509CertificationRequest::from_der(&der) {
        req.certification_request_info.subject_pki.raw.to_vec()
    } else {
        anyhow::bail!("input is not a parseable X.509 certificate or PKCS#10 CSR");
    };
    let pem_out = pem::Pem::new("PUBLIC KEY", spki).to_string();
    Ok(pem_out.into_bytes())
}

/// `dpa:ssh:parse` - parse an OpenSSH public-key line (authorized_keys format)
/// and emit algorithm, bits, raw fields and the SHA256 fingerprint.
fn ssh_parse(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let fmt = args
        .get("input_format")
        .map(|s| s.as_str())
        .unwrap_or("auto");
    match fmt {
        "rfc4716" => parse_rfc4716(input),
        "pkcs8" => parse_pkcs8_spki(input),
        "openssh" => parse_openssh_line(input),
        // "auto" (default): sniff the envelope and dispatch.
        _ => {
            let t = String::from_utf8_lossy(input);
            if t.contains("---- BEGIN SSH2 PUBLIC KEY ----") {
                return parse_rfc4716(input);
            }
            if t.contains("-----BEGIN PUBLIC KEY-----")
                || t.contains("-----BEGIN RSA PUBLIC KEY-----")
            {
                return parse_pkcs8_spki(input);
            }
            parse_openssh_line(input)
        }
    }
}

/// Parse an OpenSSH authorized_keys line: `keytype base64 [comment]`.
fn parse_openssh_line(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("input is not an SSH public key line"))?;
    let line = text.trim();
    let mut parts = line.split_whitespace();
    let _keytype = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty SSH key line"))?;
    let b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing base64 key blob"))?;
    let comment = parts.next().unwrap_or("").to_string();

    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| anyhow::anyhow!("invalid base64 key blob: {e}"))?;

    let mut json = parse_ssh_blob(&blob)?;
    json["format"] = serde_json::Value::String("OpenSSH (authorized_keys)".to_string());
    json["comment"] = serde_json::Value::String(comment);

    // RFC 4253 fingerprint: SHA256 over the raw key blob, base64 without padding.
    let digest = Sha256::digest(&blob);
    let fp = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, digest);
    json["fingerprint_sha256"] = serde_json::Value::String(format!("SHA256:{fp}"));
    json["blob_hex"] = serde_json::Value::String(hex::encode(&blob));

    Ok(serde_json::to_string_pretty(&json)?.into_bytes())
}

/// Parse an SSH2 public key blob (RFC 4253 wire format) into a JSON summary.
fn parse_ssh_blob(blob: &[u8]) -> anyhow::Result<serde_json::Value> {
    // RFC 4253: first a u32-len string holds the algorithm name.
    let mut pos = 0usize;
    let read_str = |pos: &mut usize, data: &[u8]| -> anyhow::Result<Vec<u8>> {
        if *pos + 4 > data.len() {
            anyhow::bail!("truncated SSH key blob");
        }
        let len = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
        *pos += 4;
        if *pos + len > data.len() {
            anyhow::bail!("truncated SSH key blob field");
        }
        let out = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(out)
    };
    let algo = read_str(&mut pos, blob)?;
    let algo = String::from_utf8_lossy(&algo).into_owned();

    let mut json = serde_json::json!({ "algorithm": algo });

    match algo.as_str() {
        "ssh-rsa" => {
            let e = read_str(&mut pos, blob)?;
            let n = read_str(&mut pos, blob)?;
            let bits = mpint_bits(&n);
            json["bits"] = serde_json::Value::from(bits);
            json["fields"] = serde_json::json!({
                "exponent_hex": hex::encode(e),
                "modulus_hex": hex::encode(n),
            });
        }
        "ssh-ed25519" => {
            let pk = read_str(&mut pos, blob)?;
            json["bits"] = serde_json::Value::from(256);
            json["fields"] = serde_json::json!({ "public_key_hex": hex::encode(pk) });
        }
        a if a.starts_with("ecdsa-sha2-") => {
            let curve = String::from_utf8_lossy(&read_str(&mut pos, blob)?).into_owned();
            let q = read_str(&mut pos, blob)?;
            let bits = match curve.as_str() {
                "nistp256" => 256,
                "nistp384" => 384,
                "nistp521" => 521,
                _ => q.len() * 8,
            };
            json["bits"] = serde_json::Value::from(bits);
            json["fields"] = serde_json::json!({
                "curve": curve,
                "point_hex": hex::encode(q),
            });
        }
        other => anyhow::bail!("unsupported SSH key algorithm '{other}'"),
    }
    Ok(json)
}

/// Parse an RFC 4716 SSH2 public key block:
///   ---- BEGIN SSH2 PUBLIC KEY ----
///   Comment: "user@host"
///   <base64 lines>
///   ---- END SSH2 PUBLIC KEY ----
fn parse_rfc4716(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("input is not an RFC 4716 public key block"))?;
    let mut comment = String::new();
    let mut b64 = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Comment:") {
            comment = rest.trim().trim_matches('"').to_string();
        } else if !t.is_empty() && !t.starts_with("----") {
            b64.push_str(t);
        }
    }
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|e| anyhow::anyhow!("invalid RFC 4716 base64 key blob: {e}"))?;

    let mut json = parse_ssh_blob(&blob)?;
    json["format"] = serde_json::Value::String("RFC 4716 (SSH2 PUBLIC KEY)".to_string());
    json["comment"] = serde_json::Value::String(comment);

    let digest = Sha256::digest(&blob);
    let fp = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, digest);
    json["fingerprint_sha256"] = serde_json::Value::String(format!("SHA256:{fp}"));
    json["blob_hex"] = serde_json::Value::String(hex::encode(&blob));

    Ok(serde_json::to_string_pretty(&json)?.into_bytes())
}

/// Parse a PKCS#8 SubjectPublicKeyInfo (PEM "PUBLIC KEY" or raw DER) into a
/// JSON summary. RSA and the supported NIST curves map to the same fields as
/// the OpenSSH form (bits + fields).
fn parse_pkcs8_spki(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_parser::asn1_rs::FromDer;

    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("input is not a PEM or DER public key"))?;
    let der = match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => {
            // Accept raw DER bytes or a hex string.
            let t = text.trim();
            if t.starts_with("-----") {
                anyhow::bail!("unsupported PEM label (expected PUBLIC KEY)");
            }
            let cleaned: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            if cleaned.len() >= 2 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(&cleaned).map_err(|e| anyhow::anyhow!("invalid hex DER: {e}"))?
            } else {
                input.to_vec()
            }
        }
    };

    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&der)
        .map_err(|e| anyhow::anyhow!("not a valid SPKI (PKCS#8) public key: {e}"))?;
    let oid = spki_algorithm_oid(&spki);

    let mut json = serde_json::json!({
        "format": "PKCS#8 (SubjectPublicKeyInfo)",
        "algorithm_oid": oid,
    });
    match oid.as_str() {
        OID_RSA => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts;
            let k = rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
                .map_err(|e| anyhow::anyhow!("invalid RSA public key: {e}"))?;
            let n = k.n().to_bytes_be();
            let e = k.e().to_bytes_be();
            json["algorithm"] = serde_json::Value::String("RSA".to_string());
            json["bits"] = serde_json::Value::from(mpint_bits(&n));
            json["fields"] = serde_json::json!({
                "exponent_hex": hex::encode(e),
                "modulus_hex": hex::encode(n),
            });
        }
        OID_EC_P256 => {
            json["algorithm"] = serde_json::Value::String("EC".to_string());
            json["bits"] = serde_json::Value::from(256);
            json["fields"] = serde_json::json!({
                "curve": "nistp256",
                "point_hex": hex::encode(spki.subject_public_key.data.as_ref()),
            });
        }
        OID_EC_P384 => {
            json["algorithm"] = serde_json::Value::String("EC".to_string());
            json["bits"] = serde_json::Value::from(384);
            json["fields"] = serde_json::json!({
                "curve": "nistp384",
                "point_hex": hex::encode(spki.subject_public_key.data.as_ref()),
            });
        }
        OID_EC_SECP256K1 => {
            json["algorithm"] = serde_json::Value::String("EC".to_string());
            json["bits"] = serde_json::Value::from(256);
            json["fields"] = serde_json::json!({
                "curve": "secp256k1",
                "point_hex": hex::encode(spki.subject_public_key.data.as_ref()),
            });
        }
        OID_EC_SM2 => {
            // SM2 (GB/T 32918): keep algorithm "SM2" so callers can tell the
            // domestic curve apart from the NIST family. Point validity is
            // checked by the same sm2.rs path used by dpa:sm2:verify.
            use sm2::dsa::VerifyingKey;
            VerifyingKey::from_sec1_bytes(
                SM2_DEFAULT_DISTID,
                spki.subject_public_key.data.as_ref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid SM2 public key: {e}"))?;
            json["algorithm"] = serde_json::Value::String("SM2".to_string());
            json["bits"] = serde_json::Value::from(256);
            json["fields"] = serde_json::json!({
                "curve": "sm2",
                "point_hex": hex::encode(spki.subject_public_key.data.as_ref()),
            });
        }
        other => anyhow::bail!(
            "unsupported SPKI algorithm OID '{other}' (only RSA / P-256 / P-384 / secp256k1 / SM2)"
        ),
    }
    json["subject_public_key_hex"] =
        serde_json::Value::String(hex::encode(spki.subject_public_key.data.as_ref()));

    Ok(serde_json::to_string_pretty(&json)?.into_bytes())
}

fn mpint_bits(b: &[u8]) -> usize {
    // Leading 0x00 sign octet (DER-style) is ignored for bit counting.
    let mut i = 0;
    if !b.is_empty() && b[0] == 0 {
        i = 1;
    }
    if i >= b.len() {
        return 0;
    }
    let bits = (b.len() - i) * 8;
    let lead = b[i];
    let mut sh = 0;
    while sh < 8 && ((lead << sh) & 0x80) == 0 {
        sh += 1;
    }
    bits - sh as usize
}

/// `dpa:asn1:parse` - recursive DER TLV walker that renders an ASN.1 tree as
/// JSON. Accepts raw DER bytes or a hex string.
fn asn1_parse(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let der: Vec<u8> = if looks_like_hex(input) {
        let text = std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("invalid hex input"))?;
        let cleaned: String = text
            .chars()
            .filter(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
            .collect();
        hex::decode(cleaned).map_err(|e| anyhow::anyhow!("invalid hex input: {e}"))?
    } else {
        input.to_vec()
    };
    let node = der_node(&der, 0, der.len()).map_err(|e| anyhow::anyhow!("invalid DER: {e}"))?;
    Ok(serde_json::to_string_pretty(&node.1)?.into_bytes())
}

fn looks_like_hex(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(input);
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
        .collect();
    !cleaned.is_empty()
        && cleaned.len() == text.chars().filter(|c| !c.is_ascii_whitespace()).count()
}

fn der_tag_name(tag: u8) -> &'static str {
    let low = tag & 0x1F;
    if low == 0x10 {
        return "SEQUENCE";
    }
    if low == 0x11 {
        return "SET";
    }
    if tag & 0xE0 == 0xA0 {
        return "ContextSpecific";
    }
    match low {
        0x01 => "BOOLEAN",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x0A => "ENUMERATED",
        0x0C => "UTF8String",
        0x13 => "PrintableString",
        0x14 => "TeletexString",
        0x16 => "IA5String",
        0x17 => "UTCTime",
        0x18 => "GeneralizedTime",
        0x1E => "BMPString",
        _ => "UNKNOWN",
    }
}

// Returns (bytes_consumed, JSON value) for the TLV rooted at `start`.
fn der_node(data: &[u8], start: usize, end: usize) -> anyhow::Result<(usize, serde_json::Value)> {
    if start + 2 > end {
        anyhow::bail!("truncated at offset {start}");
    }
    let tag = data[start];
    let mut p = start + 1;
    let len = der_len(data, p, end).map_err(|e| anyhow::anyhow!("{e} at offset {p}"))?;
    p += len.1;
    let content_start = p;
    let content_end = p + len.0;
    if content_end > end {
        anyhow::bail!("length {len:?} overruns input at offset {start}");
    }
    p = content_end;
    let constructed = tag & 0x20 != 0;
    let tag_num = tag & 0x1F;

    let mut node = serde_json::json!({
        "tag": der_tag_name(tag),
        "offset": start,
        "size": content_end - start,
        "constructed": constructed,
    });

    let value = if constructed {
        let mut children = Vec::new();
        let mut q = content_start;
        while q < content_end {
            let (used, child) = der_node(data, q, content_end)?;
            children.push(child);
            q += used;
        }
        serde_json::Value::Array(children)
    } else {
        let content = &data[content_start..content_end];
        match tag_num {
            0x01 => serde_json::json!({ "bool": content.first().copied() != Some(0) }),
            0x05 => serde_json::Value::Null,
            0x06 => {
                let oid = oid_string(content);
                serde_json::json!({ "oid": oid })
            }
            0x02 | 0x03 | 0x04 | 0x0A => {
                let mut extra = serde_json::Map::new();
                if tag_num == 0x03 && !content.is_empty() {
                    extra.insert("unused_bits".to_string(), serde_json::json!(content[0]));
                }
                let hex_body: &[u8] = if tag_num == 0x03 && !content.is_empty() {
                    &content[1..]
                } else {
                    content
                };
                extra.insert(
                    if tag_num == 0x02 || tag_num == 0x0A {
                        "int_hex"
                    } else {
                        "hex"
                    }
                    .to_string(),
                    serde_json::json!(hex::encode(hex_body)),
                );
                serde_json::Value::Object(extra)
            }
            0x0C | 0x13 | 0x14 | 0x16 | 0x17 | 0x18 | 0x1E => {
                let s = String::from_utf8_lossy(content);
                serde_json::json!({ "text": s })
            }
            _ => serde_json::json!({ "hex": hex::encode(content) }),
        }
    };
    node["value"] = value;
    Ok((p - start, node))
}

fn der_len(data: &[u8], p: usize, end: usize) -> anyhow::Result<(usize, usize)> {
    if p >= end {
        anyhow::bail!("truncated length");
    }
    let b = data[p];
    if b & 0x80 == 0 {
        return Ok((b as usize, 1));
    }
    let n = (b & 0x7F) as usize;
    if n == 0 {
        anyhow::bail!("indefinite length not allowed in DER");
    }
    if n > 8 || p + 1 + n > end {
        anyhow::bail!("bad long-form length");
    }
    let mut v: usize = 0;
    for i in 0..n {
        v = (v << 8) | data[p + 1 + i] as usize;
    }
    Ok((v, 1 + n))
}

fn oid_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "".to_string();
    }
    let mut out = Vec::new();
    let first = bytes[0];
    out.push(format!("{}", first / 40));
    out.push(format!("{}", first % 40));
    let mut v: u64 = 0;
    for &b in &bytes[1..] {
        v = (v << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            out.push(v.to_string());
            v = 0;
        }
    }
    out.join(".")
}

// ---------------------------------------------------------------------------
// SM2 (GB/T 32918) - merged from src/ops/sm2.rs (stage-1 refactor)
// ---------------------------------------------------------------------------

/// GM/T 0003 default distinguished identifier (16 bytes).
/// Shared across x509/SPKI parsing so SM2 points are validated with the same
/// default distid as `dpa:sm2:verify`.
pub(crate) const SM2_DEFAULT_DISTID: &str = "1234567812345678";

/// Parse a PEM envelope when present; otherwise treat the input as raw DER.
fn strip_pem(input: &[u8]) -> Vec<u8> {
    match pem::parse(input) {
        Ok(p) => p.contents().to_vec(),
        Err(_) => input.to_vec(),
    }
}

fn parse_spki<'a>(der: &'a [u8]) -> anyhow::Result<x509_parser::x509::SubjectPublicKeyInfo<'a>> {
    use x509_parser::asn1_rs::FromDer;
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der)
        .map_err(|e| anyhow::anyhow!("not a valid PEM or DER SPKI public key: {e}"))?;
    Ok(spki)
}

/// `dpa:sm2:parse` - parse an SM2 SPKI public key (PEM or DER) and emit a JSON
/// summary: the SM2 algorithm OID, the uncompressed public-key point (hex) and
/// whether the point is a valid SM2 curve point. Raw mode hex-dumps the DER.
fn sm2_parse(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let der = strip_pem(input);
    if let Some(v) = args.get("raw")
        && parse_bool(v)?
    {
        return Ok(hex::encode(&der).into_bytes());
    }

    let spki = parse_spki(&der)?;
    let oid = spki_algorithm_oid(&spki);
    if oid != OID_EC_SM2 {
        anyhow::bail!("not an SM2 public key (algorithm OID '{oid}', expected {OID_EC_SM2})");
    }
    let point = spki.subject_public_key.data.as_ref();
    let point_valid = sm2::dsa::VerifyingKey::from_sec1_bytes(SM2_DEFAULT_DISTID, point).is_ok();

    let json = serde_json::json!({
        "algorithm_oid": oid,
        "point_hex": hex::encode(point),
        "point_valid": point_valid,
        "key_type": "SM2",
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&json)?).into_bytes())
}

/// Parse an SM2 private key accepting PKCS#8 or SEC1, in PEM or raw DER form.
fn parse_sm2_secret(input: &[u8]) -> anyhow::Result<(&'static str, sm2::SecretKey)> {
    use sm2::pkcs8::DecodePrivateKey as _;
    if let Ok(text) = std::str::from_utf8(input) {
        if let Ok(sk) = sm2::SecretKey::from_pkcs8_pem(text) {
            return Ok(("pkcs8", sk));
        }
        if let Ok(sk) = sm2::SecretKey::from_sec1_pem(text) {
            return Ok(("sec1", sk));
        }
    }
    if let Ok(sk) = sm2::SecretKey::from_pkcs8_der(input) {
        return Ok(("pkcs8", sk));
    }
    if let Ok(sk) = sm2::SecretKey::from_sec1_der(input) {
        return Ok(("sec1", sk));
    }
    anyhow::bail!("not a valid SM2 private key (expected PKCS#8 or SEC1 PEM/DER)")
}

/// `dpa:sm2:pubkey:extract` - derive the SPKI public-key PEM from a PKCS#8 or
/// SEC1 SM2 private key.
fn sm2_pubkey_extract(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use sm2::pkcs8::EncodePublicKey as _;
    use sm2::pkcs8::spki::der::pem::LineEnding;
    let (_format, sk) = parse_sm2_secret(input)?;
    let pem = sk
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to encode SM2 public key: {e}"))?;
    Ok(pem.into_bytes())
}

/// `dpa:sm2:key:parse` - parse an SM2 private key (PKCS#8 / SEC1) and emit the
/// private scalar (hex), the public point and the algorithm OID as JSON.
fn sm2_key_parse(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use sm2::elliptic_curve::sec1::ToSec1Point as _;

    let (format, sk) = parse_sm2_secret(input)?;
    let priv_hex = hex::encode(sk.to_bytes());
    let point_hex = hex::encode(sk.public_key().to_sec1_point(false).as_bytes());

    let json = serde_json::json!({
        "format": format,
        "algorithm_oid": OID_EC_SM2,
        "private_key_hex": priv_hex,
        "public_key_point": point_hex,
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&json)?).into_bytes())
}

/// `dpa:sm2:verify` - verify an SM2-with-SM3 signature over the input message.
/// The public key is passed via the `key` argument as PEM or DER SPKI; the
/// signature defaults to DER (`sig_type=der`), raw 64-byte r||s is accepted
/// with `sig_type=raw`. The distinguished identifier defaults to the GM/T 0003
/// value; pass `distid` to verify signatures created with a custom ID.
/// Emits the UTF-8 text `true` / `false`.
fn sm2_verify(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = req_arg(args, "key")?;
    let digest = opt_arg(args, "digest", "sm3");
    if digest != "sm3" {
        anyhow::bail!("unknown digest '{digest}' (SM2-with-SM3 verification uses sm3 only)");
    }
    let distid = opt_arg(args, "distid", SM2_DEFAULT_DISTID);
    let sig_type = opt_arg(args, "sig_type", "der");
    let sig = decode_sig(
        req_arg(args, "signature")?,
        opt_arg(args, "sig_format", "hex"),
    )?;

    let der = strip_pem(key.as_bytes());
    let spki = parse_spki(&der)?;
    let oid = spki_algorithm_oid(&spki);
    if oid != OID_EC_SM2 {
        anyhow::bail!("unsupported SM2 public key OID '{oid}' (expected {OID_EC_SM2})");
    }
    let point = spki.subject_public_key.data.as_ref();

    use sm2::dsa::signature::Verifier as _;
    use sm2::dsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(distid, point)
        .map_err(|e| anyhow::anyhow!("invalid SM2 public key: {e}"))?;
    let signature = match sig_type {
        "der" => {
            Signature::from_der(&sig).map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?
        }
        "raw" => {
            if sig.len() != 64 {
                anyhow::bail!("raw SM2 signature must be exactly 64 bytes (r||s)");
            }
            let sig_bytes = sm2::dsa::SignatureBytes::try_from(sig.as_slice())
                .map_err(|_| anyhow::anyhow!("invalid raw signature length"))?;
            Signature::from_bytes(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("invalid raw signature: {e}"))?
        }
        other => anyhow::bail!("unknown sig_type '{other}' (expected der or raw)"),
    };

    let ok = vk.verify(input, &signature).is_ok();
    Ok(if ok {
        b"true\n".to_vec()
    } else {
        b"false\n".to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed RSA-2048 test certificate (CN=test.example.com, SAN
    // DNS:test.example.com + IP:127.0.0.1), generated once by openssl.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDejCCAmKgAwIBAgIUfLHGHjP+EWiARQux8nwa8COmLQkwDQYJKoZIhvcNAQEL\n\
BQAwOzELMAkGA1UEBhMCQ04xETAPBgNVBAoMCGRwYS10ZXN0MRkwFwYDVQQDDBB0\n\
ZXN0LmV4YW1wbGUuY29tMB4XDTI2MTAxMDE0MTMwMloXDTI3MTAxMDE0MTMwMlow\n\
OzELMAkGA1UEBhMCQ04xETAPBgNVBAoMCGRwYS10ZXN0MRkwFwYDVQQDDBB0ZXN0\n\
LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx29D\n\
l6tq4gWpcO69WLSaJBbVPekd9fLrPTKPMXTv96F15nXlDgQcP+9LLu4JAlxjnuGl\n\
iVH5dXT7b9NZUGAvCs7XFEquFfWDfgAXTTA7BSiQAXgq2oN5Ud7d14+7gotHUlL9\n\
k4NJ6UkNGIp0j5mFenS2wH8pV+EpfqewUzR5HmIi7dNeYqoyxY0DW9DwRRkd49vf\n\
FWLTQgOukStdlfd8/pFex80SF5zW5SWOr/Qa3OSR0u1XAz8qp2BoaOqx7BVmpaMJ\n\
EiiQZC3eRkslDAJGAokH4klEKmuYnOWS5fZmAMT8GqskRLhatz3+o1D7rlDxnbT0\n\
wvr+2/S8lQ5/TPXJiQIDAQABo3YwdDAdBgNVHQ4EFgQU9wItCeF7PhYiRBbXJfjn\n\
hCks/u4wHwYDVR0jBBgwFoAU9wItCeF7PhYiRBbXJfjnhCks/u4wDwYDVR0TAQH/\n\
BAUwAwEB/zAhBgNVHREEGjAYghB0ZXN0LmV4YW1wbGUuY29thwR/AAABMA0GCSqG\n\
SIb3DQEBCwUAA4IBAQC13la1dyB5Cg8CVkDvkjXNdqZIEYNVs4lDtavFwJjwQ5KN\n\
GgSY5QY4spPJrnsB71zhTVrRXzBhXr4Rabm9xVuRvrBxtky0tGyXmutlz7H3xgBn\n\
iPizDbrHNeRFhm3R4cSqbWoKz8zVXmSFWRZ78JXdjYm4p7C5tvWXSFvtoGwXatxx\n\
KMTt+ldthOANfTNX9anzG/02qMmO3GCzrlFKuVyhfzSfw/by+t3Z2mwoJaS85Q7f\n\
u2NI9PD57//Bg4eZDJTbYQGllcXlwXxuVpO7b7OaZ8DmLbaACFfKOIR8gCrgK+FE\n\
sVvr8iW2eC+/vNtGw1jC1CI7mehGJbMw6YblVRXF\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn pem_encode_decode_roundtrip() {
        let der = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let mut enc_args = HashMap::new();
        enc_args.insert("action".to_string(), "encode".to_string());
        let enc = pem_conv(&der, &enc_args).unwrap();
        let text = String::from_utf8(enc).unwrap();
        assert!(
            text.starts_with("-----BEGIN PUBLIC KEY-----"),
            "got: {text}"
        );
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"), "got: {text}");

        let mut args = HashMap::new();
        args.insert("action".to_string(), "decode".to_string());
        let dec = pem_conv(text.as_bytes(), &args).unwrap();
        assert_eq!(dec, der);
    }

    #[test]
    fn pem_encode_custom_label() {
        let mut args = HashMap::new();
        args.insert("action".to_string(), "encode".to_string());
        args.insert("label".to_string(), "RSA PUBLIC KEY".to_string());
        let out = pem_conv(&[0xAA], &args).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("RSA PUBLIC KEY"));
    }

    #[test]
    fn pem_decode_invalid_is_error() {
        let mut args = HashMap::new();
        args.insert("action".to_string(), "decode".to_string());
        assert!(pem_conv(b"not a pem", &args).is_err());
    }

    #[test]
    fn x509_parses_pem_certificate() {
        let out = x509_parse(TEST_CERT_PEM.as_bytes(), &HashMap::new()).unwrap();
        let text = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["subject"], "C=CN, O=dpa-test, CN=test.example.com");
        assert_eq!(v["issuer"], "C=CN, O=dpa-test, CN=test.example.com");
        assert_eq!(v["version"], "V3");
        let san = v["subject_alt_name"].as_array().unwrap();
        assert!(
            san.iter()
                .any(|x| x.as_str().unwrap().contains("DNS:test.example.com")),
            "SAN missing DNS entry: {san:?}"
        );
        assert!(!v["signature_algorithm"]["oid"].as_str().unwrap().is_empty());
        assert!(v["validity"]["not_before"].as_str().unwrap().len() >= 25);
    }

    #[test]
    fn x509_parses_der_certificate() {
        // decode the embedded PEM with the pem op, then re-parse as DER
        let der = pem_conv(TEST_CERT_PEM.as_bytes(), &HashMap::new()).unwrap();
        let out = x509_parse(&der, &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["subject"], "C=CN, O=dpa-test, CN=test.example.com");
    }

    #[test]
    fn x509_invalid_input_is_error() {
        assert!(x509_parse(b"garbage", &HashMap::new()).is_err());
    }

    #[test]
    fn x509_raw_mode_emits_der_hex() {
        // Raw=true on PEM input returns the stripped DER as hex, identical to
        // the DER decoded by the pem op (and the hex of a DER re-parse).
        let mut args = HashMap::new();
        args.insert("raw".to_string(), "true".to_string());
        let out = x509_parse(TEST_CERT_PEM.as_bytes(), &args).unwrap();
        let hex_text = String::from_utf8(out).unwrap();
        let der_from_hex = hex::decode(&hex_text).unwrap();
        let der_from_pem = pem_conv(TEST_CERT_PEM.as_bytes(), &HashMap::new()).unwrap();
        assert_eq!(der_from_hex, der_from_pem);

        // hex length matches a DER certificate length (leaf entry 03 82 02 8d ...).
        assert!(
            hex_text.len() > 500,
            "raw hex too short: {}",
            hex_text.len()
        );

        // Raw=false (default) still emits the JSON summary.
        let out2 = x509_parse(TEST_CERT_PEM.as_bytes(), &HashMap::new()).unwrap();
        assert!(
            String::from_utf8(out2)
                .unwrap()
                .trim_start()
                .starts_with('{')
        );
    }

    #[test]
    fn x509_parses_sm2_certificate() {
        // SM2 self-signed certificate (openssl 3.5, SM2-with-SM3 signature,
        // SPKI carries id-ecPublicKey + SM2 curve OID 1.2.156.10197.1.301).
        let pem = std::fs::read("tests/data/sm2-cert.pem").unwrap();
        let out = x509_parse(&pem, &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["version"], "V3");
        assert_eq!(
            v["signature_algorithm"]["oid"].as_str().unwrap(),
            "1.2.156.10197.1.501",
            "expected SM2-with-SM3 signature OID"
        );
        let spk = &v["subject_public_key"];
        assert_eq!(spk["algorithm_oid"], "1.2.840.10045.2.1", "id-ecPublicKey");
        assert_eq!(spk["curve_oid"], OID_EC_SM2);
        assert_eq!(spk["curve"], "sm2");
        assert_eq!(spk["bits"], 256);
        assert_eq!(
            spk["point_valid"], true,
            "SM2 point must validate via sm2.rs"
        );
        assert!(!spk["der_hex"].as_str().unwrap().is_empty());

        // DER input takes the same path.
        let der = std::fs::read("tests/data/sm2-cert.der").unwrap();
        let out = x509_parse(&der, &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["subject_public_key"]["curve"], "sm2");
        assert_eq!(v["subject_public_key"]["point_valid"], true);
    }

    // ------------------------------------------------------------------
    // PKCS#1 <-> PKCS#8 bridge (fixtures generated with openssl 3.5)
    // ------------------------------------------------------------------

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("tests/data/{name}")).expect("test fixture missing")
    }

    #[test]
    fn pkcs1_to_pkcs8_converts_private_key() {
        let pem = fixture("rsa-pkcs1.pem");
        let out = pkcs1_to_pkcs8(pem.as_bytes(), &HashMap::new()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("-----BEGIN PRIVATE KEY-----"),
            "got: {text}"
        );
        let expected = fixture("rsa-pkcs8.pem").replace("\r\n", "\n");
        assert_eq!(text.trim_end(), expected.trim_end());
    }

    #[test]
    fn pkcs8_to_pkcs1_converts_private_key() {
        let pem = fixture("rsa-pkcs8.pem");
        let out = pkcs8_to_pkcs1(pem.as_bytes(), &HashMap::new()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
            "got: {text}"
        );
        let expected = fixture("rsa-pkcs1.pem").replace("\r\n", "\n");
        assert_eq!(text.trim_end(), expected.trim_end());
    }

    #[test]
    fn pkcs_pem_roundtrips() {
        let pkcs1 = fixture("rsa-pkcs1.pem");
        let pkcs8 = pkcs1_to_pkcs8(pkcs1.as_bytes(), &HashMap::new()).unwrap();
        let back = pkcs8_to_pkcs1(&pkcs8, &HashMap::new()).unwrap();
        let round = String::from_utf8(back).unwrap().replace("\r\n", "\n");
        assert_eq!(round.trim_end(), pkcs1.replace("\r\n", "\n").trim_end());
    }

    // ------------------------------------------------------------------
    // PEM <-> JWK bridge
    // ------------------------------------------------------------------

    #[test]
    fn pem_to_jwk_rsa() {
        let pem = fixture("rsa-pub.pem");
        let out = pem_to_jwk(pem.as_bytes(), &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kty"], "RSA");
        assert!(!v["n"].as_str().unwrap().is_empty());
        assert!(!v["e"].as_str().unwrap().is_empty());
    }

    #[test]
    fn pem_to_jwk_ec_p256() {
        let pem = fixture("ec-pub.pem");
        let out = pem_to_jwk(pem.as_bytes(), &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-256");
        assert!(!v["x"].as_str().unwrap().is_empty());
        assert!(!v["y"].as_str().unwrap().is_empty());
    }

    #[test]
    fn pem_to_jwk_sm2() {
        // SM2 public key (GM/T 0003 test vector) must convert to a JWK with
        // crv=SM2; coordinates are the same 32-byte x/y as dpa:sm2:parse.
        let pem = fixture("sm2-pub.pem");
        let out = pem_to_jwk(pem.as_bytes(), &HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "SM2");
        let x = v["x"].as_str().unwrap();
        let y = v["y"].as_str().unwrap();
        assert_eq!(x.len(), 43, "x must be 32 bytes unpadded b64url: {x}");
        assert_eq!(y.len(), 43, "y must be 32 bytes unpadded b64url: {y}");
        assert!(
            !x.contains('=') && !y.contains('='),
            "b64url must be unpadded"
        );
        assert_ne!(x, y);
        assert_eq!(v["x"], "CNd64EwBzEwRBDYN2K9rb33zNCg9fBpq_VZSQHuHvuU");
        assert_eq!(v["y"], "AU4qV8NsFQ0WMk3GZOMeZDI1lgnE55hHpbFhyMc2TIo");
    }

    #[test]
    fn pkcs8_spki_parses_sm2() {
        let pem = fixture("sm2-pub.pem");
        // parse_pkcs8_spki accepts PEM text, DER bytes-as-hex or raw hex DER;
        // pass the hex form of the DER bytes (binary DER is not valid UTF-8).
        let der = pem_conv(pem.as_bytes(), &HashMap::new()).unwrap();
        let hex_der = hex::encode(&der);
        let out = parse_pkcs8_spki(hex_der.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["format"], "PKCS#8 (SubjectPublicKeyInfo)");
        assert_eq!(v["algorithm_oid"], OID_EC_SM2);
        assert_eq!(v["algorithm"], "SM2");
        assert_eq!(v["bits"], 256);
        assert_eq!(v["fields"]["curve"], "sm2");
        assert_eq!(
            v["fields"]["point_hex"],
            "0408d77ae04c01cc4c1104360dd8af6b6f7df334283d7c1a6afd5652407b87bee5\
014e2a57c36c150d16324dc664e31e6432359609c4e79847a5b161c8c7364c8a"
        );
    }

    #[test]
    fn jwk_to_pem_rsa_roundtrip() {
        let pem = fixture("rsa-pub.pem");
        let jwk = pem_to_jwk(pem.as_bytes(), &HashMap::new()).unwrap();
        let out = jwk_to_pem(&jwk, &HashMap::new()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----"));
        let der_a = pem_conv(pem.as_bytes(), &HashMap::new()).unwrap();
        let der_b = pem_conv(text.as_bytes(), &HashMap::new()).unwrap();
        assert_eq!(der_a, der_b);
    }

    #[test]
    fn jwk_to_pem_ec_roundtrip() {
        let pem = fixture("ec-pub.pem");
        let jwk = pem_to_jwk(pem.as_bytes(), &HashMap::new()).unwrap();
        let out = jwk_to_pem(&jwk, &HashMap::new()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----"));
        let der_a = pem_conv(pem.as_bytes(), &HashMap::new()).unwrap();
        let der_b = pem_conv(text.as_bytes(), &HashMap::new()).unwrap();
        assert_eq!(der_a, der_b);
    }

    // ------------------------------------------------------------------
    // Verify-only signature checks (openssl-signed fixtures)
    // ------------------------------------------------------------------

    #[test]
    fn rsa_verify_accepts_valid_signature() {
        let msg = std::fs::read("tests/data/msg.txt").unwrap();
        let key = fixture("rsa-pub.pem");
        let sig = fixture("rsa-sig.hex");
        let mut args = HashMap::new();
        args.insert("key".to_string(), key);
        args.insert("signature".to_string(), sig);
        let out = rsa_verify(&msg, &args).unwrap();
        assert_eq!(out, b"true\n");
    }

    #[test]
    fn rsa_verify_rejects_tampered_signature() {
        let msg = std::fs::read("tests/data/msg.txt").unwrap();
        let key = fixture("rsa-pub.pem");
        let sig = fixture("rsa-sig.hex");
        // Flip the first hex nibble (0x3 -> 0x4): guaranteed different bytes.
        let tampered = format!("4{}", &sig[1..]);
        assert_ne!(tampered, sig);
        let mut args = HashMap::new();
        args.insert("key".to_string(), key);
        args.insert("signature".to_string(), tampered);
        let out = rsa_verify(&msg, &args).unwrap();
        assert_eq!(out, b"false\n");
    }

    #[test]
    fn ecdsa_verify_accepts_valid_signature() {
        let msg = std::fs::read("tests/data/msg.txt").unwrap();
        let key = fixture("ec-pub.pem");
        let sig = fixture("ec-sig.hex");
        let mut args = HashMap::new();
        args.insert("key".to_string(), key);
        args.insert("signature".to_string(), sig);
        let out = ecdsa_verify(&msg, &args).unwrap();
        assert_eq!(out, b"true\n");
    }

    #[test]
    fn ecdsa_verify_rejects_tampered_signature() {
        let msg = std::fs::read("tests/data/msg.txt").unwrap();
        let key = fixture("ec-pub.pem");
        let sig = fixture("ec-sig.hex");
        // Flip the last byte of the DER (low limb of s): DER stays well-formed
        // but the signature no longer verifies.
        let mut raw = hex::decode(sig.trim()).unwrap();
        let last = raw.last_mut().unwrap();
        *last ^= 0x01;
        let mut args = HashMap::new();
        args.insert("key".to_string(), key);
        args.insert("signature".to_string(), hex::encode(&raw));
        let out = ecdsa_verify(&msg, &args).unwrap();
        assert_eq!(out, b"false\n");
    }

    // --- CSR / pubkey extract / PEM<->hex / SSH / ASN.1 --------------------------

    const TEST_CSR_PEM: &str = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIICfzCCAWcCAQAwOjEYMBYGA1UEAwwPY3NyLmV4YW1wbGUuY29tMREwDwYDVQQK\n\
DAhkcGEtdGVzdDELMAkGA1UEBhMCQ04wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n\
ggEKAoIBAQCqMtPk5nk1CB83WZO9oZOkMBPTRlDDdgXqnuYoW8vVU1Xz618t1uO6\n\
qOliRYJU/jQHCv28HLxOsYpjzdnW6V7vEcWp4dNBJ2/NDaX3jvjIgYbsErhTebzu\n\
vTjQVA/5u50dHzHGXfgG0pRcin1CN/Z+/m9UjLnisu1jfL0f6McRnoWGWr7Znkby\n\
m0XUYQu5cXMiSmm6i6JsyAtUUOMwgO5K9zEAi2FBNX7/tTFJiXwoblIm1SaLBOkO\n\
qeNWqKYM0Afqe8sFA3oOvCmPQQ6Tm22nxOrUBbqRc8BsPh7C9T/tQ52JISDv9JYs\n\
0IlGXem7EDxzZg4Q6DoRPMIaYXXZdRmHAgMBAAGgADANBgkqhkiG9w0BAQsFAAOC\n\
AQEAkYpU6qMMZukAV1hTY15NJnfHAKdseClXZkjYZZjXJM8Znd0SnICiH8ZDccBy\n\
2WylIOuy+f79hYmmFTscFeJZ1QDSP+s5ciHgOJNOCUROZGfGov//D4Stzy5eXjQ4\n\
PbReZB8TtnjhkTIeHkliRR/HwbtK55dpkfx8jxsTXJ4vQiuCpqTcgi0z9+bX/Hne\n\
LeB9FrBs91w6EIqh1WArGoHQ2pY89gMuUjhvpEGW98sg9xp0+4NL5mFxlKab+J2d\n\
9ZfU3AobbaB08wHcvQYncIJLE+uTMuRcetuv3t/WoLUEHrQY7oVwF5709QBO5Qsm\n\
zx2rOs5uS1sa29sZLso1njAFww==\n\
-----END CERTIFICATE REQUEST-----\n";

    const SSH_ED25519_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfjh1VBJLIDPH8XlLwJ2vz3YKuw6Xy5Hj62qowS3R1i dpa-test@example.com";
    const SSH_RSA_LINE: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZzWQYkcMX8P4Zr0GubhFhq3AqU19GGrS9BureZ8vs57Kv5xljXz/Eo/ez5i0xFkGgzcbDX1qVcEfu39cu9z9Xan28KpJol7Lk8d8JD2lRTzjpZaoh6lY/3tv2ZF0sT/G3CyqvQxqq1V1WmiRyi+IBr4Q1Jg3SqdRcbYa8pdiWEw+Qn23EclrLiVh8mC23nFdv9zyLiEh1Hf5ESh5pZV+oacKpTk7X7M83Fc+egoqTkk+NgsOlroZ1u+t5TaHZ8pqinl+y79+FO+pcOnt7t78YPC6baQd9mBbmiX+CnlPRlkZ0Mxst+QpelVB1m0IhPCG2XInsWzuk6wNmMEahmhWd rsa@example.com";

    #[test]
    fn csr_parse_emits_subject_json() {
        let out = csr_parse(TEST_CSR_PEM.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("csr.example.com"), "{s}");
        assert!(s.contains("subject_public_key"), "{s}");
        assert!(s.contains("signature_algorithm"), "{s}");
        assert!(
            s.contains("rsaEncryption") || s.contains("1.2.840.113549.1.1.1"),
            "{s}"
        );
    }

    #[test]
    fn pubkey_extract_from_cert_emits_spki() {
        let out = pubkey_extract(TEST_CERT_PEM.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("-----BEGIN PUBLIC KEY-----"), "{s}");
        assert!(s.contains("-----END PUBLIC KEY-----"), "{s}");
    }

    #[test]
    fn ssh_parse_ed25519_fingerprint() {
        let out = ssh_parse(SSH_ED25519_LINE.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("ssh-ed25519"), "{s}");
        assert!(s.contains("fingerprint_sha256"), "{s}");
        assert!(s.contains("256"), "{s}");
    }

    #[test]
    fn ssh_parse_rsa_bits() {
        let out = ssh_parse(SSH_RSA_LINE.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("ssh-rsa"), "{s}");
        assert!(
            s.contains("\"bits\": 2048") || s.contains("\"bits\":2048"),
            "{s}"
        );
    }

    #[test]
    fn ssh_parse_rfc4716_block() {
        let block = "---- BEGIN SSH2 PUBLIC KEY ----\n\
Comment: \"dpa-test@example.com\"\n\
AAAAC3NzaC1lZDI1NTE5AAAAICfjh1VBJLIDPH8XlLwJ2vz3YKuw6Xy5Hj62qowS3R1i\n\
---- END SSH2 PUBLIC KEY ----\n";
        let out = ssh_parse(block.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("RFC 4716"), "{s}");
        assert!(s.contains("ssh-ed25519"), "{s}");
        assert!(s.contains("dpa-test@example.com"), "{s}");
        assert!(s.contains("fingerprint_sha256"), "{s}");
    }

    #[test]
    fn ssh_parse_pkcs8_spki() {
        let pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl/bL9L+RFfhT40pEWzNr\n\
aEQ0bfWmlcxNIuFJcXeQhReCmzgA/NGDz/oDfgJVjeBBK9pSPOlwrfjt2K8TkZc8\n\
4Xvh8HlBwMMUBL+PMR6yNbqfeNdDytmzHp6kFSu+x2ThJehzlS1sHKR45+TlYJ91\n\
cXIamcF+SmVX1smOz2oZCR3wur8EHDMtT1OgUzkDqWZKUD0cE3Ntzx+WtmhJJdJ2\n\
n2gGpET2PTRcUPdf8Vd2s6Z+/1o2KEPonNOZHF68fPlMnrxbGg4aY7KkCNZCri/x\n\
gRrxP9FUohxsAOH0r+iqoYAoWTBI6CBkrAfT69f+z5EucQxZKVJJCu5F1fXhry9e\n\
VwIDAQAB\n\
-----END PUBLIC KEY-----\n";
        let out = ssh_parse(pem.as_bytes(), &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("PKCS#8"), "{s}");
        assert!(s.contains("RSA"), "{s}");
        assert!(
            s.contains("\"bits\": 2048") || s.contains("\"bits\":2048"),
            "{s}"
        );
        assert!(s.contains("modulus_hex"), "{s}");
    }

    #[test]
    fn asn1_parse_walks_simple_der() {
        // SEQUENCE { INTEGER 5, NULL }
        let der = [0x30, 0x05, 0x02, 0x01, 0x05, 0x05, 0x00];
        let out = asn1_parse(&der, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("SEQUENCE"), "{s}");
        assert!(s.contains("INTEGER"), "{s}");
        assert!(s.contains("NULL"), "{s}");
        assert!(s.contains("int_hex"), "{s}");
    }

    // Deterministic fuzz sweep over the public-key / ASN.1 parsers.
    // Arbitrary bytes (random, truncated PEM, header-like prefixes) must never
    // panic; Err results are fine. A fixed LCG keeps the sweep reproducible
    // without pulling proptest into the dependency tree.
    fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn fuzz_pem_x509_pkcs_asn1_never_panic() {
        let mut args = std::collections::HashMap::new();
        args.insert("action".to_string(), "encode".to_string());
        for seed in [0u64, 1, 42, 0xDEAD, 0xFFFF_FFFF, u64::MAX] {
            let bytes = lcg_bytes(seed, 4096);
            let _ = pem_conv(&bytes, &args);
            let _ = pem_conv(&bytes, &HashMap::new());
            let _ = x509_parse(&bytes, &HashMap::new());
            let _ = pkcs1_to_pkcs8(&bytes, &HashMap::new());
            let _ = pkcs8_to_pkcs1(&bytes, &HashMap::new());
            let _ = asn1_parse(&bytes, &HashMap::new());
            let _ = ssh_parse(&bytes, &HashMap::new());
        }
        for prefix in [
            "-----BEGIN",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "MIIB",
            "3082",
            "ssh-rsa AAAA",
            "\x00\x00\x00\x07ssh-rsa",
        ] {
            let bytes = prefix.as_bytes();
            let _ = pem_conv(bytes, &HashMap::new());
            let _ = x509_parse(bytes, &HashMap::new());
            let _ = pkcs1_to_pkcs8(bytes, &HashMap::new());
            let _ = pkcs8_to_pkcs1(bytes, &HashMap::new());
            let _ = asn1_parse(bytes, &HashMap::new());
            let _ = ssh_parse(bytes, &HashMap::new());
        }
    }

    // ---- SM2 tests (migrated from src/ops/sm2.rs) ----

    const MSG: &[u8] = b"testing";
    const DISTID: &str = "example@rustcrypto.org";
    const PRIV_D: &str = "4BB8DF505722299592CBED4283B354A13FF5D3FEEB3A0660C5BDF3C87C559499";
    const PUB_POINT: &str = "0408D77AE04C01CC4C1104360DD8AF6B6F7DF334283D7C1A6AFD5652407B87BEE5014E2A57C36C150D16324DC664E31E6432359609C4E79847A5B161C8C7364C8A";

    fn sm2_fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/data/{name}"))
            .unwrap_or_else(|e| panic!("missing fixture {name}: {e}"))
    }

    fn sm2_fixture_text(name: &str) -> String {
        String::from_utf8(sm2_fixture(name)).unwrap()
    }

    fn pub_pem() -> String {
        sm2_fixture_text("sm2-pub.pem")
    }

    fn pub_pem_from_der() -> String {
        pem::Pem::new("PUBLIC KEY", sm2_fixture("sm2-pub.der")).to_string()
    }

    fn run_op(name: &str, input: &[u8], pairs: &[(&str, &str)]) -> anyhow::Result<Vec<u8>> {
        let mut map: HashMap<String, String> = HashMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        for op in ops() {
            if op.name == name {
                return (op.run)(input, &map);
            }
        }
        anyhow::bail!("op not found: {name}")
    }

    fn parse_json(out: &[u8]) -> serde_json::Value {
        let text = String::from_utf8(out.to_vec()).unwrap();
        let text = text.trim_end_matches('\n');
        serde_json::from_str(text).unwrap_or_else(|e| panic!("invalid JSON output {text:?}: {e}"))
    }

    #[test]
    fn sm2_parse_pem() {
        let out = run_op("dpa:sm2:parse", &sm2_fixture("sm2-pub.pem"), &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["algorithm_oid"], OID_EC_SM2);
        assert_eq!(
            json["point_hex"].as_str().unwrap().to_uppercase(),
            PUB_POINT
        );
        assert_eq!(json["point_valid"], true);
        assert_eq!(json["key_type"], "SM2");
    }

    #[test]
    fn sm2_parse_der() {
        let out = run_op("dpa:sm2:parse", &sm2_fixture("sm2-pub.der"), &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["algorithm_oid"], OID_EC_SM2);
        assert_eq!(json["point_valid"], true);
    }

    #[test]
    fn sm2_parse_raw_mode() {
        let out = run_op(
            "dpa:sm2:parse",
            &sm2_fixture("sm2-pub.der"),
            &[("raw", "true")],
        )
        .unwrap();
        let expected = hex::encode(sm2_fixture("sm2-pub.der"));
        assert_eq!(String::from_utf8(out).unwrap().trim(), expected);
    }

    #[test]
    fn sm2_parse_rejects_non_sm2_key() {
        // An RSA SPKI must be rejected by the SM2 parser.
        let rsa_der = std::fs::read("tests/data/rsa-pub.pem").unwrap();
        let err = run_op("dpa:sm2:parse", &rsa_der, &[]).unwrap_err();
        assert!(err.to_string().contains("not an SM2 public key"));
    }

    #[test]
    fn sm2_parse_flags_invalid_point() {
        let der = sm2_fixture("sm2-pub.der");
        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        let out = run_op("dpa:sm2:parse", &bad, &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["point_valid"], false);
    }

    #[test]
    fn sm2_key_parse_pkcs8_pem() {
        let out = run_op("dpa:sm2:key:parse", &sm2_fixture("sm2-priv-pkcs8.pem"), &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["format"], "pkcs8");
        assert_eq!(json["algorithm_oid"], OID_EC_SM2);
        assert_eq!(
            json["private_key_hex"].as_str().unwrap().to_uppercase(),
            PRIV_D
        );
        assert_eq!(
            json["public_key_point"].as_str().unwrap().to_uppercase(),
            PUB_POINT
        );
    }

    #[test]
    fn sm2_key_parse_pkcs8_der() {
        let out = run_op("dpa:sm2:key:parse", &sm2_fixture("sm2-priv-pkcs8.der"), &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["format"], "pkcs8");
        assert_eq!(
            json["private_key_hex"].as_str().unwrap().to_uppercase(),
            PRIV_D
        );
        assert_eq!(
            json["public_key_point"].as_str().unwrap().to_uppercase(),
            PUB_POINT
        );
    }

    #[test]
    fn sm2_key_parse_sec1_der() {
        let out = run_op("dpa:sm2:key:parse", &sm2_fixture("sm2-priv-sec1.der"), &[]).unwrap();
        let json = parse_json(&out);
        assert_eq!(json["format"], "sec1");
        assert_eq!(json["algorithm_oid"], OID_EC_SM2);
        assert_eq!(
            json["private_key_hex"].as_str().unwrap().to_uppercase(),
            PRIV_D
        );
        assert_eq!(
            json["public_key_point"].as_str().unwrap().to_uppercase(),
            PUB_POINT
        );
    }

    #[test]
    fn sm2_key_parse_rejects_garbage() {
        let err = run_op("dpa:sm2:key:parse", b"not a key", &[]).unwrap_err();
        assert!(err.to_string().contains("not a valid SM2 private key"));
    }

    #[test]
    fn sm2_pubkey_extract_matches_spki() {
        let out = run_op(
            "dpa:sm2:pubkey:extract",
            &sm2_fixture("sm2-priv-pkcs8.pem"),
            &[],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(text.contains("-----END PUBLIC KEY-----"));
        let parsed = run_op("dpa:sm2:parse", text.as_bytes(), &[]).unwrap();
        let json = parse_json(&parsed);
        assert_eq!(
            json["point_hex"].as_str().unwrap().to_uppercase(),
            PUB_POINT
        );
    }

    #[test]
    fn sm2_pubkey_extract_sec1_der() {
        let out = run_op(
            "dpa:sm2:pubkey:extract",
            &sm2_fixture("sm2-priv-sec1.der"),
            &[],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn sm2_verify_official_vector_raw() {
        let out = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
                ("sig_type", "raw"),
                ("distid", DISTID),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "true\n");
    }

    #[test]
    fn sm2_verify_official_vector_der() {
        let out = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", &sm2_fixture_text("sm2-sig-der.txt")),
                ("sig_type", "der"),
                ("distid", DISTID),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "true\n");
    }

    #[test]
    fn sm2_verify_official_vector_der_key_from_der() {
        let out = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem_from_der()),
                ("signature", &sm2_fixture_text("sm2-sig-der.txt")),
                ("sig_type", "der"),
                ("distid", DISTID),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "true\n");
    }

    #[test]
    fn sm2_verify_rejects_tampered_message() {
        let out = run_op(
            "dpa:sm2:verify",
            b"testing!",
            &[
                ("key", &pub_pem()),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
                ("sig_type", "raw"),
                ("distid", DISTID),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "false\n");
    }

    #[test]
    fn sm2_verify_rejects_tampered_signature() {
        let mut sig = hex::decode(sm2_fixture_text("sm2-sig-raw.txt")).unwrap();
        sig[0] ^= 0x01;
        let out = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", &hex::encode(&sig)),
                ("sig_type", "raw"),
                ("distid", DISTID),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "false\n");
    }

    #[test]
    fn sm2_verify_default_distid_sm3_digest() {
        // Default distid and digest=sm3 are accepted; result stays false for a
        // signature created with the custom distid.
        let out = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
                ("sig_type", "raw"),
                ("digest", "sm3"),
            ],
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "false\n");
    }

    #[test]
    fn sm2_verify_rejects_unsupported_digest() {
        let err = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("digest", "sha256"),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("sm3"));
    }

    #[test]
    fn sm2_verify_rejects_short_raw_signature() {
        let err = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", "deadbeef"),
                ("sig_type", "raw"),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("64 bytes"));
    }

    #[test]
    fn sm2_verify_rejects_wrong_curve_key() {
        // A P-256 SPKI must be rejected as an SM2 key.
        let err = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &sm2_fixture_text("ec-pub.pem")),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("SM2 public key OID"));
    }

    #[test]
    fn sm2_verify_rejects_bad_key_material() {
        let err = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &sm2_fixture_text("rsa-pub.pem")),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("SM2 public key OID"));
    }

    #[test]
    fn sm2_verify_rejects_unknown_sig_type() {
        let err = run_op(
            "dpa:sm2:verify",
            MSG,
            &[
                ("key", &pub_pem()),
                ("signature", &sm2_fixture_text("sm2-sig-raw.txt")),
                ("sig_type", "pkcs1"),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("sig_type"));
    }
}
