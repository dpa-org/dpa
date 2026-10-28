//! Crypto ops: XOR / AES / ChaCha20 / RC4 / HMAC.
//!
//! AES follows the "direction split, mode parameterized" convention (aligned
//! with CyberChef): one encrypt op and one decrypt op; the block-cipher mode
//! (ecb/cbc/cfb/ofb/ctr) is an optional parameter (default cbc), and the key
//! length (16/24/32 bytes) selects AES-128/192/256. Block modes (ecb/cbc) use
//! PKCS#7 padding; stream modes (cfb/ofb/ctr) need no padding.

use std::collections::HashMap;

use super::Op;
use crate::i18n;
pub(crate) mod aes;
pub(crate) mod chacha;
pub(crate) mod classic;
pub(crate) mod hmac_kdf;
pub(crate) mod xor;

pub fn ops() -> Vec<Op> {
    let mut v = vec![];
    v.extend(aes::ops());
    v.extend(classic::ops());
    v.extend(hmac_kdf::ops());
    v.extend(chacha::ops());
    v.extend(xor::ops());
    v
}

// ---------------------------------------------------------------------------
// Streaming implementation
// ---------------------------------------------------------------------------

/// Parse a key/IV: `0x` prefix means hex, otherwise UTF-8 bytes.
pub fn parse_key(key: &str) -> anyhow::Result<Vec<u8>> {
    let t = key.trim();
    if let Some(hex_part) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        let cleaned: String = hex_part.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(&cleaned).map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.key_not_hex", &[e.to_string().as_str()]))
        })
    } else {
        Ok(key.as_bytes().to_vec())
    }
}

/// Read the required `key` argument, parse it, and reject empty keys.
pub(crate) fn require_key(args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key_str = args
        .get("key")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_key")))?;
    let key = parse_key(key_str)?;
    if key.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_key"));
    }
    Ok(key)
}

/// Read an optional argument with a default value.
pub(crate) fn opt_arg<'a>(
    args: &'a HashMap<String, String>,
    name: &str,
    default: &'a str,
) -> &'a str {
    args.get(name).map(String::as_str).unwrap_or(default)
}

/// One-shot warning for an implicit all-zero IV.
///
/// Non-GCM block-cipher encryption (CBC/CFB/OFB/CTR) defaults to the all-zero
/// IV when no explicit `iv` argument is given. That default is kept for
/// backward compatibility (legacy CyberChef-style ciphertexts), but streaming
/// modes with a fixed zero IV/nonce can reuse the keystream across messages
/// under the same key, so the CLI announces it once per op. ECB has no IV and
/// GCM already randomizes by default; decryption is excluded because the
/// all-zero default is how legacy ciphertexts are read back.
pub(crate) fn implicit_zero_iv_warning(
    args: &HashMap<String, String>,
    mode: &str,
    encrypt: bool,
) -> Option<String> {
    if !encrypt {
        return None;
    }
    if mode.eq_ignore_ascii_case("gcm") || mode.eq_ignore_ascii_case("ecb") {
        return None;
    }
    if args.contains_key("iv") {
        return None;
    }
    Some(i18n::tf("warn.implicit_zero_iv", &[mode]))
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit block counter,
// 64-byte keystream blocks. Symmetric stream: running twice decrypts.
//
// Counter limit: the 32-bit block counter wraps after 2^32 blocks, i.e.
// 256 GiB of keystream per (key, nonce) pair; past that the keystream
// repeats, which is a confidentiality break. We intentionally keep 32-bit
// (RFC 8439) and refuse nothing at build time: consumers MUST re-key (or
// change the nonce) before 256 GiB. Note the in-memory run path can never
// reach the limit in practice, but a streamed run fed a giant file can.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AES: "direction split, mode parameterized". One encrypt op + one decrypt op;
// mode (ecb/cbc/cfb/ofb/ctr) defaults to cbc; iv defaults to the all-zero block.
// ---------------------------------------------------------------------------

// --- GCM (NIST SP 800-38D): authenticated encryption with associated data.
// Memory-only for now: the streaming factory rejects gcm with an explicit
// "not streamable" error. The GHASH/GCTR/J0 core lives in `super::gcm`,
// shared with SM4-GCM (cipher.rs) through the generic [`gcm::GcmBlock`] trait.
// Per-op IV / output-layout policy is implemented below (gcm_encrypt_iv and
// gcm_split_decrypt_input): an explicit `iv` keeps the classic `ct||tag`
// layout, while omitting `iv` switches to a random IV with `iv||ct||tag`
// output that the decrypt side auto-splits (unless `zero-iv-ok` is set).

// --- Streaming factory for the aes:encrypt / aes:decrypt ops. Block modes
// (ecb/cbc) buffer to full blocks and flush padding at finish; stream modes
// carry their native cross-chunk state.

// ---------------------------------------------------------------------------
// XOR brute force (single-byte key)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// legacy block ciphers (3DES / Blowfish) and TEA family
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TEA family: 64-bit blocks, big-endian words, zero padding to 8 bytes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// key derivation (PBKDF2 / HKDF, RFC 2898 / RFC 5869)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
