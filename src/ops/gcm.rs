//! Shared GCM core (NIST SP 800-38D), generic over any 128-bit block cipher.
//!
//! AES-GCM (crypto.rs) and SM4-GCM (cipher.rs) previously carried two parallel
//! copies of the GHASH / GCTR / J0 machinery (~200 lines). Both now implement
//! [`GcmBlock`] (single in-place block encryption) and reuse this one core;
//! each op keeps only its IV / output-layout policy in the caller.

use crate::i18n;

/// A 128-bit block cipher capable of encrypting a single block in place.
pub trait GcmBlock {
    fn encrypt_block(&self, blk: &mut [u8; 16]);
}

/// Default (and recommended) GCM IV length, in bytes.
pub(crate) const GCM_IV_LEN: usize = 12;
/// GCM authentication tag length, in bytes.
pub(crate) const GCM_TAG_LEN: usize = 16;

/// Reduction constant for GF(2^128): x^128 + x^7 + x^2 + x + 1.
const GCM_R: u128 = 0xe1u128 << 120;

/// Carry-less multiplication in GF(2^128), then reduction modulo GCM_R.
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v: u128 = y;
    let mut xb: u128 = x;
    for _ in 0..128 {
        if xb & (1u128 << 127) != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= GCM_R;
        }
        xb <<= 1;
    }
    z
}

/// GHASH: accumulate AAD blocks, ciphertext blocks (both zero-padded), then
/// the 64-bit bit-lengths of AAD and ciphertext.
fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut x: u128 = 0;
    for chunk in aad.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        x = gf_mul(x ^ u128::from_be_bytes(blk), h);
    }
    for chunk in ct.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        x = gf_mul(x ^ u128::from_be_bytes(blk), h);
    }
    let mut len_blk = [0u8; 16];
    len_blk[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    len_blk[8..].copy_from_slice(&(ct.len() as u64 * 8).to_be_bytes());
    x = gf_mul(x ^ u128::from_be_bytes(len_blk), h);
    x
}

/// Increments the low 32 bits of the 128-bit counter block (SP 800-38D inc32).
fn inc32(blk: &mut [u8; 16]) {
    for i in (12..16).rev() {
        blk[i] = blk[i].wrapping_add(1);
        if blk[i] != 0 {
            break;
        }
    }
}

/// GCTR keystream: counter starts at `icb` and is inc32-ed per block.
fn gctr<C: GcmBlock>(block: &C, icb: [u8; 16], input: &[u8], out: &mut Vec<u8>) {
    let mut cb = icb;
    let mut i = 0;
    while i < input.len() {
        let mut ks = [0u8; 16];
        ks.copy_from_slice(&cb);
        block.encrypt_block(&mut ks);
        inc32(&mut cb);
        let n = (input.len() - i).min(16);
        for (j, &b) in input[i..i + n].iter().enumerate() {
            out.push(b ^ ks[j]);
        }
        i += n;
    }
}

/// Builds J0: IV || 0^31 || 1 for 96-bit IVs, otherwise GHASH_H(IV padded).
fn gcm_j0(iv: &[u8], h: u128) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        j0
    } else {
        let mut x: u128 = 0;
        for chunk in iv.chunks(16) {
            let mut blk = [0u8; 16];
            blk[..chunk.len()].copy_from_slice(chunk);
            x = gf_mul(x ^ u128::from_be_bytes(blk), h);
        }
        let mut len_blk = [0u8; 16];
        len_blk[8..].copy_from_slice(&(iv.len() as u64 * 8).to_be_bytes());
        x = gf_mul(x ^ u128::from_be_bytes(len_blk), h);
        x.to_be_bytes()
    }
}

/// GCM encryption: returns (ciphertext, 16-byte tag).
pub(crate) fn encrypt<C: GcmBlock>(
    block: &C,
    iv: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut hb = [0u8; 16];
    block.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let j0 = gcm_j0(iv, h);
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let mut ct = Vec::with_capacity(plain.len());
    gctr(block, ctr0, plain, &mut ct);
    let s = ghash(h, aad, &ct);
    let mut ek0 = [0u8; 16];
    ek0.copy_from_slice(&j0);
    block.encrypt_block(&mut ek0);
    (ct, (s ^ u128::from_be_bytes(ek0)).to_be_bytes())
}

/// GCM decryption: authenticates ciphertext + tag, then decrypts in place.
pub(crate) fn decrypt<C: GcmBlock>(
    block: &C,
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut hb = [0u8; 16];
    block.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let s = ghash(h, aad, ct);
    let j0 = gcm_j0(iv, h);
    let mut ek0 = [0u8; 16];
    ek0.copy_from_slice(&j0);
    block.encrypt_block(&mut ek0);
    let t = (s ^ u128::from_be_bytes(ek0)).to_be_bytes();
    let mut diff = 0u8;
    for (a, b) in t.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        anyhow::bail!("{}", i18n::t("err.gcm_auth_failed"));
    }
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let mut plain = Vec::with_capacity(ct.len());
    gctr(block, ctr0, ct, &mut plain);
    Ok(plain)
}
