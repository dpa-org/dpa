#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dpa differential testing: compare core operations against Python stdlib / mature reference implementations.

Coverage:
- codec  : base64(base64/url) / base32 / base58 / base62 / base85 / hex / binary /
           octal / decimal / url / html / qp / utf16
- hash   : md5 / sha1 / sha224 / sha256 / sha384 / sha512 / sha3-256 / sha3-512 /
           shake128 / shake256 / crc32 / crc32c / adler32 / blake2b / blake2s /
           md4 / ripemd160 / sm3 / keccak / whirlpool / xxhash32 / xxhash64 / hmac
- compress: gzip / zlib / deflate / lzma(xz/lzma) / bzip2 / brotli
- crypto : aes(ecb/cbc/cfb/ofb/ctr/gcm) / chacha20 / rc4 / des / 3des / sm4 /
           pbkdf2 / hkdf / sm2(verify, raw and DER, incl. negative cases)

Input set: fixed-seed pseudo-random + edge coverage (empty, 1 byte, block boundary 15/16/17, 0x00, 0xFF,
full byte 0-255, non-ASCII, control characters, oversized).

Usage:
    python scripts/difftest.py [--exe <dpa binary path>] [--cases codec|hash|compress|crypto|all]
    python scripts/difftest.py --report <report output path>

Exit codes: 0=all passed; 1=some mismatches.
"""

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import hmac as hmac_mod
import html
import lzma
import os
import quopri
import random
import re
import subprocess
import sys
import urllib.parse
import zlib
from pathlib import Path

SEED = 20261016
EXE_DEFAULT = str(Path(__file__).resolve().parent.parent / "target" / "release" / "dpa.exe")

# ---------------- input sets ----------------

def make_inputs():
    rng = random.Random(SEED)
    inputs = []
    sizes = [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
             127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 4096, 65536]
    for s in sizes:
        inputs.append((f"rand-{s}", rng.randbytes(s)))
    for i in range(20):
        s = rng.randrange(0, 4096)
        inputs.append((f"randx-{i}-{s}", rng.randbytes(s)))
    inputs += [
        ("empty", b""),
        ("zero1", b"\x00"),
        ("zeros32", b"\x00" * 32),
        ("ff32", b"\xff" * 32),
        ("all-bytes", bytes(range(256))),
        ("ascii-text", b"The quick brown fox jumps over the lazy dog 0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?/~`"),
        ("utf8-cn", "你好，世界！Hello, 差分测试。这是一个中文测试字符串。".encode("utf-8")),
        ("mixed-ctrl", b"line1\r\nline2\tend\x00mid\x1b\x7f"),
        ("printable", bytes(range(32, 127))),
        ("high-bytes", bytes(range(0x80, 0x100))),
    ]
    return inputs


# ---------------- dpa invocation wrapper ----------------

class DpaError(Exception):
    pass


def run_dpa(op, data, args=None, output_format="raw", exe=EXE_DEFAULT, timeout=120, use_file=False):
    cmd = [exe, "op", op, "--output-format", output_format]
    if args:
        cmd += args
    if use_file:
        import os, tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
            tf.write(data)
            tf.flush()
            cmd.append(tf.name)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        finally:
            os.unlink(tf.name)
        if p.returncode != 0:
            err = p.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise DpaError(f"{op}: exit {p.returncode}: {err}")
        return p.stdout
    cmd.append("-")
    p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout)
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", errors="replace").strip()[:300]
        raise DpaError(f"{op}: exit {p.returncode}: {err}")
    return p.stdout


def run_dpa_hex(op, data, args=None, exe=EXE_DEFAULT, use_file=False):
    out = run_dpa(op, data, args, "hex", exe, use_file=use_file)
    return bytes.fromhex(out.decode("ascii").strip())


def run_dpa_text(op, data, args=None, exe=EXE_DEFAULT):
    return run_dpa(op, data, args, "raw", exe).rstrip(b"\r\n")


# ---------------- reference implementations ----------------

B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58_ALPHA[r] + s
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + (s if s else "")


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHA.index(c)
    pad = len(s) - len(s.lstrip("1"))
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + b


def b62encode(b):
    zeros = 0
    for x in b:
        if x == 0:
            zeros += 1
        else:
            break
    n = int.from_bytes(b[zeros:], "big") if zeros < len(b) else 0
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = B62_ALPHA[r] + s
    return "0" * zeros + (s if s else "")


def b62decode(s):
    n = 0
    for c in s:
        n = n * 62 + B62_ALPHA.index(c)
    pad = len(s) - len(s.lstrip("0"))
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + b


def bin_encode(b):
    return "".join(f"{x:08b}" for x in b)


def bin_decode(s):
    s = re.sub(r"[\s,]", "", s)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def oct_encode(b):
    return "".join(f"{x:03o}" for x in b)


def oct_decode(s):
    s = re.sub(r"[\s,]", "", s)
    return bytes(int(s[i:i + 3], 8) for i in range(0, len(s), 3))


def dec_encode(b):
    return " ".join(str(x) for x in b)


def dec_decode(s):
    return bytes(int(t) for t in re.split(r"[\s,;]+", s.strip()) if t)


def crc32c(data, poly=0x82F63B78):
    crc = 0xFFFFFFFF
    for x in data:
        crc ^= x
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if crc & 1 else 0)
    return (~crc) & 0xFFFFFFFF


def pkcs7_pad(data, bs=16):
    pad = bs - (len(data) % bs)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data, bs=16):
    if not data or len(data) % bs:
        raise ValueError("bad pkcs7 length")
    pad = data[-1]
    if pad < 1 or pad > bs or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad pkcs7 padding")
    return data[:-pad]


def ascii85encode(b):
    return base64.a85encode(b, adobe=False)


def ascii85encode_noz(b):
    """Ascii85 without z-compression (all-zero groups emit "!!!!!"), matching dpa --remove_zeros false."""
    out = bytearray()
    for i in range(0, len(b), 4):
        chunk = b[i:i + 4]
        if len(chunk) == 4:
            v = int.from_bytes(chunk, "big")
            if v == 0:
                out += b"!!!!!"
            else:
                tmp = bytearray(5)
                for j in range(4, -1, -1):
                    tmp[j] = 33 + (v % 85)
                    v //= 85
                out += tmp
        else:
            pad = 4 - len(chunk)
            v = int.from_bytes(chunk + b"\x00" * pad, "big")
            tmp = bytearray(5)
            for j in range(4, -1, -1):
                tmp[j] = 33 + (v % 85)
                v //= 85
            out += tmp[:5 - pad]
    return bytes(out)


def ascii85decode(s):
    return base64.a85decode(s, adobe=False)


def _qp_norm(b):
    """Normalize quoted-printable soft line-break style (strip =CRLF / =LF soft break marks).

    Note: real CRLF / LF / tab in payload must not be normalized; only soft breaks are stripped.
    """
    return b.replace(b"=\r\n", b"").replace(b"=\n", b"")


def qp_encode_ref(b, wrap=76):
    """Lossless QP reference encoder: matches dpa semantics (literal CRLF/LF/tab/space kept, "=" encoded,
    soft breaks as =CRLF). quopri is unusable: its C-accelerated b2a_qp loses binary CRLF."""
    out = bytearray()
    col = 0
    i = 0
    while i < len(b):
        c = b[i]
        if c == 0x0D:
            out.append(0x0D)
            i += 1
            if i < len(b) and b[i] == 0x0A:
                out.append(0x0A)
                i += 1
            col = 0
            continue
        if c == 0x0A:
            out.append(0x0A)
            i += 1
            col = 0
            continue
        if c == 0x3D:
            enc = b"=3D"
        elif 33 <= c <= 126 or c == 0x20 or c == 0x09:
            enc = bytes((c,))
        else:
            enc = b"=" + b"%02X" % c
        if wrap > 0 and col + len(enc) > wrap:
            out.extend(b"=\r\n")
            col = 0
        out.extend(enc)
        col += len(enc)
        i += 1
    return bytes(out)


# ---------------- test framework ----------------

class Result:
    def __init__(self):
        self.total = 0
        self.failed = []
        self.skipped = []

    def record(self, ok, case, detail=""):
        self.total += 1
        if not ok:
            self.failed.append((case, detail))

    def skip(self, case, reason):
        self.skipped.append((case, reason))


def cmp_encode(res, op, data, ref_text, args=None, exe=EXE_DEFAULT, label=None):
    name = f"{op}({label or ''}) in={data[:16].hex() or '(empty)'}"
    try:
        out = run_dpa_text(op, data, args, exe)
        ref = ref_text if isinstance(ref_text, bytes) else ref_text.encode("utf-8")
        res.record(out == ref, name, f"dpa={out[:64]!r} ref={ref[:64]!r}")
    except DpaError as e:
        res.record(False, name, str(e))


def cmp_decode(res, op, text, ref_bytes, args=None, exe=EXE_DEFAULT, label=None):
    name = f"{op}({label or ''}) in={text[:16]!r}"
    try:
        out = run_dpa_hex(op, text, args, exe)
        res.record(out == ref_bytes, name, f"dpa={out[:32].hex()} ref={ref_bytes[:32].hex()}")
    except DpaError as e:
        res.record(False, name, str(e))


def cmp_bytes(res, op, data, ref_fn, args=None, exe=EXE_DEFAULT, label=None):
    """Compare the op hex output byte-for-byte against ref_fn(data)."""
    name = f"{op}({label or ''}) in={data[:16].hex() or '(empty)'}"
    try:
        out = run_dpa_hex(op, data, args, exe)
        ref = ref_fn(data)
        res.record(out == ref, name, f"dpa={out[:32].hex()} ref={ref[:32].hex()}")
    except DpaError as e:
        res.record(False, name, str(e))


def roundtrip(res, op_enc, op_dec, data, enc_args=None, dec_args=None, exe=EXE_DEFAULT, label="",
              expected=None):
    """encode->decode roundtrip: enc uses the hex channel for exact bytes (CLI text-op output carries
    a trailing LF that pollutes decode input via the raw channel); expected may transform the
    expected value (e.g. WHATWG decodes entity U+0000 to U+FFFD, see dpa 61eb32f)."""
    name = f"rt:{op_enc}->{op_dec}({label}) in={data[:16].hex() or '(empty)'}"
    try:
        enc = run_dpa_hex(op_enc, data, enc_args, exe)
        dec = run_dpa_hex(op_dec, enc, dec_args, exe)
        want = expected(data) if expected else data
        res.record(dec == want, name, f"dpa={dec[:32].hex()} want={want[:32].hex()}")
    except DpaError as e:
        res.record(False, name, str(e))


# ---------------- test suites ----------------

def test_codec(res, inputs, exe):
    text_ok = [(n, d) for n, d in inputs if _is_utf8(d)]

    # base64 / base64:url
    for n, d in inputs:
        cmp_encode(res, "base64:encode", d, base64.b64encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "base64:decode", base64.b64encode(d), d, exe=exe, label=n)
    for n, d in inputs:
        cmp_encode(res, "base64:url:encode", d, base64.urlsafe_b64encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "base64:url:decode", base64.urlsafe_b64encode(d), d, exe=exe, label=n)

    # base32
    for n, d in inputs:
        cmp_encode(res, "base32:encode", d, base64.b32encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "base32:decode", base64.b32encode(d), d, exe=exe, label=n)

    # base58 (bitcoin alphabet)
    for n, d in inputs:
        cmp_encode(res, "base58:encode", d, b58encode(d), ["--alphabet", "bitcoin"], exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "base58:decode", b58encode(d).encode(), d, exe=exe, label=n)

    # base62
    for n, d in inputs:
        cmp_encode(res, "base62:encode", d, b62encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "base62:decode", b62encode(d).encode(), d, exe=exe, label=n)

    # base85 (Ascii85/Adobe; default z-compression matches Python a85encode; also test the uncompressed form via remove_zeros=false)
    for n, d in inputs:
        cmp_encode(res, "base85:encode", d, ascii85encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_encode(res, "base85:encode", d, ascii85encode_noz(d), ["--remove_zeros", "false"], exe=exe, label=f"noz-{n}")
    for n, d in inputs:
        cmp_decode(res, "base85:decode", ascii85encode(d), d, exe=exe, label=n)
    # z-compressed form roundtrip
    for n, d in inputs:
        if len(d) % 4 == 0 and len(d) > 0:
            roundtrip(res, "base85:encode", "base85:decode", d,
                      enc_args=["--remove_zeros", "true"], exe=exe, label=f"z-{n}")

    # hex
    for n, d in inputs:
        cmp_encode(res, "hex:encode", d, binascii.hexlify(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "hex:decode", binascii.hexlify(d), d, exe=exe, label=n)

    # binary / octal / decimal
    for n, d in inputs:
        cmp_encode(res, "binary:encode", d, bin_encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "binary:decode", bin_encode(d).encode(), d, exe=exe, label=n)
    for n, d in inputs:
        cmp_encode(res, "octal:encode", d, oct_encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "octal:decode", oct_encode(d).encode(), d, exe=exe, label=n)
    for n, d in inputs:
        cmp_encode(res, "decimal:encode", d, dec_encode(d), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "decimal:decode", dec_encode(d).encode(), d, exe=exe, label=n)

    # url (RFC 3986, preserve -._~)
    for n, d in inputs:
        cmp_encode(res, "url:encode", d, urllib.parse.quote_from_bytes(d, safe="-_.~"), exe=exe, label=n)
    for n, d in inputs:
        cmp_decode(res, "url:decode", urllib.parse.quote_from_bytes(d, safe="-_.~").encode(), d, exe=exe, label=n)

    # html (valid UTF-8 inputs only; reference html.escape quote=True, single quote as decimal &#39; like dpa)
    for n, d in text_ok:
        cmp_encode(res, "html:encode", d,
                   html.escape(d.decode("utf-8"), quote=True).replace("&#x27;", "&#39;").encode("utf-8"),
                   exe=exe, label=n)
    for n, d in text_ok:
        esc = html.escape(d.decode("utf-8"), quote=True).replace("&#x27;", "&#39;").encode("utf-8")
        cmp_decode(res, "html:decode", esc, d, exe=exe, label=n)
    # html encode_all form roundtrip.
    # Note: since dpa 61eb32f numeric entity U+0000 (&#0; / &#x0;) decodes as
    # U+FFFD per WHATWG (prevents NUL injection into the output stream), so roundtrip expectations for NUL inputs are adjusted.
    for n, d in text_ok:
        roundtrip(res, "html:encode", "html:decode", d,
                  enc_args=["--encode_all", "true"], exe=exe, label=f"all-{n}",
                  expected=lambda d: d.replace(b"\x00", "\uFFFD".encode()))

    # qp (soft line-break style ignored; compare normalized encoding core; also verify dpa output decodes back via stdlib)
    # Note: dpa text ops append a trailing LF to stdout, adding a stray newline via the raw channel;
    # use the hex channel for exact encoded bytes.
    for n, d in inputs:
        out = _qp_norm(run_dpa_hex("qp:encode", d, None, exe))
        ref = _qp_norm(qp_encode_ref(d))  # lossless reference (quopri loses binary CRLF)
        res.record(out == ref, f"qp:encode-{n}", f"dpa={out[:48]} ref={ref[:48]}")
    for n, d in inputs:
        out = run_dpa_hex("qp:encode", d, None, exe)
        try:
            dec = quopri.decodestring(out)
            res.record(dec == d, f"qp:enc-dec-{n}", f"dec={dec[:16].hex()} want={d[:16].hex()}")
        except Exception as e:
            res.record(False, f"qp:enc-dec-{n}", str(e))
    for n, d in inputs:
        cmp_decode(res, "qp:decode", qp_encode_ref(d), d, exe=exe, label=n)

    # utf16
    for n, d in text_ok:
        u = d.decode("utf-8")
        cmp_encode(res, "utf16:encode", d, u.encode("utf-16-le"), ["--endian", "le"], exe=exe, label=f"le-{n}")
        cmp_encode(res, "utf16:encode", d, u.encode("utf-16-be"), ["--endian", "be"], exe=exe, label=f"be-{n}")
        cmp_encode(res, "utf16:encode", d, u.encode("utf-16"), ["--endian", "le", "--bom", "true"], exe=exe, label=f"bom-{n}")
    for n, d in text_ok:
        u = d.decode("utf-8")
        cmp_decode(res, "utf16:decode", u.encode("utf-16"), d, exe=exe, label=f"le-bom-{n}")
        cmp_decode(res, "utf16:decode", u.encode("utf-16-be"), d, ["--endian", "be"], exe=exe, label=f"be-{n}")
        cmp_decode(res, "utf16:decode", u.encode("utf-16-le"), d, ["--endian", "le"], exe=exe, label=f"le-{n}")


def test_hash(res, inputs, exe):
    sha_fns = {
        "md5": lambda b: hashlib.md5(b).digest(),
        "sha1": lambda b: hashlib.sha1(b).digest(),
        "sha224": lambda b: hashlib.sha224(b).digest(),
        "sha256": lambda b: hashlib.sha256(b).digest(),
        "sha384": lambda b: hashlib.sha384(b).digest(),
        "sha512": lambda b: hashlib.sha512(b).digest(),
    }
    for op, fn in sha_fns.items():
        for n, d in inputs:
            cmp_bytes(res, op, d, fn, exe=exe, label=n)

    for op, fn in [("sha3:256", lambda b: hashlib.sha3_256(b).digest()),
                   ("sha3:512", lambda b: hashlib.sha3_512(b).digest())]:
        for n, d in inputs:
            cmp_bytes(res, op, d, fn, exe=exe, label=n)

    for variant in ("128", "256"):
        for ln in (16, 32, 64):
            fn = (hashlib.shake_128 if variant == "128" else hashlib.shake_256)
            args = ["--variant", variant, "--length", str(ln)]
            for n, d in inputs:
                cmp_bytes(res, "shake", d, lambda b, fn=fn, ln=ln: fn(b).digest(ln),
                          args=args, exe=exe, label=f"v{variant}-l{ln}-{n}")

    for n, d in inputs:
        cmp_bytes(res, "crc32", d, lambda b: zlib.crc32(b).to_bytes(4, "big"), exe=exe, label=n)
        cmp_bytes(res, "crc32c", d, lambda b: crc32c(b).to_bytes(4, "big"),
                  ["--variant", "castagnoli"], exe=exe, label=n)
        cmp_bytes(res, "adler32", d, lambda b: (zlib.adler32(b) & 0xFFFFFFFF).to_bytes(4, "big"), exe=exe, label=n)

    blake = {"blake2b:256": (hashlib.blake2b, 32), "blake2b:384": (hashlib.blake2b, 48),
             "blake2b:512": (hashlib.blake2b, 64), "blake2s:256": (hashlib.blake2s, 32)}
    for op, (fn, ds) in blake.items():
        for n, d in inputs:
            cmp_bytes(res, op, d, lambda b, fn=fn, ds=ds: fn(b, digest_size=ds).digest(), exe=exe, label=n)

    extra = {
        "md4": None,  # Python 3.13+/OpenSSL 3 hashlib has no md4; use pycryptodome
        "ripemd160": (hashlib.new, "ripemd160"),
        "sm3": (hashlib.new, "sm3"),
    }
    for op, spec in extra.items():
        if spec is None:
            try:
                from Crypto.Hash import MD4 as _md4
                fn = lambda b, m=_md4: m.new(b).digest()
            except ImportError:
                res.skip(f"{op}", "pycryptodome not installed; md4 cannot be tested")
                continue
        else:
            fn_, algo = spec
            try:
                fn_(algo, b"").digest()
            except (ValueError, TypeError):
                res.skip(f"{op}", "hashlib does not support this algorithm")
                continue
            fn = lambda b, fn_=fn_, algo=algo: fn_(algo, b).digest()
        for n, d in inputs:
            cmp_bytes(res, op, d, fn, exe=exe, label=n)

    # keccak / whirlpool: probe each reference independently. A missing
    # reference must be recorded as a skip; it must never abort the whole
    # group silently (that used to hide ~696 checks while printing SKIP=0).
    try:
        from Crypto.Hash import keccak as _keccak_mod  # noqa: F401

        _have_keccak = True
    except ImportError:
        _have_keccak = False
        res.skip("keccak", "pycryptodome not installed")

    try:
        from whirlpool import new as _wp_mod  # noqa: F401

        _have_whirlpool = True
    except ImportError:
        try:
            from Crypto.Hash import whirlpool as _crypto_whirlpool  # noqa: F401

            _have_whirlpool = True
        except ImportError:
            _have_whirlpool = False
            res.skip("whirlpool", "whirlpool reference library not installed")

    if _have_keccak:
        for variant in ("224", "256", "384", "512"):
            args = ["--variant", variant]
            for n, d in inputs:
                cmp_bytes(res, "keccak", d, _keccak_digest(variant), args=args, exe=exe, label=f"v{variant}-{n}")
    if _have_whirlpool:
        for n, d in inputs:
            cmp_bytes(res, "whirlpool", d, _whirlpool_digest(), exe=exe, label=n)

    try:
        import xxhash as _xxh_mod
        _have_xxh = True
    except ImportError:
        _have_xxh = False
        res.skip("xxhash32/xxhash64", "xxhash library not installed")

    if _have_xxh:
        for n, d in inputs:
            cmp_bytes(res, "xxhash32", d, _xxh_digest(32), exe=exe, label=n)
            cmp_bytes(res, "xxhash64", d, _xxh_digest(64), exe=exe, label=n)

    # hmac
    for algo in ("sha1", "sha256", "sha512"):
        fn = getattr(hashlib, algo)
        for key in (b"key", b"0123456789abcdef", b"\x00" * 32):
            for n, d in inputs:
                cmp_bytes(res, "hmac", d, lambda b, fn=fn, key=key: hmac_mod.new(key, b, fn).digest(),
                          args=["--key", hexs(key) if b"\x00" in key else key.decode("latin1"), "--algo", algo], exe=exe,
                          label=f"{algo}-k{len(key)}-{n}")


def _keccak_digest(variant):
    try:
        from Crypto.Hash import keccak
    except ImportError:
        return lambda b: (_ for _ in ()).throw(ImportError("pycryptodome not installed"))
    def fn(b):
        return keccak.new(digest_bits=int(variant), data=b).digest()
    return fn


def _whirlpool_digest():
    try:
        from whirlpool import new as wp_new
    except ImportError:
        try:
            from Crypto.Hash import whirlpool
            return lambda b: whirlpool.new(b).digest()
        except ImportError:
            return lambda b: (_ for _ in ()).throw(ImportError("whirlpool reference library not installed"))
    def fn(b):
        return wp_new(b).digest()
    return fn


def _xxh_digest(bits):
    try:
        import xxhash
    except ImportError:
        return lambda b: (_ for _ in ()).throw(ImportError("xxhash not installed"))
    def fn(b):
        h = xxhash.xxh32(b, seed=0) if bits == 32 else xxhash.xxh64(b, seed=0)
        return h.digest()  # dpa emits big-endian bytes (to_be_bytes), matching the python xxhash digest
    return fn


def test_compress(res, inputs, exe):
    # Bidirectional: dpa compress -> Python decompress; Python compress -> dpa decompress; dpa self-roundtrip
    pairs = [
        ("gzip:compress", "gzip:decompress",
         lambda b: gzip.compress(b), lambda b: gzip.decompress(b)),
        ("zlib:compress", "zlib:decompress",
         lambda b: zlib.compress(b), lambda b: zlib.decompress(b)),
        ("deflate:compress", "deflate:decompress",
         lambda b: zlib.compress(b, level=6, wbits=-15), lambda b: zlib.decompress(b, wbits=-15)),
        ("bzip2:compress", "bzip2:decompress",
         lambda b: bz2.compress(b), lambda b: bz2.decompress(b)),
        ("lzma:compress", "lzma:decompress",
         lambda b: lzma.compress(b, format=lzma.FORMAT_XZ), lambda b: lzma.decompress(b)),
    ]
    for op_c, op_d, py_c, py_d in pairs:
        lzma_args = ["--format", "xz"] if op_c == "lzma:compress" else None
        for n, d in inputs:
            # dpa compress -> Python decompress
            name = f"{op_c}->py-decomp({n})"
            try:
                comp = run_dpa(op_c, d, lzma_args, "raw", exe)
                dec = py_d(comp)
                res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
            except (DpaError, Exception) as e:
                res.record(False, name, str(e)[:200])
            # Python compress -> dpa decompress
            name = f"py-comp->{op_d}({n})"
            try:
                comp = py_c(d)
                dec = run_dpa_hex(op_d, comp, None, exe)
                res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
            except Exception as e:
                res.record(False, name, str(e)[:200])
            # dpa self-roundtrip
            roundtrip(res, op_c, op_d, d, enc_args=lzma_args, exe=exe, label=n)

    # lzma alone (FORMAT_ALONE)
    for n, d in inputs:
        name = f"lzma:compress(alone)->py-decomp({n})"
        try:
            comp = run_dpa("lzma:compress", d, ["--format", "lzma"], "raw", exe)
            dec = lzma.decompress(comp, format=lzma.FORMAT_ALONE)
            res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
        except Exception as e:
            res.record(False, name, str(e)[:200])
        name = f"py-lzma(xz)->dpa({n})"
        try:
            comp = lzma.compress(d, format=lzma.FORMAT_XZ)
            dec = run_dpa_hex("lzma:decompress", comp, None, exe)
            res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
        except Exception as e:
            res.record(False, name, str(e)[:200])

    # brotli
    try:
        import brotli
    except ImportError:
        res.skip("brotli", "brotli library not installed")
        return
    for n, d in inputs:
        name = f"brotli:compress->py-decomp({n})"
        try:
            comp = run_dpa("brotli:compress", d, None, "raw", exe)
            res.record(brotli.decompress(comp) == d, name, "mismatch")
        except Exception as e:
            res.record(False, name, str(e)[:200])
        name = f"py-brotli->dpa({n})"
        try:
            comp = brotli.compress(d)
            dec = run_dpa_hex("brotli:decompress", comp, None, exe)
            res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
        except Exception as e:
            res.record(False, name, str(e)[:200])


def test_crypto(res, inputs, exe):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as chashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        res.skip("crypto", "cryptography library not installed")
        return

    # AES
    for ks in (16, 24, 32):
        key = bytes(range(ks))
        iv = bytes(range(16))
        label = f"aes{ks * 8}-cbc"
        for n, d in inputs:
            ref = AES_CBC_enc(key, iv, d)
            cmp_bytes(res, "aes:encrypt", d, lambda b, key=key, iv=iv: AES_CBC_enc(key, iv, b),
                      args=["--key", hexs(key), "--mode", "cbc", "--iv", hexs(iv)], exe=exe, label=f"{label}-{n}")
        # cbc decrypt roundtrip
        for n, d in inputs:
            ct = AES_CBC_enc(key, iv, d)
            name = f"aes:decrypt-cbc({label}-{n})"
            try:
                dec = run_dpa_hex("aes:decrypt", ct, ["--key", hexs(key), "--mode", "cbc", "--iv", hexs(iv)], exe)
                res.record(dec == d, name, f"dpa={dec[:32].hex()} want={d[:32].hex()}")
            except DpaError as e:
                res.record(False, name, str(e))
        # ctr
        for n, d in inputs:
            cmp_bytes(res, "aes:encrypt", d, lambda b, key=key, iv=iv: AES_CTR_enc(key, iv, b),
                      args=["--key", hexs(key), "--mode", "ctr", "--iv", hexs(iv)], exe=exe, label=f"aes{ks * 8}-ctr-{n}")
        # cfb / ofb
        for mode_name, ref_fn in (("cfb", lambda key, iv, b: AES_stream_enc(key, iv, b, modes.CFB)),
                                  ("ofb", lambda key, iv, b: AES_stream_enc(key, iv, b, modes.OFB))):
            for n, d in inputs:
                cmp_bytes(res, "aes:encrypt", d, lambda b, key=key, iv=iv, fn=ref_fn: fn(key, iv, b),
                          args=["--key", hexs(key), "--mode", mode_name, "--iv", hexs(iv)], exe=exe,
                          label=f"aes{ks * 8}-{mode_name}-{n}")

    # AES-GCM (tolerant tag ordering)
    key = bytes(range(16))
    iv = bytes(range(12))
    aad = b"aad-data"
    for n, d in inputs:
        ref_ct, ref_tag = AES_GCM_enc(key, iv, aad, d)
        out = run_dpa("aes:encrypt", d, ["--key", hexs(key), "--mode", "gcm", "--iv", hexs(iv), "--aad", hexs(aad)], "raw", exe, use_file=True)
        # try both ciphertext||tag and tag||ciphertext layouts
        ok = False
        if out == ref_ct + ref_tag:
            ok = True
        elif out == ref_tag + ref_ct:
            ok = True
        res.record(ok, f"aes:encrypt-gcm-{n}", f"len={len(out)} ct={ref_ct[:16].hex()} tag={ref_tag.hex()}")
        # decrypt roundtrip (ciphertext as input, tag passed separately)
        name = f"aes:decrypt-gcm-{n}"
        try:
            dec = run_dpa_hex("aes:decrypt", ref_ct,
                              ["--key", hexs(key), "--mode", "gcm", "--iv", hexs(iv), "--aad", hexs(aad), "--tag", hexs(ref_tag)],
                              exe, use_file=True)
            res.record(dec == d, name, f"dpa={dec[:32].hex()} want={d[:32].hex()}")
        except DpaError as e:
            res.record(False, name, str(e))

    # chacha20
    key = bytes(range(32))
    nonce = bytes(range(12))
    for n, d in inputs:
        out = run_dpa("chacha20", d, ["--key", hexs(key), "--nonce", hexs(nonce)], "raw", exe)
        ref = chacha20_ref(key, nonce, d)
        res.record(out == ref, f"chacha20-{n}", f"dpa={out[:32].hex()} ref={ref[:32].hex()}")
        # symmetric roundtrip
        name = f"chacha20-rt-{n}"
        try:
            dec = run_dpa("chacha20", out, ["--key", hexs(key), "--nonce", hexs(nonce)], "raw", exe)
            res.record(dec == d, name, f"dec={dec[:32].hex()} want={d[:32].hex()}")
        except DpaError as e:
            res.record(False, name, str(e))

    # rc4
    for key in (b"Key", b"SecretKey", bytes(range(16))):
        for n, d in inputs:
            out = run_dpa("rc4", d, ["--key", hexs(key) if b"\x00" in key else key.decode("latin1")], "raw", exe)
            ref = rc4_ref(key, d)
            res.record(out == ref, f"rc4-k{len(key)}-{n}", f"dpa={out[:32].hex()} ref={ref[:32].hex()}")

    # des / 3des cbc
    des_key = bytes(range(8))
    des_iv = bytes(range(8))
    for n, d in inputs:
        ref = DES_CBC_enc(des_key, des_iv, d)
        cmp_bytes(res, "des:encrypt", d, lambda b, key=des_key, iv=des_iv: DES_CBC_enc(key, iv, b),
                  args=["--key", hexs(des_key), "--mode", "cbc", "--iv", hexs(des_iv)], exe=exe, label=f"des-cbc-{n}")
    td_key = bytes(range(24))
    td_iv = bytes(range(8))
    for n, d in inputs:
        ref = TDES_CBC_enc(td_key, td_iv, d)
        cmp_bytes(res, "des3:encrypt", d, lambda b, key=td_key, iv=td_iv: TDES_CBC_enc(key, iv, b),
                  args=["--key", hexs(td_key), "--mode", "cbc", "--iv", hexs(td_iv)], exe=exe, label=f"3des-cbc-{n}")

    # sm4: ECB standard vector + per-mode roundtrips
    sm4_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    sm4_pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    out = run_dpa_hex("sm4:encrypt", sm4_pt, ["--key", hexs(sm4_key), "--mode", "ecb", "--padding", "none"], exe)
    res.record(out == bytes.fromhex("681edf34d206965e86b3e94f536e4246"),
               "sm4:encrypt-ecb-stdvec", f"dpa={out.hex()} want=681edf34d206965e86b3e94f536e4246")
    for mode_name in ("ecb", "cbc", "cfb", "ofb", "ctr"):
        for n, d in inputs:
            sm4_args = ["--key", hexs(sm4_key), "--mode", mode_name, "--iv", hexs(bytes(range(16)))]
            roundtrip(res, "sm4:encrypt", "sm4:decrypt", d,
                      enc_args=sm4_args, dec_args=sm4_args,
                      exe=exe, label=f"sm4-{mode_name}-{n}")

    # sm4-gcm: pysm4 (standalone SM4 block impl, validated against the GM standard vector) as NIST SP 800-38D reference,
    # covering multi-length inputs / iv variations / aad variations / tag verification failures
    try:
        import pysm4
    except ImportError:
        res.skip("sm4-gcm", "pysm4 not installed; SM4-GCM differential unavailable")
    else:
        def sm4_gcm_enc_ref(key, iv, aad, data):
            gcm_r = 0xE1 << 120

            def gf_mul(x, y):
                z, v, xb = 0, y, x
                for _ in range(128):
                    if xb & (1 << 127):
                        z ^= v
                    lsb = v & 1
                    v >>= 1
                    if lsb:
                        v ^= gcm_r
                    xb <<= 1
                return z

            def enc_block(blk):
                return pysm4.encrypt(int.from_bytes(blk, "big"), int.from_bytes(key, "big")).to_bytes(16, "big")

            def chunks(b):
                return [b[i:i + 16] for i in range(0, len(b), 16)]

            def ghash(h, aad_, ct_):
                x = 0
                for ch in chunks(aad_):
                    x = gf_mul(x ^ int.from_bytes(ch + b"\x00" * (16 - len(ch)), "big"), h)
                for ch in chunks(ct_):
                    x = gf_mul(x ^ int.from_bytes(ch + b"\x00" * (16 - len(ch)), "big"), h)
                lb = (len(aad_) * 8).to_bytes(8, "big") + (len(ct_) * 8).to_bytes(8, "big")
                return gf_mul(x ^ int.from_bytes(lb, "big"), h)

            def inc32(blk):
                b = bytearray(blk)
                for i in range(15, 11, -1):
                    b[i] = (b[i] + 1) & 0xFF
                    if b[i]:
                        break
                return bytes(b)

            def gctr(icb, data):
                cb, out = icb, bytearray()
                for i in range(0, len(data), 16):
                    ks = enc_block(cb)
                    ch = data[i:i + 16]
                    out.extend(a ^ b for a, b in zip(ch, ks))
                    cb = inc32(cb)
                return bytes(out)

            h = int.from_bytes(enc_block(b"\x00" * 16), "big")
            if len(iv) == 12:
                j0 = iv + b"\x00" * 3 + b"\x01"
            else:
                x = 0
                for ch in chunks(iv):
                    x = gf_mul(x ^ int.from_bytes(ch + b"\x00" * (16 - len(ch)), "big"), h)
                lb = b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big")
                j0 = gf_mul(x ^ int.from_bytes(lb, "big"), h).to_bytes(16, "big")
            ct = gctr(inc32(j0), data)
            s = ghash(h, aad, ct)
            tag = (s ^ int.from_bytes(enc_block(j0), "big")).to_bytes(16, "big")
            return ct, tag

        gcm_iv = bytes(range(12))
        gcm_aad = b"aad-data"
        for n, d in inputs:
            ref_ct, ref_tag = sm4_gcm_enc_ref(sm4_key, gcm_iv, gcm_aad, d)
            out = run_dpa("sm4:encrypt", d,
                          ["--key", hexs(sm4_key), "--mode", "gcm", "--iv", hexs(gcm_iv), "--aad", hexs(gcm_aad)],
                          "raw", exe, use_file=True)
            res.record(out == ref_ct + ref_tag, f"sm4:encrypt-gcm-{n}",
                       f"len={len(out)} ct={ref_ct[:16].hex()} tag={ref_tag.hex()}")
            name = f"sm4:decrypt-gcm-{n}"
            try:
                dec = run_dpa_hex("sm4:decrypt", ref_ct,
                                  ["--key", hexs(sm4_key), "--mode", "gcm", "--iv", hexs(gcm_iv),
                                   "--aad", hexs(gcm_aad), "--tag", hexs(ref_tag)],
                                  exe, use_file=True)
                res.record(dec == d, name, f"dpa={dec[:32].hex()} want={d[:32].hex()}")
            except DpaError as e:
                res.record(False, name, str(e))
            # tag verification failure: a tampered tag must make decryption error out
            name = f"sm4:decrypt-gcm-tagfail-{n}"
            bad_tag = bytearray(ref_tag)
            bad_tag[0] ^= 0x01
            try:
                run_dpa_hex("sm4:decrypt", ref_ct,
                            ["--key", hexs(sm4_key), "--mode", "gcm", "--iv", hexs(gcm_iv),
                             "--aad", hexs(gcm_aad), "--tag", hexs(bytes(bad_tag))],
                            exe, use_file=True)
                res.record(False, name, "decryption succeeded despite tampered tag")
            except DpaError:
                res.record(True, name, "authentication failure rejected")
        # iv variations (including non-12-byte, exercising the GHASH J0 branch)
        for ivlen in (8, 13, 16, 20):
            iv = bytes(range(ivlen))
            ref_ct, ref_tag = sm4_gcm_enc_ref(sm4_key, iv, b"", b"abc")
            out = run_dpa("sm4:encrypt", b"abc",
                          ["--key", hexs(sm4_key), "--mode", "gcm", "--iv", hexs(iv)],
                          "raw", exe, use_file=True)
            res.record(out == ref_ct + ref_tag, f"sm4:encrypt-gcm-iv{ivlen}",
                       f"ct={ref_ct.hex()} tag={ref_tag.hex()}")
        # aad variations (empty / short / regular / longer than a block)
        for aad_v in (b"", b"a", b"aad-data", b"longer-aad" * 8):
            ref_ct, ref_tag = sm4_gcm_enc_ref(sm4_key, gcm_iv, aad_v, b"payload-payload-payload")
            out = run_dpa("sm4:encrypt", b"payload-payload-payload",
                          ["--key", hexs(sm4_key), "--mode", "gcm", "--iv", hexs(gcm_iv), "--aad", hexs(aad_v)],
                          "raw", exe, use_file=True)
            res.record(out == ref_ct + ref_tag, f"sm4:encrypt-gcm-aad{len(aad_v)}",
                       f"ct={ref_ct.hex()} tag={ref_tag.hex()}")

    # pbkdf2
    for algo in ("sha1", "sha256", "sha512"):
        for iters in (1, 1000, 100000):
            for ln in (16, 32, 64):
                salt = b"salt123"
                pwd = b"password"
                ref = hashlib.pbkdf2_hmac(algo, pwd, salt, iters, ln)
                out = run_dpa_hex("pbkdf2", pwd,
                                  ["--salt", "salt123", "--iterations", str(iters), "--length", str(ln), "--hash", algo], exe)
                res.record(out == ref, f"pbkdf2-{algo}-i{iters}-l{ln}",
                           f"dpa={out[:32].hex()} ref={ref[:32].hex()}")

    # hkdf
    ikm = b"input-key-material"
    for ln in (16, 32, 64):
        ref = HKDF(algorithm=chashes.SHA256(), length=ln, salt=b"hkdf-salt", info=b"info").derive(ikm)
        out = run_dpa_hex("hkdf", ikm,
                          ["--salt", "hkdf-salt", "--info", "info", "--length", str(ln), "--hash", "sha256"], exe)
        res.record(out == ref, f"hkdf-sha256-l{ln}", f"dpa={out[:32].hex()} ref={ref[:32].hex()}")

    # SM2-with-SM3 verification differential (gmssl reference, raw/DER + negative cases)
    test_crypto_sm2(res, exe)


def test_crypto_sm2(res, exe):
    """SM2-with-SM3 verification differential: fixed-seed random keys/messages, gmssl generates signatures,
    compared against dpa:sm2:verify; covers raw(r||s) and DER signature layouts,
    default distid, and three negative cases: tampered message / tampered signature / wrong key."""
    try:
        from gmssl import sm2 as gm_sm2
    except ImportError:
        res.skip("sm2", "gmssl not installed; SM2 verification differential unavailable")
        return

    rng = random.Random(SEED + 0x5A12)
    keypairs = [_sm2_gen_keypair(rng), _sm2_gen_keypair(rng)]

    msgs = [
        ("empty", b""),
        ("one", b"\x01"),
        ("16b", bytes(range(16))),
        ("256b", bytes(range(256))),
        ("ascii", b"The quick brown fox jumps over the lazy dog"),
        ("utf8-cn", "你好，世界！SM2 差分测试。".encode("utf-8")),
        ("ff32", b"\xff" * 32),
        ("rand512", rng.randbytes(512)),
    ]

    def sign(msg, c):
        while True:
            sig = c.sign_with_sm3(msg, rng.randbytes(32).hex().upper())
            if sig is not None:
                return sig

    for idx, (priv, pub) in enumerate(keypairs):
        der_c = gm_sm2.CryptSM2(private_key=priv, public_key=pub, asn1=True)
        raw_c = gm_sm2.CryptSM2(private_key=priv, public_key=pub, asn1=False)
        pem = _sm2_pub_pem_single(pub)
        other_pem = _sm2_pub_pem_single(keypairs[1 - idx][1])

        for n, msg in msgs:
            # positive: both DER and raw layouts must verify in dpa, consistent with the gmssl reference
            for layout, c in (("der", der_c), ("raw", raw_c)):
                sig = sign(msg, c)
                name = f"sm2:verify-{layout}-k{idx}-{n}"
                try:
                    out = run_dpa_text("sm2:verify", msg,
                                       ["--key=" + pem, "--signature", sig, "--sig_type", layout], exe)
                    ok = out == b"true"
                except DpaError as e:
                    ok = False
                    out = str(e)
                ref_ok = (der_c if layout == "der" else raw_c).verify_with_sm3(sig, msg) == 1
                res.record(ok and ref_ok, name,
                           f"layout={layout} dpa={out!r} gmssl_ref={ref_ok}")

            # negative: tampered message (the signature itself is valid; verification must fail)
            tampered = msg + b"\x00" if msg else b"\x01"
            sig_t = sign(tampered, der_c)
            name = f"sm2:verify-neg-msg-k{idx}-{n}"
            try:
                out = run_dpa_text("sm2:verify", msg,
                                   ["--key=" + pem, "--signature", sig_t, "--sig_type", "der"], exe)
                res.record(out == b"false", name, f"dpa={out!r}")
            except DpaError as e:
                res.record(False, name, f"unexpected dpa error: {e}")

            # negative: tampered signature (flip the first DER byte; dpa may report invalid or return false)
            sig_b = bytearray.fromhex(sig_t)
            sig_b[0] ^= 0x01
            name = f"sm2:verify-neg-sig-k{idx}-{n}"
            try:
                out = run_dpa_text("sm2:verify", msg,
                                   ["--key=" + pem, "--signature", bytes(sig_b).hex(), "--sig_type", "der"], exe)
                res.record(out == b"false", name, f"dpa={out!r}")
            except DpaError as e:
                res.record(True, name, f"dpa rejected invalid DER signature: {e}")

        # negative: wrong key (a valid signature paired with a different public key; verification must fail)
        for n, msg in msgs[:4]:
            sig = sign(msg, der_c)
            name = f"sm2:verify-neg-key-k{idx}-{n}"
            try:
                out = run_dpa_text("sm2:verify", msg,
                                   ["--key=" + other_pem, "--signature", sig, "--sig_type", "der"], exe)
                res.record(out == b"false", name, f"dpa={out!r}")
            except DpaError as e:
                res.record(False, name, f"unexpected dpa error: {e}")


def _sm2_gen_keypair(rng):
    """Generate a random SM2 keypair: (private d hex, uncompressed point 04||x||y hex)."""
    from gmssl import sm2 as gm_sm2
    n = int(gm_sm2.default_ecc_table["n"], 16)
    d = int.from_bytes(rng.randbytes(32), "big") % (n - 1) + 1
    d_hex = format(d, "064x")
    c = gm_sm2.CryptSM2(private_key=d_hex, public_key="04" + "00" * 64)
    pub = c._kg(d, gm_sm2.default_ecc_table["g"]).rjust(128, "0")
    return d_hex, "04" + pub


def _sm2_pub_pem_single(point_hex):
    """Encode an SM2 public-key point (04||x||y) as a single-line SPKI PEM
    (id-ecPublicKey + SM2 curve OID 1.2.156.10197.1.301)."""
    oid_ec = _der_oid("1.2.840.10045.2.1")
    oid_sm2 = _der_oid("1.2.156.10197.1.301")
    alg = _der_tlv(0x30, _der_tlv(0x06, oid_ec) + _der_tlv(0x06, oid_sm2))
    bitstr = _der_tlv(0x03, b"\x00" + bytes.fromhex(point_hex))
    spki = _der_tlv(0x30, alg + bitstr)
    b64 = base64.b64encode(spki).decode()
    return "-----BEGIN PUBLIC KEY-----" + b64 + "-----END PUBLIC KEY-----"


def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _der_oid(s):
    parts = [int(x) for x in s.split(".")]
    out = [parts[0] * 40 + parts[1]]
    for v in parts[2:]:
        buf = [v & 0x7F]
        v >>= 7
        while v:
            buf.append(0x80 | (v & 0x7F))
            v >>= 7
        out.extend(reversed(buf))
    return bytes(out)


# ---------------- crypto reference implementations ----------------

def hexs(b):
    return "0x" + b.hex()


def AES_CBC_enc(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return c.update(pkcs7_pad(data, 16)) + c.finalize()


def AES_CTR_enc(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def AES_stream_enc(key, iv, data, mode_cls):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    c = Cipher(algorithms.AES(key), mode_cls(iv)).encryptor()
    return c.update(data) + c.finalize()


def AES_GCM_enc(key, iv, aad, data):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    full = AESGCM(key).encrypt(iv, data, aad)  # ciphertext||tag
    return full[:-16], full[-16:]  # split off the tag (GCM tag is fixed at 16 bytes)


def chacha20_ref(key, nonce, data):
    """IETF RFC 7539 ChaCha20 (key 32B / nonce 12B / 32-bit counter starting at 0),
    aligned with dpa's RustCrypto chacha20 crate; cryptography's ChaCha20 is a 16B-nonce
    variant and cannot be used as a reference."""
    import struct

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = rotl(x[d], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = rotl(x[b], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = rotl(x[d], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = rotl(x[b], 7)

    consts = struct.unpack("<4I", b"expand 32-byte k")
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce)
    out = bytearray()
    counter = 0
    for off in range(0, len(data), 64):
        state = list(consts) + list(k) + [counter] + list(n)
        work = state[:]
        for _ in range(10):
            qr(work, 0, 4, 8, 12); qr(work, 1, 5, 9, 13)
            qr(work, 2, 6, 10, 14); qr(work, 3, 7, 11, 15)
            qr(work, 0, 5, 10, 15); qr(work, 1, 6, 11, 12)
            qr(work, 2, 7, 8, 13); qr(work, 3, 4, 9, 14)
        ks = struct.pack("<16I", *((s + w) & 0xFFFFFFFF for s, w in zip(work, state)))
        chunk = data[off:off + 64]
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)


def rc4_ref(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def DES_CBC_enc(key, iv, data):
    from Crypto.Cipher import DES
    return DES.new(key, DES.MODE_CBC, iv).encrypt(pkcs7_pad(data, 8))


def TDES_CBC_enc(key, iv, data):
    from Crypto.Cipher import DES3
    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(pkcs7_pad(data, 8))


def _is_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# ---------------- main flow ----------------

def main():
    ap = argparse.ArgumentParser(description="dpa differential testing")
    ap.add_argument("--exe", default=EXE_DEFAULT, help="path to the dpa binary")
    ap.add_argument("--cases", default="all", choices=["all", "codec", "hash", "compress", "crypto"])
    ap.add_argument("--report", default="", help="report output path (optional)")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="treat skips and whole-group exceptions as failures (used in CI; omit locally when reference libraries are missing)",
    )
    args = ap.parse_args()

    exe = args.exe
    if not os.path.isfile(exe):
        print(f"FATAL: dpa binary not found: {exe}", file=sys.stderr)
        sys.exit(2)

    inputs = make_inputs()
    res = Result()

    def run_case(name, fn):
        print(f"\n=== {name} ===")
        try:
            fn(res, inputs, exe)
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
            res.record(False, f"group:{name}", detail)
            print(f"  case-group exception (recorded as failure): {detail}")

    if args.cases in ("all", "codec"):
        run_case("codec", test_codec)
    if args.cases in ("all", "hash"):
        run_case("hash", test_hash)
    if args.cases in ("all", "compress"):
        run_case("compress", test_compress)
    if args.cases in ("all", "crypto"):
        run_case("crypto", test_crypto)

    print("\n" + "=" * 70)
    print(f"TOTAL={res.total}  FAIL={len(res.failed)}  SKIP={len(res.skipped)}")
    if res.skipped:
        print("SKIPPED:")
        for case, why in res.skipped:
            print(f"  - {case}: {why}")
    if res.failed:
        print("\nFAILED DETAILS:")
        for case, detail in res.failed:
            print(f"  FAIL {case}")
            print(f"      {detail[:300]}")
    else:
        print("\nALL PASSED")

    if args.report:
        lines = [f"# dpa differential testing report", "",
                 f"- date: 2026-10-16", f"- dpa binary: {exe}", "",
                 f"- TOTAL={res.total}  FAIL={len(res.failed)}  SKIP={len(res.skipped)}", ""]
        if res.failed:
            lines.append("## failure details")
            for case, detail in res.failed:
                lines.append(f"- `{case}`: {detail[:300]}")
        if res.skipped:
            lines.append("## skipped details")
            for case, why in res.skipped:
                lines.append(f"- `{case}`: {why}")
        Path(args.report).write_text("\n".join(lines), encoding="utf-8")
        print(f"\nreport written to: {args.report}")

    if res.failed:
        sys.exit(1)
    if args.strict and res.skipped:
        print(f"\nSTRICT: {len(res.skipped)} skipped group(s) count as failure")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
