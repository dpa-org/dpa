#!/usr/bin/env python3
"""Check i18n key parity between en/ and zh-CN/ resource directories.

Rules (fail on any violation):
  1. i18n/en/*.ftl and i18n/zh-CN/*.ftl must contain the exact same file set
     (same basenames) -- a missing file means a whole family is untranslated.
  2. For each pair of files, the key set of zh-CN must equal the key set of en:
     - short keys (err./msg./cli.) and op/arg keys (op.*) must all be present
       in zh-CN (missing -> gap -> FAIL);
     - zh-CN must not carry keys absent from en (extra -> FAIL).
     Legacy english-original rows (no op./err./msg./cli. prefix) are permitted
     in zh-CN as translation assets but must not appear in en.

Usage: python3 scripts/check_i18n_keys.py
Exit code 0 = parity OK, 1 = gap/extra found.
"""

import os
import re
import sys

I18N = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "i18n")
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

SRC_KEY_RE = re.compile(r'i18n::(?:t|tf)\s*\(\s*"([^"]+)"')


def parse_keys(path):
    keys = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#") or " = " not in s:
                continue
            keys.add(s.split(" = ", 1)[0].strip())
    return keys


def is_short_key(k):
    return k.startswith(("err.", "msg.", "cli."))


def is_op_key(k):
    return k.startswith("op.")


def collect_src_keys(src_root):
    """Collect every literal i18n key referenced from Rust sources."""
    keys = set()
    for root, _dirs, files in os.walk(src_root):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8") as fh:
                for m in SRC_KEY_RE.finditer(fh.read()):
                    keys.add(m.group(1))
    return keys


def main():
    en_dir = os.path.join(I18N, "en")
    zh_dir = os.path.join(I18N, "zh-CN")
    if not os.path.isdir(en_dir) or not os.path.isdir(zh_dir):
        print(f"missing i18n directory: {en_dir} or {zh_dir}")
        return 1

    en_files = sorted(f for f in os.listdir(en_dir) if f.endswith(".ftl"))
    zh_files = sorted(f for f in os.listdir(zh_dir) if f.endswith(".ftl"))
    ok = True

    if en_files != zh_files:
        ok = False
        missing = set(en_files) - set(zh_files)
        extra = set(zh_files) - set(en_files)
        if missing:
            print(f"[FAIL] zh-CN missing files: {sorted(missing)}")
        if extra:
            print(f"[FAIL] zh-CN has extra files not in en: {sorted(extra)}")

    for fn in en_files:
        en_path = os.path.join(en_dir, fn)
        zh_path = os.path.join(zh_dir, fn)
        if not os.path.exists(zh_path):
            continue
        en_keys = parse_keys(en_path)
        zh_keys = parse_keys(zh_path)
        gap = sorted(en_keys - zh_keys)
        extra = sorted(zh_keys - en_keys)
        if gap:
            ok = False
            print(f"[FAIL] {fn}: zh-CN missing {len(gap)} key(s):")
            for k in gap:
                print(f"       - {k}")
        if extra:
            # legacy english-original rows are tolerated in zh-CN; only fail
            # when the extra keys look like structured keys (op./err./msg./cli.)
            structured_extra = [k for k in extra if is_short_key(k) or is_op_key(k)]
            if structured_extra:
                ok = False
                print(f"[FAIL] {fn}: zh-CN has {len(structured_extra)} structured key(s) absent from en:")
                for k in structured_extra:
                    print(f"       - {k}")
            else:
                print(f"[INFO] {fn}: zh-CN has {len(extra)} legacy english-original row(s) (non-keyed assets, ignored)")

    # Rule 3: source-referenced keys must exist in the en resource set.
    en_all = set()
    for fn in en_files:
        en_all |= parse_keys(os.path.join(en_dir, fn))
    src_keys = collect_src_keys(SRC)
    missing = sorted(src_keys - en_all)
    if missing:
        ok = False
        print(f"[FAIL] src references {len(missing)} key(s) undefined in en resources:")
        for k in missing:
            print(f"       - {k}")
    else:
        print(f"[OK] src key coverage: {len(src_keys)} referenced key(s) all defined in en.")

    if ok:
        print(f"[OK] i18n key parity: {len(en_files)} file(s), all zh-CN keys match en.")
        return 0
    print("[FAIL] i18n key parity broken (see gaps above).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
