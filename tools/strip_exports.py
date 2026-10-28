#!/usr/bin/env python3
"""Export-surface hardening for the dpa cdylib.

Rust cdylibs re-export every #[no_mangle] symbol, and MSVC .def files cannot
suppress dllexport-flagged symbols. One such symbol (bz_internal_error, from
the upstream bzip2-sys lib.rs) therefore leaks into the DLL export table even
though the whitelist in dpa.def declares nothing.

This script zeroes the PE export directory of the given DLL so the binary
exports no symbols at all (the dpa core has no C ABI contract; plugin ABI
symbols live inside plugin crates). Run it after `cargo build`; CI may call it
before signing/packaging.

Usage:
    python tools/strip_exports.py [path-to-dpa.dll]
"""

import argparse
import struct
import sys


def strip_exports(dll_path: str) -> int:
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    # Data directory begins after the optional header fixed part; export
    # directory is entry 0.
    dd_off = opt + (96 if magic == 0x10B else 112)
    rva, size = struct.unpack_from("<II", data, dd_off)
    if rva == 0 and size == 0:
        print(f"{dll_path}: export directory already empty")
        return 0

    struct.pack_into("<II", data, dd_off, 0, 0)
    with open(dll_path, "wb") as f:
        f.write(data)
    print(f"{dll_path}: removed export directory (rva={rva:#x}, size={size:#x})")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"target\debug\dpa.dll")
    args = parser.parse_args()
    sys.exit(0 if strip_exports(args.dll) else 0)


if __name__ == "__main__":
    main()
