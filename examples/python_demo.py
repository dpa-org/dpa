"""dpa Python bindings example.

Build the extension module first: `cargo build --release --features python`
produces `target/release/dpa.dll`; copy it to `dpa.pyd` (or install it into
site-packages) and this script finds it next to the repository root.
"""

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# Load the locally built extension module from target/release next to this repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "target" / "release"))

import dpa

print("dpa", dpa.__version__)

# 1) Run a flow in memory: Base64 encode, then hex for display.
flow = """
steps:
  - op: dpa:base64:encode
  - op: dpa:hex:encode
"""
print("run:", dpa.run(flow, b"hello dpa"))

# 2) Batch: the same flow applied to several inputs (processed sequentially).
outs = dpa.run_batch(
    "steps:\n  - op: dpa:sha256\n  - op: dpa:hex:encode\n",
    [b"a", b"b", b"c"],
)
print("batch:", outs)

# 3) A flow file plus an input file, written to a temporary directory.
with TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / "hash.yaml").write_text(
        "steps:\n  - op: dpa:sha256\n  - op: dpa:hex:encode\n", encoding="utf-8"
    )
    (tmp / "in.txt").write_bytes(b"abc")
    result = dpa.run_file(
        str(tmp / "hash.yaml"), str(tmp / "in.txt"), output_format="hex"
    )
    print("file:", result)

# 4) Introspect built-in ops.
print("hash ops:", [o["name"] for o in dpa.list_ops("hash")])
print("sha256 args:", dpa.op("dpa:sha256")["args"])
