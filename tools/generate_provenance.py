#!/usr/bin/env python3
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
paths = [ROOT / "reference/python/fip_reference/core.py", ROOT / "reference/javascript/fip-reference.js"]
paths += sorted((ROOT / "conformance/vectors").glob("*.json"))
paths += sorted((ROOT / "conformance/expected-results").glob("*.json"))
out = ROOT / "docs/source-artifact-hashes.sha256"
out.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n" for p in paths))
print(f"Source-derived artifacts: {len(paths)}")

