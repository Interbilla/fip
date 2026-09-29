#!/usr/bin/env python3
"""Write or check hashes of the frozen FIP 0.1 text artifacts.

The hashed set is text only: the two reference adapters, the conformance
vectors, and the expected-result files. Each hash is SHA-256 of the file
after CRLF is rewritten to LF. Lone CR bytes are preserved. A Windows CRLF
checkout and a Linux LF checkout therefore produce the same digests.

Binary files are not in this set. Hash any future binary with sha256_raw()
from canonical_hash so its newline bytes are left unchanged.

    python tools/generate_provenance.py --check
    python tools/generate_provenance.py
"""

import sys
from pathlib import Path

from canonical_hash import sha256_canonical_text

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/source-artifact-hashes.sha256"


def artifact_paths() -> list[Path]:
    paths = [
        ROOT / "reference/python/fip_reference/core.py",
        ROOT / "reference/javascript/fip-reference.js",
    ]
    paths += sorted((ROOT / "conformance/vectors").glob("*.json"))
    paths += sorted((ROOT / "conformance/expected-results").glob("*.json"))
    return paths


def render() -> str:
    lines = [
        f"{sha256_canonical_text(path)}  {path.relative_to(ROOT).as_posix()}\n"
        for path in artifact_paths()
    ]
    return "".join(lines)


def main(argv: list[str]) -> int:
    generated = render()
    if "--check" in argv:
        published = OUT.read_bytes().replace(b"\r\n", b"\n").decode("ascii")
        if published != generated:
            print("Provenance hashes differ from docs/source-artifact-hashes.sha256", file=sys.stderr)
            return 1
        print(f"Provenance check: PASS ({generated.count(chr(10))} artifacts)")
        return 0
    OUT.write_text(generated, newline="\n")
    print(f"Source-derived artifacts: {generated.count(chr(10))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
