#!/usr/bin/env python3
"""FIP 0.2 validated baseline provenance.

This is not the frozen FIP 0.1 provenance in
docs/source-artifact-hashes.sha256. It covers the validated 0.2 baseline.
It does not freeze those artifacts forever, and it does not rewrite the
0.1 manifest.

Text artifacts are hashed with the canonical rule: CRLF becomes LF, and a
lone CR is preserved. No binary artifacts are in this set.

    python tools/generate_fip02_provenance.py --check
    python tools/generate_fip02_provenance.py
"""

import sys
from pathlib import Path

from canonical_hash import sha256_canonical_text

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/fip-0.2-artifact-hashes.sha256"
HEADER = "# FIP 0.2 validated baseline provenance\n"

EXCLUDED = {
    "conformance/fip-0.2/openshell/m4/m4-report.json",
    "conformance/fip-0.2/openshell/m4/openshell.log",
}


def artifact_paths() -> list[Path]:
    roots = [
        ROOT / "docs/specification/fip-0.2",
        ROOT / "examples/fip-0.2",
        ROOT / "reference/fip-0.2",
        ROOT / "conformance/fip-0.2",
        ROOT / "integration/openshell-m4",
    ]
    paths = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative in EXCLUDED:
                continue
            paths.append(path)
    paths += sorted((ROOT / "tests").glob("test_fip02_*.py"))
    paths.append(ROOT / "tools/canonical_hash.py")
    return sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix())


def render() -> str:
    lines = [
        f"{sha256_canonical_text(path)}  {path.relative_to(ROOT).as_posix()}\n"
        for path in artifact_paths()
    ]
    return HEADER + "".join(lines)


def main(argv: list[str]) -> int:
    generated = render()
    count = generated.count("\n") - 1
    if "--check" in argv:
        published = OUT.read_bytes().replace(b"\r\n", b"\n").decode("ascii")
        if published != generated:
            print("FIP 0.2 provenance hashes differ from docs/fip-0.2-artifact-hashes.sha256", file=sys.stderr)
            return 1
        print(f"FIP 0.2 validated baseline provenance: PASS ({count} artifacts)")
        return 0
    OUT.write_text(generated, newline="\n")
    print(f"FIP 0.2 validated baseline provenance: {count} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
