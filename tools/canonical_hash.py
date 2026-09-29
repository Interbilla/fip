"""SHA-256 helpers for repository integrity checks.

Text artifacts are hashed after the byte sequence CR LF is replaced by LF.
Lone CR bytes are preserved. No other byte is changed.

Binary artifacts must use sha256_raw(). generate_provenance.py hashes only
known text artifacts (the two frozen adapters, conformance vectors, and
expected results) and therefore uses sha256_canonical_text().
"""

import hashlib
from pathlib import Path


def canonical_text_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def sha256_canonical_text(path: Path) -> str:
    return hashlib.sha256(canonical_text_bytes(path)).hexdigest()


def sha256_raw(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
