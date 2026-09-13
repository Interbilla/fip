#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
skip = {"LICENSE"}
patterns = {
    "secret": re.compile(r"(?i)(sk-[a-z0-9_-]{16,}|bearer\s+[a-z0-9._-]{16,}|password\s*[:=]|api[_-]?key\s*[:=])"),
    "private_ip": re.compile(r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)"),
    "local_path": re.compile(r"(?:/home/[^/\s]+/|[A-Z]:\\\\)"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "customer_term": re.compile(r"(?i)\b(LADWP|USFS|Kiewit|Vantage)\b"),
}
findings = []
approved_public_values = {"info@interbilla.com", "echow@interbilla.com"}
for path in ROOT.rglob("*"):
    if path.resolve() == Path(__file__).resolve() or not path.is_file() or path.name in skip or ".git" in path.parts or path.stat().st_size > 2_000_000:
        continue
    try: text = path.read_text()
    except UnicodeDecodeError: continue
    for kind, pattern in patterns.items():
        for match in pattern.finditer(text):
            if match.group(0) in approved_public_values:
                continue
            findings.append((kind, str(path.relative_to(ROOT)), text.count("\n", 0, match.start()) + 1, match.group(0)))
if findings:
    for row in findings: print(": ".join(map(str, row)))
    raise SystemExit(1)
print("Public release sensitive-data scan: PASS (0 findings)")
