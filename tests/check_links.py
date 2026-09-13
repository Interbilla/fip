#!/usr/bin/env python3
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
missing = []
for doc in ROOT.rglob("*.md"):
    text = doc.read_text()
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = (doc.parent / target.split("#", 1)[0]).resolve()
        if not path.exists():
            missing.append(f"{doc.relative_to(ROOT)} -> {target}")
if missing:
    print("\n".join(missing))
    raise SystemExit(1)
print("Internal links: PASS")

