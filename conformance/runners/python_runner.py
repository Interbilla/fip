#!/usr/bin/env python3
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/python"))
from fip_reference import evaluate  # noqa: E402

passed = 0
vectors = sorted((ROOT / "conformance/vectors").glob("*.json"))
for vector in vectors:
    expected = json.loads((ROOT / "conformance/expected-results" / vector.name).read_text())
    actual = evaluate(json.loads(vector.read_text()))
    ok = actual["decision"] == expected["decision"] and actual.get("codes", []) == expected.get("codes", [])
    passed += ok
    if not ok:
        print(f"FAIL {vector.name}: expected={expected} actual={{'decision': actual['decision'], 'codes': actual.get('codes', [])}}")
print(f"Python conformance: {passed}/{len(vectors)}")
raise SystemExit(0 if passed == len(vectors) == 47 else 1)

