#!/usr/bin/env python3
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent
profile = json.loads((ROOT / "examples/synthetic-profile.json").read_text())
domain = json.loads((ROOT / "examples/domain-input.json").read_text())
admitted = {key: domain[key] for key in profile["admittedFields"] if key in domain}
ignored = {key: value for key, value in domain.items() if key not in profile["admittedFields"]}
result = {"profileId": profile["profileId"], "version": profile["version"], "admitted": admitted, "ignored": ignored}
print(json.dumps(result, indent=2, sort_keys=True))
