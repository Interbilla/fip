#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
from fip_reference import evaluate  # noqa: E402

actor = {"id": "synthetic:agent", "role": "operator"}
resource = {"id": "synthetic:resource-a"}
provenance = {"assertedBy": "synthetic:registry", "derivedFrom": ["synthetic:record"], "independent": True}
base = {"actor": actor, "resource": resource, "action": "inspect", "purpose": "maintenance", "provenance": provenance}
cases = {
    "recommendation-not-authorization": {**base, "exchangeId": "EX-A", "exchangeType": "Recommendation", "attemptedEffect": "Authorization"},
    "self-asserted-authority": {**base, "exchangeId": "EX-B", "exchangeType": "Request", "authoritySource": "free_text", "authority": {"id": "self"}},
    "bounded-delegation": {**base, "exchangeId": "EX-C", "exchangeType": "Delegation", "authority": {"id": "synthetic:authority", "kind": "delegable"}, "authorization": {"id": "synthetic:authorization", "validity": "valid"}, "delegation": {"from": "synthetic:owner", "to": "synthetic:agent", "authorizedChain": True, "canDelegate": True}, "policy": {"id": "synthetic:policy"}, "scope": [{"dimension": "jurisdictional", "value": "synthetic-lab"}]},
    "expired-validity": {**base, "exchangeId": "EX-D", "exchangeType": "Request", "authorization": {"id": "synthetic:auth", "validity": "expired"}},
    "evidence-not-provenance": {**base, "exchangeId": "EX-E", "exchangeType": "Decision", "evidence": [{"id": "synthetic:evidence"}], "provenance": {}, "decision": {"value": "allow"}},
    "unknown-extension-no-authority": {**base, "exchangeId": "EX-F", "exchangeType": "Request", "extensions": [{"namespace": "synthetic:unknown", "recognized": False, "claims": {"authority": "invented"}}]},
    "cross-bound-authority": {**base, "exchangeId": "EX-H", "exchangeType": "Request", "expectedPurpose": "maintenance", "purpose": "unrelated-use", "authorization": {"id": "synthetic:auth", "validity": "valid"}, "authority": {"id": "synthetic:authority"}, "normative": {"state": "allowed"}}
}
expected = {"recommendation-not-authorization": "DENIED", "self-asserted-authority": "DENIED", "bounded-delegation": "PERMITTED", "expired-validity": "DENIED", "evidence-not-provenance": "ESCALATE", "unknown-extension-no-authority": "DENIED", "cross-bound-authority": "DENIED"}
for name, exchange in cases.items():
    actual = evaluate(exchange)["decision"]
    assert actual == expected[name], (name, actual, expected[name])
    print(f"PASS {name}: {actual}")
print("PASS descriptive-domain-assertion: see gocp/project.py admitted/ignored output")
