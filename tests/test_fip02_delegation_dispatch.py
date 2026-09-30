"""Operational Delegation must reach the existing delegation predicate.

The Q13C run-1 path authorized a Delegation exchange from the action grant
while canDelegate was false. These tests keep that denial at authority
evaluation. They do not add a delegation rule.
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, project  # noqa: E402

POLICY = json.loads((ROOT / "examples" / "fip-0.2" / "filesystem-read-write.json").read_text(encoding="utf-8"))


def single_read_policy():
    policy = copy.deepcopy(POLICY)
    policy["enforcementRequirements"] = [
        item for item in policy["enforcementRequirements"] if item["requirementId"] == "req-read"
    ]
    policy["enforcementRequirements"][0]["groupId"] = "read-only"
    policy["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
    policy["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
    policy["authorizations"][0]["requirementIds"] = ["req-read"]
    policy["obligations"] = []
    return policy


def delegation(policy, **overrides):
    body = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-delegate",
        "exchangeType": "Delegation",
        "policyId": policy["policyId"],
        "traceId": "trace-delegation-dispatch",
        "actor": {"id": "agent-field", "identity": "id-agent-field"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"authorizationId": "az-files", "validity": {"state": "valid"}},
        "delegation": {
            "delegationId": "del-1",
            "from": "mission-control",
            "to": "agent-field",
            "authorityId": "auth-mission-control",
            "canDelegate": False,
        },
        "validity": {"state": "valid"},
        "provenance": copy.deepcopy(policy["provenance"]),
    }
    body.update(overrides)
    return body


class DelegationDispatchTest(unittest.TestCase):
    def test_can_delegate_false_is_not_authorized_on_the_run1_path(self):
        policy = single_read_policy()
        exchange = delegation(policy)
        result = assess(exchange, policy=policy)
        projected = project(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("delegation_requires_explicit_authority", result["codes"])
        self.assertIsNone(projected["operationalIr"])
        self.assertNotEqual(projected["authorityDecision"], "AUTHORIZED")

    def test_can_delegate_false_denies_even_when_authority_kind_is_delegable(self):
        policy = single_read_policy()
        policy["authorities"][0]["kind"] = "delegable"
        exchange = delegation(policy, authority={"id": "auth-mission-control", "kind": "delegable"})
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("delegation_requires_explicit_authority", result["codes"])
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_can_delegate_true_authorizes_a_bounded_operational_delegation(self):
        policy = single_read_policy()
        policy["authorities"][0]["kind"] = "delegable"
        exchange = delegation(
            policy,
            authority={"id": "auth-mission-control", "kind": "delegable"},
            delegation={
                "delegationId": "del-1",
                "from": "mission-control",
                "to": "agent-field",
                "authorityId": "auth-mission-control",
                "canDelegate": True,
            },
        )
        result = assess(exchange, policy=policy)
        projected = project(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIsNotNone(projected["operationalIr"])
        self.assertFalse(result["deployable"])

    def test_absent_can_delegate_uses_delegable_kind(self):
        policy = single_read_policy()
        policy["authorities"][0]["kind"] = "delegable"
        body = delegation(policy, authority={"id": "auth-mission-control", "kind": "delegable"})
        del body["delegation"]["canDelegate"]
        self.assertEqual(assess(body, policy=policy)["authorityDecision"], "AUTHORIZED")
        direct = single_read_policy()
        refused = delegation(direct)
        del refused["delegation"]["canDelegate"]
        denied = assess(refused, policy=direct)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIn("delegation_requires_explicit_authority", denied["codes"])

    def test_expired_and_revoked_operational_delegation_are_denied(self):
        policy = single_read_policy()
        policy["authorities"][0]["kind"] = "delegable"
        for state, code in (("expired", "validity_expired"), ("revoked", "validity_revoked")):
            exchange = delegation(
                policy,
                validity={"state": state},
                authority={"id": "auth-mission-control", "kind": "delegable"},
                delegation={
                    "delegationId": "del-1",
                    "from": "mission-control",
                    "to": "agent-field",
                    "authorityId": "auth-mission-control",
                    "canDelegate": True,
                },
            )
            result = assess(exchange, policy=policy)
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(code, result["codes"])
            self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_missing_delegation_authority_fails_closed(self):
        policy = single_read_policy()
        exchange = delegation(policy)
        del exchange["authority"]
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertTrue(any(reason.startswith("missing_fields:") and "authority" in reason for reason in result["reasons"]))
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_operational_requirements_still_apply_after_a_permitted_delegation(self):
        policy = single_read_policy()
        policy["authorities"][0]["kind"] = "delegable"
        permitted = {
            "authority": {"id": "auth-mission-control", "kind": "delegable"},
            "delegation": {
                "delegationId": "del-1",
                "from": "mission-control",
                "to": "agent-field",
                "authorityId": "auth-mission-control",
                "canDelegate": True,
            },
        }
        missing_provenance = delegation(policy, **permitted)
        del missing_provenance["provenance"]
        provenance = assess(missing_provenance, policy=policy)
        self.assertEqual(provenance["authorityDecision"], "INCOMPLETE")
        self.assertIn("provenance", provenance["reasons"])

        missing_policy = assess(delegation(policy, **permitted), policy=None)
        self.assertEqual(missing_policy["authorityDecision"], "INCOMPLETE")
        self.assertIn("companion_policy_not_inferred", missing_policy["reasons"])

        mismatched = delegation(policy, **permitted)
        mismatched["policyId"] = "pol-other"
        mismatch = assess(mismatched, policy=policy)
        self.assertEqual(mismatch["authorityDecision"], "INCOMPLETE")
        self.assertIn("policy_mismatch", mismatch["reasons"])

    def test_semantic_only_can_delegate_false_remains_denied(self):
        policy = single_read_policy()
        exchange = delegation(policy, mode="semantic-only")
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("delegation_requires_explicit_authority", result["codes"])


if __name__ == "__main__":
    unittest.main()
