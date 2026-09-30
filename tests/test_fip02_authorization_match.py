"""Exchange identity must match the authorization that grants the action.

q13c-run-3 accepted mission:Other because the grant matcher compared only
the action. These tests keep that denial in authority evaluation.
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


def request(policy, **overrides):
    body = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-read",
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": "trace-match",
        "actor": {"id": "agent-field", "identity": "id-agent-field"},
        "resource": {"id": "mission:InspectionInput"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"id": "az-files", "validity": {"state": "valid"}},
        "provenance": copy.deepcopy(policy["provenance"]),
    }
    body.update(overrides)
    return body


class AuthorizationMatchTest(unittest.TestCase):
    def test_exact_resource_is_authorized_and_projected(self):
        policy = single_read_policy()
        exchange = request(policy)
        result = assess(exchange, policy=policy)
        projected = project(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIsNotNone(projected["operationalIr"])
        resources = {binding.get("resourceId") for binding in projected["operationalIr"]["bindings"]}
        actions = {binding.get("actionId") for binding in projected["operationalIr"]["bindings"]}
        self.assertEqual(resources, {"mission:InspectionInput"})
        self.assertEqual(actions, {"ReadInspectionInput"})

    def test_substituted_resource_is_denied_without_an_operational_ir(self):
        policy = single_read_policy()
        exchange = request(policy, resource={"id": "mission:Other"})
        result = assess(exchange, policy=policy)
        projected = project(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("resource_mismatch", result["reasons"])
        self.assertIsNone(projected["operationalIr"])
        self.assertNotEqual(projected["authorityDecision"], "AUTHORIZED")

    def test_missing_required_resource_fails_closed(self):
        policy = single_read_policy()
        exchange = request(policy)
        del exchange["resource"]
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertTrue(any("resource" in reason for reason in result["reasons"]))
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_exact_action_is_authorized(self):
        policy = single_read_policy()
        self.assertEqual(assess(request(policy), policy=policy)["authorityDecision"], "AUTHORIZED")

    def test_substituted_action_is_denied(self):
        policy = single_read_policy()
        exchange = request(policy, action="WriteInspectionOutput")
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("action_mismatch", result["reasons"])
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_exact_purpose_is_authorized_and_substituted_purpose_is_denied(self):
        policy = single_read_policy()
        self.assertEqual(assess(request(policy), policy=policy)["authorityDecision"], "AUTHORIZED")
        exchanged = request(policy, purpose="OtherPurpose")
        result = assess(exchanged, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("purpose_mismatch", result["reasons"])
        self.assertIsNone(project(exchanged, policy=policy)["operationalIr"])

    def test_scope_match_and_substitution(self):
        policy = single_read_policy()
        policy["scopes"] = [{"scopeId": "scope-mission", "dimension": "spatial", "value": "inspection"}]
        policy["authorizations"][0]["conditions"] = [
            {"conditionId": "cond-scope", "type": "scope-match", "scopeId": "scope-mission"}
        ]
        matched = request(policy, scope=[{"dimension": "spatial", "value": "inspection"}])
        self.assertEqual(assess(matched, policy=policy)["authorityDecision"], "AUTHORIZED")
        substituted = request(policy, scope=[{"dimension": "spatial", "value": "other"}])
        denied = assess(substituted, policy=policy)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIsNone(project(substituted, policy=policy)["operationalIr"])

    def test_scope_identifiers_use_the_same_exact_comparison(self):
        policy = single_read_policy()
        policy["scopes"] = [{"scopeId": "scope-mission", "dimension": "spatial", "value": "inspection"}]
        policy["authorizations"][0]["scopeIds"] = ["scope-mission"]
        matched = request(policy, scope=[{"dimension": "spatial", "value": "inspection"}])
        self.assertEqual(assess(matched, policy=policy)["authorityDecision"], "AUTHORIZED")
        substituted = request(policy, scope=[{"dimension": "spatial", "value": "other"}])
        denied = assess(substituted, policy=policy)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIn("scope_mismatch", denied["reasons"])
        self.assertIsNone(project(substituted, policy=policy)["operationalIr"])

    def test_actor_substitution_is_denied(self):
        policy = single_read_policy()
        exchange = request(policy, actor={"id": "other-agent", "identity": "id-other"})
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("actor_mismatch", result["reasons"])
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_role_does_not_grant_or_deny_a_consistent_authorization(self):
        policy = single_read_policy()
        labeled = assess(request(policy, role="unrelated-role"), policy=policy)
        unlabeled = assess(request(policy), policy=policy)
        self.assertEqual(labeled["authorityDecision"], "AUTHORIZED")
        self.assertEqual(unlabeled["authorityDecision"], "AUTHORIZED")
        refused = request(policy, role="operator", action="OtherAction")
        self.assertEqual(assess(refused, policy=policy)["authorityDecision"], "DENIED")

    def test_projection_does_not_repair_a_mismatched_resource(self):
        policy = single_read_policy()
        exchange = request(policy, resource={"id": "mission:Other"})
        projected = project(exchange, policy=policy)
        self.assertIsNone(projected["operationalIr"])
        self.assertEqual(projected["authorityDecision"], "DENIED")


if __name__ == "__main__":
    unittest.main()
