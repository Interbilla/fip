"""Validity use rule for authority-relevant objects.

The states come from the schema enum. Absence keeps the specified behavior
for each object: a required policy Validity that is missing is incomplete,
while an optional Authorization or Delegation Validity that is missing does
not by itself deny.
"""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
TARGET = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"
NON_VALID = ("expired", "revoked", "superseded", "not-yet-valid")
CODES = {
    "expired": "validity_expired",
    "revoked": "validity_revoked",
    "superseded": "validity_superseded",
    "not-yet-valid": "validity_not_yet_valid",
}


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def load_adapter():
    spec = importlib.util.spec_from_file_location("openshell_adapter_validity", TARGET / "adapter.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def delegation(state=None, include=True):
    document = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "semantic-only",
        "exchangeId": "ex-delegate",
        "exchangeType": "Delegation",
        "actor": {"id": "agent-field"},
        "delegation": {"delegationId": "del-1", "from": "mission-control", "to": "agent-field", "canDelegate": True},
        "action": "ReadInspectionInput",
        "authority": {"id": "auth-mission-control", "kind": "delegable"},
        "provenance": {
            "assertedBy": "mission-control",
            "derivedFrom": ["trace-validity"],
            "independent": True,
            "traceId": "trace-validity",
        },
    }
    if include:
        document["validity"] = {"state": state or "valid"}
    return document


def approval(state=None, include=True, value="approved"):
    decision = {
        "decisionId": "dec-approve-delete",
        "kind": "approval",
        "value": value,
        "requirementId": "req-delete",
    }
    if include:
        decision["validity"] = {"state": state or "valid"}
    return {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-approve-delete",
        "exchangeType": "Decision",
        "policyId": "pol-approval",
        "traceId": "trace-approval-decision",
        "actor": {"id": "approver-mission"},
        "decision": decision,
        "provenance": {
            "assertedBy": "approver-mission",
            "derivedFrom": ["trace-approval"],
            "independent": True,
            "traceId": "trace-approval-decision",
        },
    }


class ValidityUseTest(unittest.TestCase):
    def test_authorization_validity_valid_and_absent_remain_usable(self):
        policy = load("filesystem-read-write.json")
        self.assertEqual(policy["authorizations"][0]["validity"]["state"], "valid")
        self.assertEqual(assess(policy)["authorityDecision"], "AUTHORIZED")
        absent = copy.deepcopy(policy)
        del absent["authorizations"][0]["validity"]
        self.assertEqual(assess(absent)["authorityDecision"], "AUTHORIZED")

    def test_authorization_non_valid_states_deny_without_an_operational_ir(self):
        for state in NON_VALID:
            policy = load("filesystem-read-write.json")
            policy["authorizations"][0]["validity"] = {"state": state}
            result = assess(policy)
            projected = project(policy)
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(CODES[state], result["codes"])
            self.assertIsNone(projected["operationalIr"])
            self.assertNotEqual(projected["authorityDecision"], "AUTHORIZED")

    def test_policy_validity_valid_remains_authorized(self):
        policy = load("openshell-filesystem-read-write.json")
        self.assertEqual(policy["validity"]["state"], "valid")
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIsNotNone(project(policy)["operationalIr"])

    def test_policy_validity_absent_is_incomplete(self):
        policy = load("openshell-filesystem-read-write.json")
        del policy["validity"]
        result = assess(policy)
        projected = project(policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("validity", result["reasons"])
        self.assertNotIn("validity_expired", result["codes"])
        self.assertIsNone(projected["operationalIr"])

    def test_policy_non_valid_states_deny_and_emit_no_deployable_policy(self):
        adapter = load_adapter()
        manifest = json.loads((TARGET / "manifest.json").read_text(encoding="utf-8"))
        profile = json.loads((TARGET / "execution-profile.json").read_text(encoding="utf-8"))
        for state in NON_VALID:
            policy = load("openshell-filesystem-read-write.json")
            policy["validity"] = {"state": state}
            result = assess(policy)
            projected = project(policy)
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(CODES[state], result["codes"])
            self.assertIn("policy_validity", result["reasons"])
            self.assertNotIn("missing_authority", result["codes"])
            self.assertIsNone(projected["operationalIr"])
            self.assertNotEqual(projected["authorityDecision"], "AUTHORIZED")
            compiled = adapter.compile_policy(
                None,
                {
                    "authorityDecision": result["authorityDecision"],
                    "compilationDisposition": "NOT_COMPILED",
                    "deployable": False,
                },
                manifest,
                profile,
            )
            self.assertIsNone(compiled["generatedPolicy"])
            self.assertFalse(compiled["deployable"])
            self.assertNotEqual(compiled["compilationDisposition"], "FULL")

    def test_delegation_validity_valid_and_absent_follow_delegation_rules(self):
        valid = assess(delegation("valid"))
        self.assertEqual(valid["authorityDecision"], "AUTHORIZED")
        self.assertIn("semantic_only", valid["codes"])
        self.assertFalse(valid["deployable"])
        absent = assess(delegation(include=False))
        self.assertEqual(absent["authorityDecision"], "AUTHORIZED")
        self.assertIn("semantic_only", absent["codes"])
        refused = delegation(include=False)
        refused["delegation"]["canDelegate"] = False
        denied = assess(refused)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIn("delegation_requires_explicit_authority", denied["codes"])

    def test_delegation_non_valid_states_deny(self):
        for state in NON_VALID:
            result = assess(delegation(state))
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(CODES[state], result["codes"])
            self.assertNotIn("semantic_only", result["codes"])
            self.assertFalse(result["deployable"])
            self.assertIsNone(project(delegation(state))["operationalIr"])

    def test_consequential_exchange_validity_denies_use(self):
        policy = load("filesystem-read-write.json")
        exchange = {
            "fipVersion": "0.2",
            "document": "Exchange",
            "status": "ENFORCEMENT CANDIDATE",
            "mode": "operational",
            "exchangeId": "ex-read",
            "exchangeType": "Request",
            "policyId": policy["policyId"],
            "traceId": "trace-files",
            "actor": {"id": "agent-field"},
            "resource": {"id": "mission:InspectionInput"},
            "action": "ReadInspectionInput",
            "purpose": "FieldInspection",
            "authority": {"id": "auth-mission-control", "kind": "direct"},
            "authorization": {"id": "az-files", "validity": "valid"},
            "validity": {"state": "revoked"},
            "provenance": {"assertedBy": "agent-field", "traceId": "trace-files"},
        }
        result = assess(exchange, policy=policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("validity_revoked", result["codes"])
        self.assertIsNone(project(exchange, policy=policy)["operationalIr"])

    def test_authorization_reference_non_valid_states_deny(self):
        policy = load("filesystem-read-write.json")
        for state in NON_VALID:
            exchange = {
                "fipVersion": "0.2",
                "document": "Exchange",
                "status": "ENFORCEMENT CANDIDATE",
                "mode": "operational",
                "exchangeId": "ex-read",
                "exchangeType": "Request",
                "policyId": policy["policyId"],
                "traceId": "trace-files",
                "actor": {"id": "agent-field"},
                "resource": {"id": "mission:InspectionInput"},
                "action": "ReadInspectionInput",
                "purpose": "FieldInspection",
                "authority": {"id": "auth-mission-control", "kind": "direct"},
                "authorization": {"id": "az-files", "validity": state},
                "provenance": {"assertedBy": "agent-field", "traceId": "trace-files"},
            }
            result = assess(exchange, policy=policy)
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(CODES[state], result["codes"])

    def test_valid_approval_decision_satisfies_require_approval(self):
        decision = approval("valid")
        result = assess(decision)
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertTrue(result["approvalRecord"])
        self.assertFalse(result["deployable"])
        self.assertIsNone(project(decision)["operationalIr"])
        policy = load("human-approval.json")
        satisfied = assess(policy, approvals=[decision])
        self.assertEqual(satisfied["authorityDecision"], "AUTHORIZED")
        self.assertNotIn("approval_required", satisfied["codes"])

    def test_approval_decision_without_validity_stays_incomplete(self):
        result = assess(approval(include=False))
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("approval_required", result["codes"])
        self.assertFalse(result.get("approvalRecord"))

    def test_rejected_approval_value_stays_incomplete(self):
        result = assess(approval("valid", value="rejected"))
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("approval_required", result["codes"])

    def test_non_valid_approval_decisions_do_not_authorize(self):
        policy = load("human-approval.json")
        for state in NON_VALID:
            decision = approval(state)
            result = assess(decision)
            self.assertEqual(result["authorityDecision"], "DENIED", state)
            self.assertIn(CODES[state], result["codes"])
            self.assertFalse(result.get("approvalRecord"))
            self.assertFalse(result["deployable"])
            self.assertIsNone(project(decision)["operationalIr"])
            waiting = assess(policy, approvals=[decision])
            self.assertIn("approval_required", waiting["codes"])
            self.assertIsNone(project(policy, approvals=[decision])["operationalIr"])

    def test_unresolved_validity_window_stays_incomplete(self):
        policy = load("filesystem-read-write.json")
        policy["conditions"] = [{"conditionId": "c-window", "type": "validity-window"}]
        policy["enforcementRequirements"][0]["conditionIds"] = ["c-window"]
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIsNone(project(policy)["operationalIr"])

    def test_inconsistent_validity_interval_is_incomplete(self):
        policy = load("filesystem-read-write.json")
        policy["validity"] = {
            "state": "valid",
            "notBefore": "2024-02-02T00:00:00Z",
            "notAfter": "2024-01-01T00:00:00Z",
        }
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("policy_validity", result["reasons"])
        self.assertIsNone(project(policy)["operationalIr"])


if __name__ == "__main__":
    unittest.main()
