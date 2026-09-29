"""FIP 0.2 authority evaluator. Compilation is out of scope for this milestone."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def grant(result, action_id):
    matches = [item for item in result["grants"] if item["actionId"] == action_id]
    return matches[0]


class AuthorityEvaluatorTest(unittest.TestCase):
    def test_result_is_never_deployable(self):
        for name in (
            "filesystem-read-write.json",
            "rest-get.json",
            "model-inference.json",
            "proxy-mediated-credential.json",
            "prohibition.json",
            "human-approval.json",
            "human-approval-decision.json",
            "multi-binding-action.json",
            "lifted-0.1-exchange.json",
        ):
            result = assess(load(name))
            self.assertEqual(result["compilationDisposition"], "NOT_COMPILED")
            self.assertFalse(result["deployable"])
            self.assertIn("not_compiled", result["codes"])
            self.assertNotEqual(result["compilationDisposition"], "FULL")

    def test_operational_examples_authorize_without_compiling(self):
        for name in (
            "filesystem-read-write.json",
            "rest-get.json",
            "model-inference.json",
            "proxy-mediated-credential.json",
            "multi-binding-action.json",
        ):
            result = assess(load(name))
            self.assertEqual(result["authorityDecision"], "AUTHORIZED", name)
            self.assertNotIn("semantic_only", result["codes"])

    def test_prohibition_dominates_only_the_overlapping_action(self):
        result = assess(load("prohibition.json"))
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertEqual(grant(result, "ReadInspectionOutput")["authorityDecision"], "DENIED")
        self.assertIn("prohibition_dominates", grant(result, "ReadInspectionOutput")["codes"])
        self.assertEqual(grant(result, "ReadInspectionInput")["authorityDecision"], "AUTHORIZED")

    def test_excepted_binding_is_not_dominated(self):
        policy = load("rest-get.json")
        self.assertEqual(assess(policy)["authorityDecision"], "AUTHORIZED")
        for prohibition in policy["prohibitions"]:
            prohibition["bindingPattern"]["exceptBindingIds"] = []
        denied = assess(policy)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIn("prohibition_dominates", grant(denied, "GetWeather")["codes"])

    def test_missing_operational_binding_is_incomplete(self):
        policy = load("filesystem-read-write.json")
        policy["executionBindings"] = []
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("missing_execution_binding", result["codes"])
        self.assertNotEqual(result["authorityDecision"], "AUTHORIZED")

    def test_semantic_only_may_omit_bindings(self):
        policy = load("filesystem-read-write.json")
        policy["mode"] = "semantic-only"
        policy["executionBindings"] = []
        policy["enforcementRequirements"] = []
        for authorization in policy["authorizations"]:
            authorization["requirementIds"] = []
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIn("semantic_only", result["codes"])
        self.assertFalse(result["deployable"])

    def test_approval_withholds_execution_until_a_decision_exists(self):
        policy = load("human-approval.json")
        waiting = assess(policy)
        self.assertEqual(waiting["authorityDecision"], "AUTHORIZED")
        self.assertIn("approval_required", waiting["codes"])
        self.assertFalse(waiting["deployable"])
        satisfied = assess(policy, approvals=[load("human-approval-decision.json")])
        self.assertEqual(satisfied["authorityDecision"], "AUTHORIZED")
        self.assertNotIn("approval_required", satisfied["codes"])
        self.assertFalse(satisfied["deployable"])

    def test_approval_decision_itself_is_not_deployable(self):
        result = assess(load("human-approval-decision.json"))
        self.assertTrue(result["approvalRecord"])
        self.assertFalse(result["deployable"])

    def test_lifted_0_1_exchange_is_semantic_only(self):
        result = assess(load("lifted-0.1-exchange.json"))
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIn("semantic_only", result["codes"])
        self.assertFalse(result["deployable"])

    def test_unknown_version_produces_no_allow(self):
        result = assess({"document": "Exchange"})
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("unknown_fip_version", result["codes"])
        self.assertFalse(result["deployable"])
        raw = assess({"fipVersion": "0.1", "document": "Exchange"})
        self.assertNotEqual(raw["authorityDecision"], "AUTHORIZED")
        self.assertFalse(raw["deployable"])
        self.assertIn("version_0_1_requires_lifter", raw["reasons"])

    def test_author_cannot_stamp_a_deployable_decision(self):
        policy = load("filesystem-read-write.json")
        policy["deployable"] = True
        policy["authorityDecision"] = "AUTHORIZED"
        policy["compilationDisposition"] = "FULL"
        result = assess(policy)
        self.assertFalse(result["deployable"])
        self.assertEqual(result["compilationDisposition"], "NOT_COMPILED")
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")

    def test_obligation_is_not_a_permit(self):
        policy = load("filesystem-read-write.json")
        policy["authorizations"] = []
        result = assess(policy)
        self.assertIn("obligation_is_not_authority", result["codes"])
        self.assertNotEqual(result["authorityDecision"], "AUTHORIZED")

    def test_missing_authority_is_not_permission(self):
        policy = load("filesystem-read-write.json")
        policy["authorities"] = []
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("missing_authority", result["codes"])

    def test_silent_escalation_and_credential_are_denied(self):
        lifted = load("lifted-0.1-exchange.json")
        lifted["exchangeType"] = "Assertion"
        lifted["attemptedEffect"] = "Instruction"
        escalated = assess(lifted)
        self.assertEqual(escalated["authorityDecision"], "DENIED")
        self.assertIn("silent_semantic_escalation", escalated["codes"])
        request = {
            "fipVersion": "0.2",
            "document": "Exchange",
            "status": "ENFORCEMENT CANDIDATE",
            "mode": "semantic-only",
            "exchangeId": "ex-cred",
            "exchangeType": "Request",
            "actor": {"id": "agent-field"},
            "resource": {"id": "mission:InspectionInput"},
            "action": "ReadInspectionInput",
            "purpose": "FieldInspection",
            "credential": {"id": "cred-1"},
        }
        denied = assess(request)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIn("credential_is_not_authorization", denied["codes"])

    def test_failed_purpose_condition_denies_and_missing_input_is_incomplete(self):
        policy = load("filesystem-read-write.json")
        policy["authorizations"][0]["conditions"] = [
            {"conditionId": "c-purpose", "type": "purpose-match", "purpose": "FieldInspection"}
        ]
        exchange = {
            "fipVersion": "0.2",
            "document": "Exchange",
            "status": "ENFORCEMENT CANDIDATE",
            "mode": "operational",
            "exchangeId": "ex-read",
            "exchangeType": "Request",
            "policyId": "pol-files",
            "actor": {"id": "agent-field"},
            "resource": {"id": "mission:InspectionInput"},
            "action": "ReadInspectionInput",
            "purpose": "FieldInspection",
            "authority": {"id": "auth-mission-control", "kind": "direct"},
            "authorization": {"id": "az-files", "validity": "valid"},
            "provenance": {"assertedBy": "agent-field", "traceId": "t"},
        }
        allowed = assess(exchange, policy=policy)
        self.assertEqual(allowed["authorityDecision"], "AUTHORIZED")
        self.assertFalse(allowed["deployable"])
        policy["authorizations"][0]["conditions"][0]["purpose"] = "Inspection"
        denied = assess(exchange, policy=policy)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        policy["scopes"] = [
            {"scopeId": "scope-lab", "dimension": "jurisdictional", "value": "field-lab"}
        ]
        policy["authorizations"][0]["conditions"] = [
            {"conditionId": "c-scope", "type": "scope-match", "scopeId": "scope-lab"}
        ]
        incomplete = assess(exchange, policy=policy)
        self.assertEqual(incomplete["authorityDecision"], "INCOMPLETE")

    def test_expired_validity_denies(self):
        policy = load("filesystem-read-write.json")
        policy["authorizations"][0]["validity"] = {"state": "expired"}
        result = assess(policy)
        self.assertEqual(result["authorityDecision"], "DENIED")
        self.assertIn("validity_expired", result["codes"])

    def test_operational_exchange_does_not_infer_a_missing_policy(self):
        exchange = {
            "fipVersion": "0.2",
            "document": "Exchange",
            "status": "ENFORCEMENT CANDIDATE",
            "mode": "operational",
            "exchangeId": "ex-read",
            "exchangeType": "Request",
            "policyId": "pol-files",
            "actor": {"id": "agent-field"},
            "resource": {"id": "mission:InspectionInput"},
            "action": "ReadInspectionInput",
            "purpose": "Inspection",
            "authority": {"id": "auth-mission-control"},
            "provenance": {"assertedBy": "agent-field", "traceId": "t"},
        }
        result = assess(exchange)
        self.assertEqual(result["authorityDecision"], "INCOMPLETE")
        self.assertIn("companion_policy_not_inferred", result["reasons"])
        self.assertFalse(result["deployable"])

    def test_copy_does_not_mutate_the_loaded_example(self):
        original = load("rest-get.json")
        snapshot = copy.deepcopy(original)
        assess(original)
        self.assertEqual(original, snapshot)


if __name__ == "__main__":
    unittest.main()
