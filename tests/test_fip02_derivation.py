"""Enforcement IR derivation. The consumed IR must match a fresh projection."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess_coverage, project, verify_derivation  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
TARGET = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def binding(ir, binding_id):
    return next(item for item in ir["bindings"] if item["bindingId"] == binding_id)


def requirement(ir, requirement_id):
    return next(item for item in ir["requirements"] if item["requirementId"] == requirement_id)


class DerivationVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_module("openshell_adapter_derivation", TARGET / "adapter.py")
        cls.manifest = json.loads((TARGET / "manifest.json").read_text(encoding="utf-8"))
        cls.profile = json.loads((TARGET / "execution-profile.json").read_text(encoding="utf-8"))
        cls.files = load("openshell-filesystem-read-write.json")
        cls.files_ir = project(cls.files)["operationalIr"]

    def test_exact_regenerated_ir_matches(self):
        verdict = verify_derivation(self.files_ir, self.files)
        self.assertTrue(verdict["matched"])
        shuffled = copy.deepcopy(self.files_ir)
        shuffled["requirements"].reverse()
        shuffled["bindings"].reverse()
        self.assertTrue(verify_derivation(shuffled, self.files)["matched"])

    def test_locator_widening_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        binding(mutated, "in-read")["locator"]["path"] = "/mission"
        self._reject(mutated, self.files)

    def test_ancestor_read_does_not_compile(self):
        document = copy.deepcopy(self.files)
        document["enforcementRequirements"] = [
            item for item in document["enforcementRequirements"] if item["requirementId"] == "req-read"
        ]
        document["enforcementRequirements"][0]["groupId"] = "read-only"
        document["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
        document["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
        document["authorizations"][0]["requirementIds"] = ["req-read"]
        ir = project(document)["operationalIr"]
        self.assertEqual(binding(ir, "in-read")["locator"]["path"], "/mission/input")
        mutated = copy.deepcopy(ir)
        binding(mutated, "in-read")["locator"]["path"] = "/mission"
        coverage = assess_coverage(mutated, self.manifest, self.profile, document=document)
        compiled = self.adapter.compile_policy(
            mutated, coverage, self.manifest, self.profile, document=document
        )
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        self.assertFalse(coverage["deployable"])
        self.assertIsNone(compiled["generatedPolicy"])
        self.assertNotEqual(compiled["compilationDisposition"], "FULL")
        self.assertFalse(compiled["deployable"])

    def test_operation_widening_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        binding(mutated, "in-read")["operation"] = "write"
        self._reject(mutated, self.files)

    def test_stable_binding_id_with_changed_locator_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        self.assertEqual(binding(mutated, "in-read")["bindingId"], "in-read")
        binding(mutated, "in-read")["locator"]["path"] = "/mission/other"
        self._reject(mutated, self.files)

    def test_stable_requirement_id_with_changed_operation_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        self.assertEqual(requirement(mutated, "req-read")["requirementId"], "req-read")
        binding(mutated, "in-read")["operation"] = "write"
        self._reject(mutated, self.files)

    def test_requirement_deletion_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        mutated["requirements"] = [item for item in mutated["requirements"] if item["requirementId"] != "req-write"]
        mutated["groups"][0]["requirementIds"] = ["req-read"]
        mutated["coverage"]["fipGrants"] = ["req-read"]
        self._reject(mutated, self.files)

    def test_requirement_addition_is_rejected_unless_projected(self):
        mutated = copy.deepcopy(self.files_ir)
        extra = copy.deepcopy(requirement(mutated, "req-read"))
        extra["requirementId"] = "req-extra"
        mutated["requirements"].append(extra)
        self._reject(mutated, self.files)
        self.assertTrue(verify_derivation(self.files_ir, self.files)["matched"])

    def test_all_of_to_any_of_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        for item in mutated["requirements"]:
            item["composition"] = "anyOf"
        for item in mutated["groups"]:
            item["composition"] = "anyOf"
        self._reject(mutated, self.files)

    def test_lifetime_widening_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        requirement(mutated, "req-read")["lifetime"] = "revocable"
        binding(mutated, "in-read")["lifetime"] = "revocable"
        self._reject(mutated, self.files)

    def test_resource_and_action_substitution_are_rejected(self):
        resource = copy.deepcopy(self.files_ir)
        binding(resource, "in-read")["resourceId"] = "mission:InspectionOutput"
        self._reject(resource, self.files)
        action = copy.deepcopy(self.files_ir)
        binding(action, "in-read")["actionId"] = "WriteInspectionOutput"
        self._reject(action, self.files)

    def test_substrate_promoted_into_fip_grants_is_rejected(self):
        mutated = copy.deepcopy(self.files_ir)
        mutated["coverage"]["fipGrants"].append("/tmp")
        self._reject(mutated, self.files)

    def test_prohibition_removal_is_rejected(self):
        policy = load("prohibition.json")
        exchange = {
            "fipVersion": "0.2",
            "document": "Exchange",
            "status": "ENFORCEMENT CANDIDATE",
            "mode": "operational",
            "exchangeId": "ex-ReadInspectionInput",
            "exchangeType": "Request",
            "policyId": policy["policyId"],
            "traceId": policy["traceId"],
            "actor": {"id": "agent-field"},
            "resource": {"id": "mission:InspectionInput"},
            "action": "ReadInspectionInput",
            "purpose": "FieldInspection",
            "authority": {"id": "auth-mission-control", "kind": "direct"},
            "authorization": {"id": "az-reads", "validity": "valid"},
            "provenance": policy["provenance"],
        }
        ir = project(exchange, policy=policy)["operationalIr"]
        self.assertTrue(ir["prohibitions"])
        self.assertTrue(verify_derivation(ir, exchange, policy=policy)["matched"])
        mutated = copy.deepcopy(ir)
        mutated["prohibitions"] = []
        verdict = verify_derivation(mutated, exchange, policy=policy)
        self.assertFalse(verdict["matched"])

    def test_trace_metadata_does_not_fail_derivation(self):
        mutated = copy.deepcopy(self.files_ir)
        mutated["traceId"] = "trace-other"
        for item in mutated["requirements"]:
            item["traceId"] = "trace-other"
        mutated["adapterAnnotations"] = {"note": "informational"}
        self.assertTrue(verify_derivation(mutated, self.files)["matched"])

    def test_supplied_ir_cannot_revive_a_decision_without_projection(self):
        expired = copy.deepcopy(self.files)
        expired["validity"] = {"state": "expired"}
        verdict = verify_derivation(self.files_ir, expired)
        self.assertFalse(verdict["matched"])
        self.assertIsNone(verdict["operationalIr"])
        coverage = assess_coverage(self.files_ir, self.manifest, self.profile, document=expired)
        compiled = self.adapter.compile_policy(
            self.files_ir, coverage, self.manifest, self.profile, document=expired
        )
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        self.assertFalse(coverage["deployable"])
        self.assertIsNone(compiled["generatedPolicy"])

    def test_positive_controls_remain_deployable(self):
        names = (
            "openshell-filesystem-read-write.json",
            "openshell-rest-target-restricted.json",
            "openshell-tcp-connect.json",
            "openshell-mcp-tool.json",
        )
        for name in names:
            document = load(name)
            ir = project(document)["operationalIr"]
            coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
            compiled = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
            self.assertEqual(coverage["compilationDisposition"], "FULL", name)
            self.assertTrue(coverage["deployable"], name)
            self.assertIsNotNone(compiled["generatedPolicy"], name)
            self.assertEqual(compiled["compilationDisposition"], "FULL", name)

    def _reject(self, mutated, document):
        verdict = verify_derivation(mutated, document)
        self.assertFalse(verdict["matched"])
        coverage = assess_coverage(mutated, self.manifest, self.profile, document=document)
        compiled = self.adapter.compile_policy(
            mutated, coverage, self.manifest, self.profile, document=document
        )
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        self.assertFalse(coverage["deployable"])
        self.assertNotEqual(coverage["compilationDisposition"], "FULL")
        self.assertIsNone(compiled["generatedPolicy"])
        self.assertEqual(compiled["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", compiled["diagnostics"])


if __name__ == "__main__":
    unittest.main()
