"""OpenShell v0.1.2 capability profile. No policy YAML is emitted."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess_coverage, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
PROFILE = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"
SCHEMA_DIR = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
FORBIDDEN = {
    "openshell", "landlock", "seccomp", "network_policies", "filesystem_policy",
    "kubernetes", "opa", "rules", "yaml",
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def keys_of(value, found=None):
    found = found if found is not None else set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(str(key).lower())
            keys_of(item, found)
    elif isinstance(value, list):
        for item in value:
            keys_of(item, found)
    return found


def exchange_for(policy, action, resource):
    return {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-" + action,
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": policy["traceId"],
        "actor": {"id": "agent-field"},
        "resource": {"id": resource},
        "action": action,
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"id": policy["authorizations"][0]["authorizationId"], "validity": "valid"},
        "provenance": policy["provenance"],
    }


class OpenShellProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import jsonschema
        from referencing import Registry, Resource

        common = load_json(SCHEMA_DIR / "common.schema.json")
        schema = load_json(SCHEMA_DIR / "capability-manifest.schema.json")
        registry = Registry().with_resources([
            ("urn:fip:0.2:common", Resource.from_contents(common)),
        ])
        cls.validator = jsonschema.Draft202012Validator(schema, registry=registry)
        profile_schema = load_json(SCHEMA_DIR / "compilation-profile.schema.json")
        cls.profile_validator = jsonschema.Draft202012Validator(profile_schema, registry=registry)
        cls.manifest = load_json(PROFILE / "manifest.json")
        cls.profile = load_json(PROFILE / "execution-profile.json")
        cls.validator.validate(cls.manifest)
        cls.profile_validator.validate(cls.profile)

    def assess(self, ir):
        before_ir = copy.deepcopy(ir)
        before_manifest = copy.deepcopy(self.manifest)
        result = assess_coverage(ir, self.manifest, self.profile)
        self.assertEqual(ir, before_ir)
        self.assertEqual(self.manifest, before_manifest)
        self.assertFalse(keys_of(result) & FORBIDDEN)
        self.assertFalse(result["deployable"])
        self.assertNotEqual(result["compilationDisposition"], "FULL")
        return result

    def status(self, result):
        return {item["requirementId"]: item["status"] for item in result["requirements"]}

    def test_profile_does_not_overclaim(self):
        manifest = self.manifest
        self.assertEqual(manifest["targetVersion"], "0.1.2")
        self.assertNotIn("lifetimes", manifest)
        lifetimes = {item["capabilityId"]: item["lifetimes"] for item in manifest["capabilities"]}
        self.assertEqual(lifetimes["filesystem"], ["establishment-bound"])
        self.assertEqual(lifetimes["process"], ["establishment-bound"])
        self.assertEqual(lifetimes["network"], ["establishment-bound", "revocable"])
        self.assertNotIn("model", manifest["kinds"])
        self.assertNotIn("credential", manifest["kinds"])
        self.assertNotIn("process", manifest["kinds"])
        self.assertNotIn("correlated", manifest["auditStrengths"])
        self.assertFalse(manifest["precision"]["modelId"])
        self.assertFalse(manifest["precision"]["traceCorrelation"])
        self.assertEqual(manifest["precision"]["credentialDisclosures"], ["proxy-mediated"])
        self.assertEqual(manifest["precision"]["credentialBinding"]["required"], ["host", "port"])
        self.assertFalse(manifest["approval"]["actionGate"])
        self.assertTrue(manifest["approval"]["policyMutation"])
        self.assertEqual(manifest["dangerousDefaults"], [])
        self.assertFalse(keys_of(manifest) & FORBIDDEN)
        writes = {
            item["locator"]["path"]
            for item in manifest["substrate"]
            if item.get("operation") == "write"
        }
        self.assertEqual(writes, {"/tmp", "/dev/null"})

    def test_filesystem_read_write_is_rejected_for_baseline_and_audit(self):
        result = self.assess(project(load_json(EXAMPLES / "filesystem-read-write.json"))["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["codes"], ["unsupported_requirement"])
        self.assertNotIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(self.status(result), {"req-read": "unenforced", "req-write": "unenforced"})
        self.assertTrue(all(item["required"] == "correlated" and item["status"] == "unenforced" for item in result["audit"]))
        self.assertEqual(result["selectedRequirementIds"], [])
        baseline = result["coverage"]["targetBaseline"]
        self.assertIn("/tmp", [item.get("locator", {}).get("path") for item in baseline])
        self.assertTrue(all(item["acceptance"] == "accepted" for item in baseline))
        self.assertTrue(all(item["status"] == "baseline" and item["authorityBearing"] is False for item in baseline))
        self.assertNotIn("/tmp", json.dumps(result["coverage"]["fipGrants"]))

    def test_rest_get_is_rejected_for_lifetime_and_baseline(self):
        result = self.assess(project(load_json(EXAMPLES / "rest-get.json"))["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "PARTIAL")
        self.assertEqual(result["codes"], ["unsupported_requirement"])
        self.assertNotIn("lifetime_mismatch", result["codes"])
        self.assertEqual(self.status(result), {"req-weather": "unenforced", "req-no-other-network": "enforced"})
        self.assertEqual(result["selectedRequirementIds"], ["req-no-other-network"])
        audit = {item["requirementId"]: item for item in result["audit"]}
        self.assertEqual(audit["req-weather"]["status"], "unenforced")
        self.assertEqual(audit["req-no-other-network"]["required"], "target-native")
        self.assertEqual(audit["req-no-other-network"]["status"], "enforced")

    def test_model_inference_is_rejected_before_model_kind(self):
        result = self.assess(project(load_json(EXAMPLES / "model-inference.json"))["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["codes"], ["lifetime_mismatch", "subset_not_demonstrated"])
        self.assertEqual(self.status(result), {"req-model": "rejected", "req-provider": "rejected"})
        self.assertEqual(result["selectedRequirementIds"], [])

    def test_proxy_credential_is_not_claimed(self):
        result = self.assess(project(load_json(EXAMPLES / "proxy-mediated-credential.json"))["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["codes"], ["subset_not_demonstrated", "unsupported_requirement"])
        self.assertNotIn("lifetime_mismatch", result["codes"])
        self.assertEqual(
            self.status(result),
            {"req-credential-use": "rejected", "req-no-other-credentials": "unenforced"},
        )
        self.assertEqual(result["prohibitions"][0]["status"], "unenforced")

    def test_multi_binding_is_rejected(self):
        result = self.assess(project(load_json(EXAMPLES / "multi-binding-action.json"))["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["codes"], ["unsupported_requirement", "subset_not_demonstrated"])
        self.assertEqual(
            self.status(result),
            {"req-connect": "unenforced", "req-credential": "rejected", "req-get": "unenforced"},
        )
        self.assertEqual(result["groups"][0]["status"], "rejected")
        self.assertEqual(result["selectedRequirementIds"], [])

    def test_prohibition_slice_keeps_the_deny_and_rejects_the_permit_audit(self):
        policy = load_json(EXAMPLES / "prohibition.json")
        whole = project(policy)
        self.assertIsNone(whole["operationalIr"])
        allowed = exchange_for(policy, "ReadInspectionInput", "mission:InspectionInput")
        result = self.assess(project(allowed, policy=policy)["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "PARTIAL")
        self.assertEqual(result["codes"], ["unsupported_requirement"])
        self.assertNotIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(self.status(result), {"req-read-input": "unenforced", "req-deny-output": "enforced"})
        self.assertEqual(result["prohibitions"][0]["status"], "enforced")
        self.assertEqual(result["selectedRequirementIds"], ["req-deny-output"])

    def test_human_approval_is_not_an_action_gate(self):
        policy = load_json(EXAMPLES / "human-approval.json")
        waiting = project(policy)
        self.assertIsNone(waiting["operationalIr"])
        unassessed = assess_coverage(waiting, self.manifest)
        self.assertEqual(unassessed["compilationDisposition"], "NOT_COMPILED")
        self.assertEqual(unassessed["codes"], ["not_compiled"])
        decision = load_json(EXAMPLES / "human-approval-decision.json")
        result = self.assess(project(policy, approvals=[decision])["operationalIr"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["codes"], ["subset_not_demonstrated"])
        self.assertNotIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(self.status(result), {"req-delete": "rejected"})
        self.assertEqual(result["requirements"][0]["effect"], "require-approval")

    def test_unaccepted_writable_substrate_still_rejects(self):
        ir = project(load_json(EXAMPLES / "filesystem-read-write.json"))["operationalIr"]
        result = assess_coverage(ir, self.manifest)
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", result["codes"])
        tmp = next(item for item in result["coverage"]["targetBaseline"] if item.get("substrateId") == "runtime-tmp")
        self.assertEqual(tmp["acceptance"], "unaccepted")
        self.assertNotIn("/tmp", result["coverage"]["fipGrants"])
