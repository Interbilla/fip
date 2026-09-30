"""Capability manifest coverage. No target policy is emitted."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess_coverage, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
MANIFESTS = ROOT / "conformance" / "fip-0.2" / "manifests"
SCHEMA_DIR = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
FORBIDDEN = {
    "openshell", "landlock", "seccomp", "network_policies", "filesystem_policy",
    "kubernetes", "opa", "rules", "yaml",
}


def load_example(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def load_manifest(name):
    return json.loads((MANIFESTS / name).read_text(encoding="utf-8"))


_SOURCES = {}


def ir_for(name):
    document = load_example(name)
    ir = project(document)["operationalIr"]
    if isinstance(ir, dict):
        _SOURCES[id(ir)] = document
    return ir


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


def validator(schema_name):
    import jsonschema
    from referencing import Registry, Resource

    common = json.loads((SCHEMA_DIR / "common.schema.json").read_text(encoding="utf-8"))
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    registry = Registry().with_resources([
        ("urn:fip:0.2:common", Resource.from_contents(common)),
    ])
    return jsonschema.Draft202012Validator(schema, registry=registry)


class CoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assessment_validator = validator("coverage-assessment.schema.json")
        cls.manifest_validator = validator("capability-manifest.schema.json")
        for path in MANIFESTS.glob("*.json"):
            cls.manifest_validator.validate(json.loads(path.read_text(encoding="utf-8")))

    def assess(self, ir, manifest, document=None, policy=None, approvals=None):
        before = copy.deepcopy(ir)
        if document is None and policy is None and isinstance(ir, dict):
            document = _SOURCES.get(id(ir))
        result = assess_coverage(ir, manifest, document=document, policy=policy, approvals=approvals)
        self.assertEqual(ir, before)
        self.assertFalse(keys_of(result) & FORBIDDEN)
        if result["compilationDisposition"] != "NOT_COMPILED":
            self.assessment_validator.validate(result)
        self.assertEqual(result["authorityDecision"], ir["authorityDecision"])
        return result

    def test_exact_filesystem_read_is_enforced_and_full(self):
        result = self.assess(ir_for("filesystem-read-write.json"), load_manifest("full-capability-test-target.json"))
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertTrue(result["deployable"])
        statuses = {item["requirementId"]: item["status"] for item in result["requirements"]}
        self.assertEqual(statuses["req-read"], "enforced")
        self.assertEqual(statuses["req-write"], "enforced")
        self.assertEqual(result["groups"][0]["status"], "enforced")
        self.assertEqual(result["groups"][0]["composition"], "allOf")
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])

    def test_read_write_bundle_rejects_a_read_grant(self):
        result = self.assess(ir_for("filesystem-read-write.json"), load_manifest("filesystem-only-target.json"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertFalse(result["deployable"])
        read = next(item for item in result["requirements"] if item["requirementId"] == "req-read")
        self.assertEqual(read["status"], "rejected")
        self.assertIn("subset_not_demonstrated", read["codes"])

    def test_rest_method_and_path_are_enforced(self):
        result = self.assess(ir_for("rest-get.json"), load_manifest("api-method-path-target.json"))
        weather = next(item for item in result["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["status"], "enforced")
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertTrue(result["deployable"])

    def test_host_only_target_is_not_full_for_rest(self):
        result = self.assess(ir_for("rest-get.json"), load_manifest("network-host-only-target.json"))
        weather = next(item for item in result["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["status"], "rejected")
        self.assertNotEqual(result["compilationDisposition"], "FULL")
        self.assertFalse(result["deployable"])

    def test_exact_model_is_enforced_and_provider_only_is_not_full(self):
        model = ir_for("model-inference.json")
        covered = self.assess(model, load_manifest("full-capability-test-target.json"))
        self.assertEqual(
            next(item for item in covered["requirements"] if item["requirementId"] == "req-model")["status"],
            "enforced",
        )
        self.assertEqual(covered["compilationDisposition"], "FULL")
        provider = load_manifest("full-capability-test-target.json")
        provider["kinds"] = ["inference-provider"]
        provider["precision"]["modelId"] = False
        uncovered = self.assess(model, provider)
        self.assertNotEqual(uncovered["compilationDisposition"], "FULL")
        self.assertEqual(
            next(item for item in uncovered["requirements"] if item["requirementId"] == "req-model")["status"],
            "rejected",
        )

    def test_proxy_credential_enforced_and_process_visible_is_not_full(self):
        credential = ir_for("proxy-mediated-credential.json")
        covered = self.assess(credential, load_manifest("full-capability-test-target.json"))
        self.assertEqual(covered["compilationDisposition"], "FULL")
        self.assertEqual(covered["requirements"][0]["status"], "enforced")
        widened = self.assess(credential, load_manifest("no-credential-proxy-target.json"))
        self.assertNotEqual(widened["compilationDisposition"], "FULL")
        self.assertFalse(widened["deployable"])
        permit = next(item for item in widened["requirements"] if item["requirementId"] == "req-credential-use")
        self.assertEqual(permit["status"], "rejected")

    def test_all_of_full_partial_and_rejected(self):
        multi = ir_for("multi-binding-action.json")
        full = self.assess(multi, load_manifest("full-capability-test-target.json"))
        self.assertEqual(full["compilationDisposition"], "FULL")
        self.assertEqual(full["groups"][0]["requirementIds"], ["req-connect", "req-credential", "req-get"])
        self.assertTrue(full["deployable"])
        missing = load_manifest("full-capability-test-target.json")
        missing["kinds"] = [kind for kind in missing["kinds"] if kind != "credential"]
        missing["precision"]["credentialDisclosures"] = []
        missing["precision"].pop("credentialBinding", None)
        partial = self.assess(multi, missing)
        self.assertEqual(partial["compilationDisposition"], "PARTIAL")
        self.assertFalse(partial["deployable"])
        partial_status = {item["requirementId"]: item["status"] for item in partial["requirements"]}
        self.assertEqual(partial_status["req-connect"], "enforced")
        self.assertEqual(partial_status["req-credential"], "unenforced")
        self.assertEqual(partial["groups"][0]["status"], "unenforced")
        self.assertEqual(partial["selectedRequirementIds"], [])
        widened = load_manifest("no-credential-proxy-target.json")
        rejected = self.assess(multi, widened)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")
        self.assertFalse(rejected["deployable"])

    def test_any_of_one_exact_alternative_is_full(self):
        policy = load_example("multi-binding-action.json")
        for requirement in policy["enforcementRequirements"]:
            requirement["composition"] = "anyOf"
        ir = project(policy)["operationalIr"]
        manifest = load_manifest("api-method-path-target.json")
        manifest["kinds"] = ["api"]
        manifest["operations"] = ["query"]
        manifest["compositions"] = ["anyOf"]
        result = self.assess(ir, manifest, document=policy)
        self.assertEqual(result["groups"][0]["composition"], "anyOf")
        self.assertEqual(result["groups"][0]["status"], "enforced")
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertEqual(result["selectedRequirementIds"], ["req-get"])
        self.assertTrue(result["deployable"])
        statuses = {item["requirementId"]: item["status"] for item in result["requirements"]}
        self.assertEqual(statuses["req-get"], "enforced")
        self.assertNotEqual(statuses["req-connect"], "enforced")

    def test_prohibition_enforced_and_unsupported_is_not_full(self):
        policy = load_example("prohibition.json")
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
        covered = self.assess(ir, load_manifest("full-capability-test-target.json"), document=exchange, policy=policy)
        self.assertEqual(covered["prohibitions"][0]["status"], "enforced")
        self.assertEqual(covered["compilationDisposition"], "FULL")
        no_deny = load_manifest("full-capability-test-target.json")
        no_deny["effects"] = ["permit"]
        uncovered = self.assess(ir, no_deny, document=exchange, policy=policy)
        self.assertNotEqual(uncovered["compilationDisposition"], "FULL")
        self.assertEqual(uncovered["prohibitions"][0]["status"], "unenforced")
        self.assertFalse(uncovered["deployable"])

    def test_correlated_audit_and_target_native_only(self):
        ir = ir_for("filesystem-read-write.json")
        covered = self.assess(ir, load_manifest("full-capability-test-target.json"))
        self.assertTrue(all(item["status"] == "enforced" for item in covered["audit"]))
        self.assertEqual(covered["audit"][0]["required"], "correlated")
        native = load_manifest("full-capability-test-target.json")
        native["auditStrengths"] = ["none", "target-native"]
        native["precision"]["traceCorrelation"] = False
        uncovered = self.assess(ir, native)
        self.assertNotEqual(uncovered["compilationDisposition"], "FULL")
        self.assertTrue(all(item["status"] == "unenforced" for item in uncovered["audit"]))
        self.assertFalse(uncovered["deployable"])

    def test_revocable_lifetime_and_static_target(self):
        ir = ir_for("rest-get.json")
        covered = self.assess(ir, load_manifest("api-method-path-target.json"))
        self.assertEqual(covered["compilationDisposition"], "FULL")
        static = self.assess(ir, load_manifest("non-revocable-target.json"))
        self.assertNotEqual(static["compilationDisposition"], "FULL")
        self.assertFalse(static["deployable"])
        self.assertIn("lifetime_mismatch", static["codes"])
        weather = next(item for item in static["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["status"], "rejected")

    def test_baseline_is_disclosed_and_is_not_a_grant(self):
        ir = ir_for("filesystem-read-write.json")
        result = self.assess(ir, load_manifest("broad-baseline-target.json"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])
        baseline = result["coverage"]["targetBaseline"]
        self.assertEqual(baseline[0]["locator"]["path"], "/tmp")
        self.assertEqual(baseline[0]["status"], "baseline")
        self.assertFalse(baseline[0]["authorityBearing"])
        self.assertNotIn("/tmp", json.dumps(result["coverage"]["fipGrants"]))
        self.assertNotIn("req-tmp", result["coverage"]["fipGrants"])

    def test_dangerous_any_host_target_is_not_full(self):
        result = self.assess(ir_for("rest-get.json"), load_manifest("dangerous-network-target.json"))
        self.assertNotEqual(result["compilationDisposition"], "FULL")
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertFalse(result["deployable"])
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        weather = next(item for item in result["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["status"], "rejected")
        self.assertIn("subset_not_demonstrated", result["codes"])
        self.assertTrue(any(item["description"] == "canConnectAnyHost" for item in result["coverage"]["targetBaseline"]))
        self.assertNotIn("weather.example.com", result["coverage"]["fipGrants"])

    def test_manifest_cannot_change_authority_and_stamps_are_ignored(self):
        ir = ir_for("filesystem-read-write.json")
        ir["compilationDisposition"] = "FULL"
        ir["deployable"] = True
        result = self.assess(ir, load_manifest("filesystem-only-target.json"))
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertNotEqual(result["compilationDisposition"], "FULL")
        self.assertFalse(result["deployable"])
        self.assertTrue(ir["deployable"])

    def test_semantic_only_and_malformed_manifest_are_not_compiled(self):
        semantic = project(load_example("lifted-0.1-exchange.json"))["semanticProjection"]
        semantic_result = assess_coverage(semantic, load_manifest("full-capability-test-target.json"))
        self.assertEqual(semantic_result["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(semantic_result["deployable"])
        malformed = assess_coverage(ir_for("filesystem-read-write.json"), {"manifestVersion": "9"})
        self.assertEqual(malformed["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(malformed["deployable"])
        stamped = load_manifest("full-capability-test-target.json")
        stamped["openshell"] = {"network_policies": []}
        rejected = assess_coverage(ir_for("filesystem-read-write.json"), stamped)
        self.assertEqual(rejected["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(rejected["deployable"])

    def test_audit_only_effect_does_not_satisfy_a_permit(self):
        result = self.assess(ir_for("filesystem-read-write.json"), load_manifest("audit-only-target.json"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertTrue(all(item["status"] == "rejected" for item in result["requirements"]))
        self.assertIn("subset_not_demonstrated", result["codes"])

    def test_catalog_lists_required_cases(self):
        catalog = json.loads(
            (ROOT / "conformance" / "fip-0.2" / "coverage" / "catalog.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(catalog["cases"]), 25)
        self.assertEqual(len({item["id"] for item in catalog["cases"]}), 25)


if __name__ == "__main__":
    unittest.main()
