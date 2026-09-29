"""Capability-scoped lifetimes, execution substrate, and credential precision."""

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


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def scoped_manifest():
    manifest = load(MANIFESTS / "full-capability-test-target.json")
    manifest["capabilities"] = [
        {"capabilityId": "filesystem", "kinds": ["filesystem"], "lifetimes": ["establishment-bound"]},
        {"capabilityId": "process", "kinds": ["process", "executable"], "lifetimes": ["establishment-bound"]},
        {
            "capabilityId": "network",
            "kinds": ["service", "api", "inference-provider"],
            "lifetimes": ["establishment-bound", "revocable"],
        },
        {
            "capabilityId": "credential",
            "kinds": ["credential"],
            "lifetimes": ["establishment-bound", "revocable"],
        },
        {"capabilityId": "model", "kinds": ["model"], "lifetimes": ["establishment-bound", "revocable"]},
        {
            "capabilityId": "other",
            "kinds": ["device", "message-channel", "datastore"],
            "lifetimes": ["establishment-bound"],
        },
    ]
    return manifest


def ir_for(name):
    return project(load(EXAMPLES / name))["operationalIr"]


def profile_for(path, substrate_class="writable-runtime"):
    return {
        "profileVersion": "0",
        "profileId": "profile-m2c",
        "acceptedExecutionSubstrate": [
            {
                "substrateClass": substrate_class,
                "substrateId": "item-1",
                "kind": "filesystem",
                "operation": "write" if substrate_class == "writable-runtime" else "read",
                "locator": {"path": path},
            }
        ],
    }


class CapabilityRefinementTest(unittest.TestCase):
    def assess(self, ir, manifest, profile=None):
        before = copy.deepcopy(ir)
        result = assess_coverage(ir, manifest, profile)
        self.assertEqual(ir, before)
        return result

    def test_revocable_network_does_not_make_filesystem_revocable(self):
        manifest = scoped_manifest()
        rest = self.assess(ir_for("rest-get.json"), manifest)
        weather = next(item for item in rest["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["status"], "enforced")
        self.assertNotIn("lifetime_mismatch", rest["codes"])
        files = ir_for("filesystem-read-write.json")
        for requirement in files["requirements"]:
            requirement["lifetime"] = "revocable"
        for binding in files["bindings"]:
            binding["lifetime"] = "revocable"
        rejected = self.assess(files, manifest)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")
        self.assertIn("lifetime_mismatch", rejected["codes"])
        self.assertTrue(all(item["status"] == "rejected" for item in rejected["requirements"]))

    def test_establishment_filesystem_stays_establishment_only(self):
        manifest = scoped_manifest()
        covered = self.assess(ir_for("filesystem-read-write.json"), manifest)
        self.assertEqual(covered["compilationDisposition"], "FULL")
        self.assertEqual(
            next(item["lifetimes"] for item in manifest["capabilities"] if item["capabilityId"] == "filesystem"),
            ["establishment-bound"],
        )
        self.assertIn("revocable", next(item["lifetimes"] for item in manifest["capabilities"] if item["capabilityId"] == "network"))

    def test_accepted_substrate_never_becomes_a_grant(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "substrateId": "item-1",
            "description": "temporary workspace",
            "substrateClass": "writable-runtime",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/tmp"},
            "authorityBearing": False,
        }]
        result = self.assess(ir_for("filesystem-read-write.json"), manifest, profile_for("/tmp"))
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])
        row = result["coverage"]["targetBaseline"][0]
        self.assertEqual(row["acceptance"], "accepted")
        self.assertEqual(row["locator"]["path"], "/tmp")
        self.assertEqual(row["declaredBy"], manifest["adapterId"])
        self.assertNotIn("/tmp", result["coverage"]["fipGrants"])
        self.assertFalse(row["authorityBearing"])

    def test_undeclared_baseline_authority_is_rejected(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "description": "undeclared mission write",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/mission/extra"},
            "authorityBearing": False,
        }]
        result = self.assess(ir_for("filesystem-read-write.json"), manifest, profile_for("/mission/extra"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(result["coverage"]["targetBaseline"][0]["substrateClass"], "operational-authority")
        self.assertEqual(result["coverage"]["targetBaseline"][0]["acceptance"], "unaccepted")
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])

    def test_substrate_that_conflicts_with_a_prohibition_is_rejected(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "substrateId": "item-1",
            "description": "temporary workspace",
            "substrateClass": "writable-runtime",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/tmp"},
            "authorityBearing": False,
        }]
        ir = ir_for("filesystem-read-write.json")
        ir["bindings"].append({
            "bindingId": "tmp-write",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/tmp"},
            "lifetime": "establishment-bound",
        })
        ir["prohibitions"].append({
            "prohibitionId": "proh-tmp",
            "bindingIds": ["tmp-write"],
            "requirementIds": [],
        })
        result = self.assess(ir, manifest, profile_for("/tmp"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(result["coverage"]["targetBaseline"][0]["acceptance"], "unaccepted")
        self.assertNotIn("/tmp", result["coverage"]["fipGrants"])

    def test_target_cannot_label_a_mission_path_as_trusted_substrate(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "substrateId": "mission-write",
            "description": "mission directory labeled as runtime workspace",
            "substrateClass": "writable-runtime",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/mission/private"},
            "authorityBearing": False,
        }]
        result = self.assess(ir_for("filesystem-read-write.json"), manifest, profile_for("/tmp"))
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", result["codes"])
        self.assertEqual(result["coverage"]["targetBaseline"][0]["acceptance"], "unaccepted")
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])

    def test_writable_runtime_requires_explicit_profile_acceptance(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "substrateId": "item-1",
            "description": "temporary workspace",
            "substrateClass": "writable-runtime",
            "kind": "filesystem",
            "operation": "write",
            "locator": {"path": "/tmp"},
            "authorityBearing": False,
        }]
        ir = ir_for("filesystem-read-write.json")
        refused = self.assess(ir, manifest)
        self.assertEqual(refused["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", refused["codes"])
        accepted = self.assess(ir, manifest, profile_for("/tmp"))
        self.assertEqual(accepted["compilationDisposition"], "FULL")
        self.assertEqual(accepted["coverage"]["targetBaseline"][0]["acceptance"], "accepted")

    def test_restrictive_substrate_does_not_become_authority(self):
        manifest = scoped_manifest()
        manifest["substrate"] = [{
            "substrateId": "syscall-restriction",
            "description": "syscall restriction",
            "substrateClass": "restrictive",
            "kind": "process",
            "authorityBearing": False,
        }]
        result = self.assess(ir_for("filesystem-read-write.json"), manifest)
        self.assertEqual(result["compilationDisposition"], "FULL")
        row = result["coverage"]["targetBaseline"][0]
        self.assertEqual(row["substrateClass"], "restrictive")
        self.assertEqual(row["acceptance"], "unaccepted")
        self.assertEqual(result["coverage"]["fipGrants"], ["req-read", "req-write"])
        self.assertNotIn("syscall-restriction", result["coverage"]["fipGrants"])

    def test_proxy_disclosure_is_independent_of_binding_precision(self):
        manifest = scoped_manifest()
        manifest["kinds"] = [kind for kind in manifest["kinds"] if kind != "credential"]
        manifest["precision"]["credentialDisclosures"] = ["proxy-mediated"]
        manifest["precision"]["credentialBinding"] = {
            "dimensions": ["host", "port"],
            "required": ["host", "port"],
        }
        missing_locator = self._credential_ir(disclosure="proxy-mediated", locator={"serviceId": "credential:FieldModel"})
        disclosure_only = self.assess(missing_locator, manifest)
        permit = next(item for item in disclosure_only["requirements"] if item["requirementId"] == "req-credential-use")
        self.assertEqual(permit["status"], "rejected")
        self.assertIn("subset_not_demonstrated", permit["codes"])
        visible = self._credential_ir(
            disclosure="process-visible",
            locator={"host": "status.example.com", "port": 443},
        )
        precise_but_visible = self.assess(visible, manifest)
        visible_permit = next(item for item in precise_but_visible["requirements"] if item["requirementId"] == "req-credential-use")
        self.assertEqual(visible_permit["status"], "rejected")
        self.assertIn("subset_not_demonstrated", visible_permit["codes"])

    def test_exact_credential_boundary_can_be_enforced_without_a_generic_kind(self):
        manifest = scoped_manifest()
        manifest["kinds"] = [kind for kind in manifest["kinds"] if kind != "credential"]
        manifest["precision"]["credentialDisclosures"] = ["proxy-mediated"]
        manifest["precision"]["credentialBinding"] = {
            "dimensions": ["host", "port", "path", "protocol"],
            "required": ["host", "port"],
        }
        ir = self._credential_ir(
            disclosure="proxy-mediated",
            locator={"host": "status.example.com", "port": 443, "path": "/status"},
            protocol={"family": "http", "http": {"method": "GET", "path": "/status"}},
        )
        result = self.assess(ir, manifest)
        permit = next(item for item in result["requirements"] if item["requirementId"] == "req-credential-use")
        self.assertEqual(permit["status"], "enforced")
        self.assertNotIn("credential", manifest["kinds"])

    def test_broader_credential_boundary_fails_the_subset_invariant(self):
        manifest = scoped_manifest()
        manifest["precision"]["credentialDisclosures"] = ["proxy-mediated"]
        manifest["precision"]["credentialBinding"] = {
            "dimensions": ["provider", "host", "port", "path", "protocol"],
            "required": ["host", "port"],
        }
        ir = self._credential_ir(disclosure="proxy-mediated", locator={"serviceId": "credential:FieldModel"})
        result = self.assess(ir, manifest)
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        permit = next(item for item in result["requirements"] if item["requirementId"] == "req-credential-use")
        self.assertEqual(permit["status"], "rejected")
        self.assertIn("subset_not_demonstrated", permit["codes"])

    def test_m2c_catalog_lists_the_refinement_cases(self):
        catalog = load(ROOT / "conformance" / "fip-0.2" / "coverage" / "m2c-catalog.json")
        self.assertEqual(len(catalog["cases"]), 11)
        self.assertEqual(len({item["id"] for item in catalog["cases"]}), 11)

    def _credential_ir(self, disclosure, locator, protocol=None):
        binding = {
            "bindingId": "model-credential",
            "kind": "credential",
            "operation": "invoke",
            "disclosure": disclosure,
            "locator": locator,
            "lifetime": "establishment-bound",
        }
        if protocol:
            binding["protocol"] = protocol
        requirement = {
            "requirementId": "req-credential-use",
            "effect": "permit",
            "bindingIds": ["model-credential"],
            "composition": "allOf",
            "groupId": "credential-use",
            "audit": "none",
            "lifetime": "establishment-bound",
        }
        return {
            "irVersion": "0",
            "fipVersion": "0.2",
            "policyId": "pol-m2c",
            "traceId": "trace-m2c",
            "authorityDecision": "AUTHORIZED",
            "requirements": [requirement],
            "bindings": [binding],
            "groups": [{
                "groupId": "credential-use",
                "composition": "allOf",
                "requirementIds": ["req-credential-use"],
            }],
            "prohibitions": [],
            "coverage": {"fipGrants": ["req-credential-use"], "targetEnforcement": [], "targetBaseline": []},
        }


if __name__ == "__main__":
    unittest.main()
