"""OpenShell v0.1.2 filesystem policy adapter. The runtime is not invoked."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
TARGET = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"
GOLDEN = ROOT / "conformance" / "fip-0.2" / "openshell" / "filesystem-policy.json"


def load_adapter():
    spec = importlib.util.spec_from_file_location("openshell_adapter", TARGET / "adapter.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OpenShellAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_adapter()
        cls.policy = load(EXAMPLES / "openshell-filesystem-read-write.json")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")
        cls.authority = assess(cls.policy)
        cls.projection = project(cls.policy)
        cls.ir = cls.projection["operationalIr"]
        cls.coverage = assess_coverage(cls.ir, cls.manifest, cls.profile, document=cls.policy)
        cls.result = cls.adapter.compile_policy(cls.ir, cls.coverage, cls.manifest, cls.profile, document=cls.policy)

    def test_slice_is_authorized_projected_and_full_before_compilation(self):
        self.assertEqual(self.authority["authorityDecision"], "AUTHORIZED")
        self.assertFalse(self.authority["deployable"])
        self.assertIsNotNone(self.ir)
        self.assertEqual(self.ir["authorityDecision"], "AUTHORIZED")
        self.assertEqual(
            {item["requirementId"]: item["audit"] for item in self.ir["requirements"]},
            {"req-read": "target-native", "req-write": "target-native"},
        )
        self.assertEqual(self.coverage["compilationDisposition"], "FULL")
        self.assertTrue(self.coverage["deployable"])
        self.assertEqual(self.coverage["selectedRequirementIds"], ["req-read", "req-write"])
        self.assertEqual(self.coverage["coverage"]["fipGrants"], ["req-read", "req-write"])

    def test_generated_policy_matches_the_golden_structure(self):
        result = self.result
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertTrue(result["deployable"])
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        self.assertEqual(result["monotonicity"], "demonstrated")
        self.assertEqual(result["sourceCommit"], "6648bd0c290efbc41ba131ee9831ee45cd431f94")
        self.assertEqual(result["policySchemaVersion"], 1)
        self.assertEqual(result["targetVersion"], "0.1.2")
        self.assertEqual(result["generatedPolicy"], load(GOLDEN))
        self.assertEqual(self.adapter.parse_policy_yaml(result["policyYaml"]), result["generatedPolicy"])
        self.assertEqual(
            self.adapter.parse_policy_yaml((GOLDEN.with_suffix(".yaml")).read_text(encoding="utf-8")),
            result["generatedPolicy"],
        )
        self.assertEqual(result["sourceRequirementIds"], ["req-read", "req-write"])
        self.assertEqual(result["sourceBindingIds"], ["in-read", "out-write"])
        self.assertEqual(result["extractedAuthority"]["mission"], [
            {"operation": "read", "path": "/mission/input"},
            {"operation": "write", "path": "/mission/output"},
        ])
        self.assertNotIn("/tmp", [item["path"] for item in result["extractedAuthority"]["mission"]])
        self.assertIn("/tmp", [item["path"] for item in result["extractedAuthority"]["substrate"]])
        self.assertTrue(any(item["substrateId"] == "runtime-syscall-restriction" and item["emitted"] is False for item in result["substrateMappings"]))
        self.assertFalse(result["generatedPolicy"]["filesystem_policy"]["include_workdir"])
        self.assertEqual(result["generatedPolicy"]["landlock"]["compatibility"], "hard_requirement")
        self.assertNotIn("network_policies", result["generatedPolicy"])

    def test_gate_refuses_partial_rejected_and_not_compiled(self):
        rest_policy = load(EXAMPLES / "rest-get.json")
        rest = project(rest_policy)
        partial = assess_coverage(rest["operationalIr"], self.manifest, self.profile, document=rest_policy)
        self.assertEqual(partial["compilationDisposition"], "PARTIAL")
        self.assertIsNone(self.adapter.compile_policy(rest["operationalIr"], partial, self.manifest, self.profile)["generatedPolicy"])
        rejected_policy = load(EXAMPLES / "filesystem-read-write.json")
        rejected_ir = project(rejected_policy)["operationalIr"]
        rejected = assess_coverage(rejected_ir, self.manifest, self.profile, document=rejected_policy)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")
        self.assertIsNone(self.adapter.compile_policy(rejected_ir, rejected, self.manifest, self.profile)["generatedPolicy"])
        uncompiled = assess_coverage({"projection": "semantic"}, self.manifest, self.profile)
        self.assertEqual(uncompiled["compilationDisposition"], "NOT_COMPILED")
        refused = self.adapter.compile_policy(None, uncompiled, self.manifest, self.profile)
        self.assertIsNone(refused["generatedPolicy"])
        self.assertEqual(refused["runtimeDisposition"], "UNOBSERVED")
        self.assertNotEqual(refused["compilationDisposition"], "FULL")

    def test_gate_refuses_authority_other_than_authorized_and_false_deployable(self):
        for authority in ("DENIED", "INCOMPLETE", "REVIEW"):
            stamped = copy.deepcopy(self.coverage)
            stamped["authorityDecision"] = authority
            stamped["compilationDisposition"] = "FULL"
            stamped["deployable"] = True
            result = self.adapter.compile_policy(self.ir, stamped, self.manifest, self.profile, document=self.policy)
            self.assertIsNone(result["generatedPolicy"])
            self.assertNotEqual(result["compilationDisposition"], "FULL")
            self.assertFalse(result["deployable"])
        withheld = copy.deepcopy(self.coverage)
        withheld["deployable"] = False
        result = self.adapter.compile_policy(self.ir, withheld, self.manifest, self.profile, document=self.policy)
        self.assertIsNone(result["generatedPolicy"])
        self.assertNotEqual(result["compilationDisposition"], "FULL")

    def test_identity_mismatches_emit_no_policy(self):
        cases = [
            ("adapterId", "other-adapter", "manifest_identity_mismatch"),
            ("targetVersion", "0.1.3", "target_version_mismatch"),
            ("adapterVersion", "9", "adapter_version_mismatch"),
        ]
        for field, value, diagnostic in cases:
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            result = self.adapter.compile_policy(self.ir, self.coverage, manifest, self.profile, document=self.policy)
            self.assertIsNone(result["generatedPolicy"])
            self.assertIn(diagnostic, result["diagnostics"])
        profile = copy.deepcopy(self.profile)
        profile["profileId"] = "other-profile"
        result = self.adapter.compile_policy(self.ir, self.coverage, self.manifest, profile, document=self.policy)
        self.assertIsNone(result["generatedPolicy"])
        self.assertIn("execution_profile_mismatch", result["diagnostics"])

    def test_missing_path_unsupported_operation_and_omitted_members_emit_no_policy(self):
        missing_path = copy.deepcopy(self.ir)
        next(item for item in missing_path["bindings"] if item["bindingId"] == "in-read")["locator"] = {}
        missing = self.adapter.compile_policy(missing_path, self.coverage, self.manifest, self.profile, document=self.policy)
        self.assertIsNone(missing["generatedPolicy"])
        self.assertIn("subset_not_demonstrated", missing["diagnostics"])
        unsupported = copy.deepcopy(self.ir)
        next(item for item in unsupported["bindings"] if item["bindingId"] == "out-write")["operation"] = "delete"
        widened = self.adapter.compile_policy(unsupported, self.coverage, self.manifest, self.profile, document=self.policy)
        self.assertIsNone(widened["generatedPolicy"])
        self.assertIn("subset_not_demonstrated", widened["diagnostics"])
        omitted = copy.deepcopy(self.ir)
        omitted["requirements"] = [item for item in omitted["requirements"] if item["requirementId"] != "req-write"]
        deleted = self.adapter.compile_policy(omitted, self.coverage, self.manifest, self.profile, document=self.policy)
        self.assertIsNone(deleted["generatedPolicy"])
        self.assertIn("subset_not_demonstrated", deleted["diagnostics"])
        dropped = copy.deepcopy(self.coverage)
        dropped["selectedRequirementIds"] = ["req-read"]
        self.assertIn(
            "allof_member_omitted",
            self.adapter.compile_policy(self.ir, dropped, self.manifest, self.profile, document=self.policy)["diagnostics"],
        )

    def test_post_generation_widening_emits_no_policy(self):
        grants = [(item["operation"], item["path"]) for item in self.result["ruleMappings"]]
        substrate = [
            {"substrateId": item["substrateId"], "operation": item["operation"], "path": item["path"]}
            for item in self.result["substrateMappings"]
            if item["emitted"]
        ]
        mutations = [
            ("read_emitted_as_read_write", self._move_read_to_write),
            ("path_broader_or_unaccepted", self._broaden_grant),
            ("path_broader_or_unaccepted", self._add_unaccepted),
            ("substrate_access_widened", self._widen_substrate),
            ("workdir_implicitly_added", self._enable_workdir),
            ("soft_filesystem_enforcement", self._soften_landlock),
            ("read_authority_mismatch", self._drop_grant),
        ]
        for diagnostic, mutate in mutations:
            policy = copy.deepcopy(self.result["generatedPolicy"])
            mutate(policy)
            admitted = self.adapter.admit_generated_policy(
                policy, self.ir, self.coverage, grants, substrate, mappings=self.result["ruleMappings"]
            )
            self.assertIsNone(admitted["generatedPolicy"])
            self.assertFalse(admitted["deployable"])
            self.assertEqual(admitted["compilationDisposition"], "REJECTED")
            self.assertEqual(admitted["runtimeDisposition"], "UNOBSERVED")
            self.assertIn(diagnostic, admitted["diagnostics"])
            self.assertEqual(admitted["monotonicity"], "not_demonstrated")

    def _move_read_to_write(self, policy):
        policy["filesystem_policy"]["read_only"].remove("/mission/input")
        policy["filesystem_policy"]["read_write"].append("/mission/input")

    def _broaden_grant(self, policy):
        paths = policy["filesystem_policy"]["read_only"]
        paths[paths.index("/mission/input")] = "/mission"

    def _add_unaccepted(self, policy):
        policy["filesystem_policy"]["read_write"].append("/mission/extra")

    def _widen_substrate(self, policy):
        policy["filesystem_policy"]["read_only"].remove("/usr")
        policy["filesystem_policy"]["read_write"].append("/usr")

    def _enable_workdir(self, policy):
        policy["filesystem_policy"]["include_workdir"] = True

    def _soften_landlock(self, policy):
        policy["landlock"]["compatibility"] = "best_effort"

    def _drop_grant(self, policy):
        policy["filesystem_policy"]["read_only"].remove("/mission/input")


if __name__ == "__main__":
    unittest.main()
