"""The REST runtime fixture compiles. This test does not start a sandbox."""

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
CONFORMANCE_HASH = "487cf5c82708397a7a45e48d6d7f2b97d7d948715f235dba215ca2ab53c8b504"
FILESYSTEM_HASH = "6cf6240b86186a0d94fcffe49034e8cb2fb5a03835dea68c765ceddb47456afb"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class RestRuntimeFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_module("openshell_adapter_m5d", TARGET / "adapter.py")
        cls.runtime = load_module("openshell_runtime_m5d", TARGET / "runtime.py")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")
        cls.document = load(EXAMPLES / "openshell-rest-runtime.json")
        cls.authority = assess(cls.document)
        cls.projection = project(cls.document)
        cls.coverage = assess_coverage(
            cls.projection["operationalIr"], cls.manifest, cls.profile, document=cls.document
        )
        cls.result = cls.adapter.compile_policy(
            cls.projection["operationalIr"], cls.coverage, cls.manifest, cls.profile, document=cls.document
        )

    def test_fixture_is_authorized_full_and_unobserved(self):
        self.assertEqual(self.authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(self.projection["compilationDisposition"], "NOT_COMPILED")
        self.assertEqual(self.coverage["compilationDisposition"], "FULL")
        self.assertTrue(self.coverage["deployable"])
        self.assertEqual(self.result["compilationDisposition"], "FULL")
        self.assertEqual(self.result["runtimeDisposition"], "UNOBSERVED")
        self.assertEqual(self.result["monotonicity"], "demonstrated")
        endpoint = self.result["generatedPolicy"]["network_policies"]["req-example-get"]["endpoints"][0]
        self.assertEqual(endpoint["host"], "example.com")
        self.assertEqual(endpoint["rules"], [{"allow": {"method": "GET", "path": "/"}}])
        self.assertNotIn("/usr/bin/curl", json.dumps(self.document))
        digest = self.runtime.canonical_policy_hash(self.result["generatedPolicy"])
        again = self.runtime.canonical_policy_hash(
            self.adapter.compile_policy(
                self.projection["operationalIr"], self.coverage, self.manifest, self.profile, document=self.document
            )["generatedPolicy"]
        )
        self.assertEqual(digest, again)
        self.assertNotEqual(digest, CONFORMANCE_HASH)

    def test_readback_name_echo_is_not_a_new_grant(self):
        policy = json.loads(json.dumps(self.result["generatedPolicy"]))
        policy["network_policies"]["req-example-get"]["name"] = "req-example-get"
        reasons = self.adapter.verify_effective_policy(
            policy,
            self.result["networkGrants"],
            self.result["extractedAuthority"]["substrate"],
            self.result["binaryRestrictions"],
        )
        self.assertEqual(reasons, [])
        policy["network_policies"]["req-example-get"]["name"] = "other-rule"
        widened = self.adapter.verify_effective_policy(
            policy,
            self.result["networkGrants"],
            self.result["extractedAuthority"]["substrate"],
            self.result["binaryRestrictions"],
        )
        self.assertIn("unexpected_rule_fields", widened)

    def test_conformance_and_strict_probes_stay_in_place(self):
        conformance = load(EXAMPLES / "openshell-rest-target-restricted.json")
        ir = project(conformance)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile, document=conformance)
        compiled = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=conformance)
        self.assertEqual(self.runtime.canonical_policy_hash(compiled["generatedPolicy"]), CONFORMANCE_HASH)
        strict = load(EXAMPLES / "openshell-rest-get.json")
        strict_ir = project(strict)["operationalIr"]
        strict_coverage = assess_coverage(strict_ir, self.manifest, self.profile, document=strict)
        self.assertEqual(strict_coverage["compilationDisposition"], "REJECTED")
        architectural_policy = load(EXAMPLES / "rest-get.json")
        architectural = project(architectural_policy)
        architectural_coverage = assess_coverage(
            architectural["operationalIr"], self.manifest, self.profile, document=architectural_policy
        )
        self.assertEqual(architectural_coverage["compilationDisposition"], "PARTIAL")
        files = load(EXAMPLES / "openshell-filesystem-read-write.json")
        files_ir = project(files)["operationalIr"]
        files_coverage = assess_coverage(files_ir, self.manifest, self.profile, document=files)
        files_compiled = self.adapter.compile_policy(
            files_ir, files_coverage, self.manifest, self.profile, document=files
        )
        self.assertEqual(self.runtime.canonical_policy_hash(files_compiled["generatedPolicy"]), FILESYSTEM_HASH)


if __name__ == "__main__":
    unittest.main()
