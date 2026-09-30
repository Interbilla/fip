"""OpenShell exact filesystem locators. Derivation and representability stay distinct."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess_coverage, project, verify_derivation  # noqa: E402
from fip02.coverage import filesystem_locator_issue  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
TARGET = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def single_read(path):
    document = load("openshell-filesystem-read-write.json")
    document["policyId"] = "pol-representability"
    document["enforcementRequirements"][0]["groupId"] = "read-only"
    document["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
    document["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
    document["authorizations"][0]["requirementIds"] = ["req-read"]
    document["executionBindings"][0]["locator"]["path"] = path
    return document


class FilesystemRepresentabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_module("openshell_adapter_representability", TARGET / "adapter.py")
        cls.manifest = json.loads((TARGET / "manifest.json").read_text(encoding="utf-8"))
        cls.profile = json.loads((TARGET / "execution-profile.json").read_text(encoding="utf-8"))

    def test_derivation_failure_stays_distinct_from_representability(self):
        document = single_read("/mission/input")
        ir = project(document)["operationalIr"]
        mutated = copy.deepcopy(ir)
        mutated["bindings"][0]["locator"]["path"] = "/mission"
        verdict = verify_derivation(mutated, document)
        self.assertFalse(verdict["matched"])
        coverage = assess_coverage(mutated, self.manifest, self.profile, document=document)
        compiled = self.adapter.compile_policy(mutated, coverage, self.manifest, self.profile, document=document)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        self.assertNotIn("filesystem_locator_not_exact", coverage["diagnostics"])
        self.assertFalse(coverage["deployable"])
        self.assertIsNone(compiled["generatedPolicy"])
        self.assertIn("subset_not_demonstrated", compiled["diagnostics"])

    def test_pattern_locator_matches_derivation_and_is_not_full(self):
        document = single_read("/mission/*")
        ir = project(document)["operationalIr"]
        verdict = verify_derivation(ir, document)
        self.assertTrue(verdict["matched"])
        self.assertEqual(ir["bindings"][0]["locator"]["path"], "/mission/*")
        coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
        compiled = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
        self.assertEqual(coverage["authorityDecision"], "AUTHORIZED")
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("unsupported_requirement", coverage["codes"])
        self.assertIn("filesystem_locator_not_exact", coverage["diagnostics"])
        self.assertNotIn("subset_not_demonstrated", coverage["codes"])
        self.assertFalse(coverage["deployable"])
        self.assertIsNone(compiled["generatedPolicy"])
        stamped = copy.deepcopy(coverage)
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        stamped["selectedRequirementIds"] = ["req-read"]
        for item in stamped["requirements"]:
            item["status"] = "enforced"
        forced = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile, document=document)
        self.assertIsNone(forced["generatedPolicy"])
        self.assertIn("filesystem_locator_not_exact", forced["diagnostics"])

    def test_exact_path_remains_deployable(self):
        document = single_read("/mission/input")
        ir = project(document)["operationalIr"]
        self.assertTrue(verify_derivation(ir, document)["matched"])
        coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
        compiled = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
        self.assertEqual(coverage["compilationDisposition"], "FULL")
        self.assertTrue(coverage["deployable"])
        self.assertIsNotNone(compiled["generatedPolicy"])
        self.assertIn("/mission/input", compiled["generatedPolicy"]["filesystem_policy"]["read_only"])

    def test_locator_matrix_follows_the_pinned_profile(self):
        accepted = {
            "/mission/input": None,
            "/mission": None,
        }
        rejected = {
            "/mission/*": "filesystem_locator_not_exact",
            "/mission/?": "filesystem_locator_not_exact",
            "/mission/[abc]": "filesystem_locator_not_exact",
            "/mission/[a-z]": "filesystem_locator_not_exact",
            "relative/path": "filesystem_locator_not_exact",
            "./mission/input": "filesystem_locator_not_exact",
            "../mission/input": "filesystem_locator_not_exact",
            "/mission/../other": "filesystem_locator_not_exact",
            "/mission//input": "filesystem_locator_not_exact",
            "/mission/input/": "filesystem_locator_not_exact",
            "/mission/./input": "filesystem_locator_not_exact",
        }
        for path, expected in {**accepted, **rejected}.items():
            self.assertEqual(filesystem_locator_issue(path), expected, path)
            document = single_read(path)
            ir = project(document)["operationalIr"]
            self.assertTrue(verify_derivation(ir, document)["matched"], path)
            coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
            compiled = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
            if expected is None:
                self.assertEqual(coverage["compilationDisposition"], "FULL", path)
                self.assertIsNotNone(compiled["generatedPolicy"], path)
            else:
                self.assertEqual(coverage["compilationDisposition"], "REJECTED", path)
                self.assertIn("filesystem_locator_not_exact", coverage["diagnostics"], path)
                self.assertNotIn("subset_not_demonstrated", coverage["codes"], path)
                self.assertFalse(coverage["deployable"], path)
                self.assertIsNone(compiled["generatedPolicy"], path)

    def test_ordinary_filename_characters_stay_exact(self):
        for path in ("/mission/input+1", "/mission/report.md", "/mission/a]b"):
            self.assertIsNone(filesystem_locator_issue(path), path)

    def test_pattern_is_not_rewritten_into_another_path(self):
        document = single_read("/mission/../secret")
        ir = project(document)["operationalIr"]
        self.assertEqual(ir["bindings"][0]["locator"]["path"], "/mission/../secret")
        compiled = self.adapter.compile_policy(
            ir,
            assess_coverage(ir, self.manifest, self.profile, document=document),
            self.manifest,
            self.profile,
            document=document,
        )
        self.assertIsNone(compiled["generatedPolicy"])
        self.assertNotIn("/secret", json.dumps(compiled))


if __name__ == "__main__":
    unittest.main()
