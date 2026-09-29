"""Portable M4 record tests. They do not launch OpenShell."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "openshell_runtime",
    ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "runtime.py",
)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def spec_by_id(probe_id):
    return next(item for item in runtime.PROBES if item["id"] == probe_id)


class RuntimeRecordTest(unittest.TestCase):
    def test_canonical_hash_ignores_key_order(self):
        left = {"version": 1, "landlock": {"compatibility": "hard_requirement"}}
        right = {"landlock": {"compatibility": "hard_requirement"}, "version": 1}
        self.assertEqual(runtime.canonical_policy_hash(left), runtime.canonical_policy_hash(right))

    def test_version_pin_rejects_a_different_release(self):
        self.assertTrue(runtime.version_accepted("0.1.2", None))
        self.assertTrue(runtime.version_accepted("0.1.2", runtime.PINNED_COMMIT))
        self.assertFalse(runtime.version_accepted("0.1.3", None))
        self.assertFalse(runtime.version_accepted("0.1.2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

    def test_enforced_deny_is_not_a_fip_grant(self):
        spec = spec_by_id("critical-input-write")
        judgment = runtime.interpret_probe(spec, {"outcome": "failure", "errno": 13, "errnoName": "EACCES"})
        self.assertTrue(judgment["passed"])
        self.assertEqual(judgment["runtimeDisposition"], "ENFORCED_DENY")
        self.assertFalse(judgment["fipGrant"])

    def test_missing_file_is_not_an_enforcement_denial(self):
        spec = spec_by_id("unauthorized-unrelated-read")
        judgment = runtime.interpret_probe(spec, {"outcome": "failure", "errno": 2, "errnoName": "ENOENT"})
        self.assertFalse(judgment["passed"])
        self.assertEqual(judgment["runtimeDisposition"], "UNOBSERVED")
        self.assertEqual(judgment["classification"], "evidence-failure")

    def test_unauthorized_success_is_a_monotonicity_violation(self):
        spec = spec_by_id("critical-unrelated-write")
        judgment = runtime.interpret_probe(spec, {"outcome": "success", "errno": None})
        self.assertFalse(judgment["passed"])
        self.assertEqual(judgment["classification"], "monotonicity-violation")
        self.assertFalse(judgment["fipGrant"])

    def test_substrate_success_is_not_counted_as_a_grant(self):
        spec = spec_by_id("substrate-tmp-write")
        judgment = runtime.interpret_probe(spec, {"outcome": "success", "errno": None})
        self.assertTrue(judgment["passed"])
        self.assertEqual(judgment["authorityClass"], "execution-substrate")
        self.assertFalse(judgment["fipGrant"])

    def test_correlation_keeps_target_evidence_separate(self):
        spec = spec_by_id("authorized-read")
        adapter_result = {
            "traceId": "trace-openshell-files",
            "policyId": "pol-openshell-files",
            "adapterId": "openshell-v0.1.2",
            "ruleMappings": [
                {
                    "requirementId": "req-read",
                    "bindingId": "in-read",
                    "operation": "read",
                    "path": "/mission/input",
                }
            ],
            "substrateMappings": [],
        }
        evidence = {"source": "target-native", "eventId": None, "ocsfRecord": None}
        record = runtime.correlation_record(
            spec,
            {"observedAt": "2026-09-29T00:00:00Z"},
            adapter_result,
            "abc",
            evidence,
        )
        self.assertEqual(record["correlationSource"], "fip-side")
        self.assertEqual(record["requirementId"], "req-read")
        self.assertEqual(record["bindingId"], "in-read")
        self.assertIsNone(record["exchangeId"])
        self.assertNotIn("traceId", record["targetNativeEvidence"])
        self.assertNotIn("requirementId", record["targetNativeEvidence"])

    def test_landlock_requires_hard_requirement_and_abi_3(self):
        hard = "OCSF CONFIG:ENABLED Landlock ruleset built [abi:v5 compat:HardRequirement rules_applied:12 skipped:1]"
        self.assertTrue(runtime.landlock_confirmed(hard)[0])
        soft = "OCSF CONFIG:ENABLED Landlock ruleset built [abi:v5 compat:BestEffort rules_applied:12]"
        self.assertFalse(runtime.landlock_confirmed(soft)[0])
        old = "OCSF CONFIG:ENABLED Landlock ruleset built [abi:v2 compat:HardRequirement rules_applied:4]"
        self.assertFalse(runtime.landlock_confirmed(old)[0])


if __name__ == "__main__":
    unittest.main()
