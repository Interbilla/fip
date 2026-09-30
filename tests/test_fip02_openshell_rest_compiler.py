"""OpenShell v0.1.2 REST compiler hardening. No sandbox and no runtime."""

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
FILESYSTEM_HASH = "6cf6240b86186a0d94fcffe49034e8cb2fb5a03835dea68c765ceddb47456afb"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OpenShellRestCompilerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_module("openshell_adapter_rest", TARGET / "adapter.py")
        cls.runtime = load_module("openshell_runtime_rest", TARGET / "runtime.py")
        cls.policy = load(EXAMPLES / "openshell-rest-get.json")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")
        cls.authority = assess(cls.policy)
        cls.projection = project(cls.policy)
        cls.ir = cls.projection["operationalIr"]
        cls.coverage = assess_coverage(cls.ir, cls.manifest, cls.profile, document=cls.policy)
        cls.result = cls.adapter.compile_policy(cls.ir, cls.coverage, cls.manifest, cls.profile, document=cls.policy)
        cls.grants = [{
            "requirementId": "req-weather-get",
            "bindingId": "weather-get",
            "host": "weather.example.com",
            "port": 443,
            "method": "GET",
            "path": "/weather",
        }]
        cls.binaries = ["/usr/bin/curl"]
        cls.substrate = [
            {"substrateId": "runtime-usr", "operation": "read", "path": "/usr"},
            {"substrateId": "runtime-lib", "operation": "read", "path": "/lib"},
            {"substrateId": "runtime-etc", "operation": "read", "path": "/etc"},
            {"substrateId": "runtime-app", "operation": "read", "path": "/app"},
            {"substrateId": "runtime-var-log", "operation": "read", "path": "/var/log"},
            {"substrateId": "runtime-proc", "operation": "read", "path": "/proc"},
            {"substrateId": "runtime-urandom", "operation": "read", "path": "/dev/urandom"},
            {"substrateId": "runtime-ca", "operation": "read", "path": "/run/openshell-supervisor-ca"},
            {"substrateId": "runtime-tmp", "operation": "write", "path": "/tmp"},
            {"substrateId": "runtime-null", "operation": "write", "path": "/dev/null"},
        ]

    def test_probe_is_case_a_and_does_not_compile(self):
        self.assertEqual(self.authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(self.projection["compilationDisposition"], "NOT_COMPILED")
        self.assertEqual(self.coverage["compilationDisposition"], "REJECTED")
        self.assertFalse(self.coverage["deployable"])
        self.assertIn("subset_not_demonstrated", self.coverage["codes"])
        self.assertIsNone(self.result["generatedPolicy"])
        self.assertFalse(self.result["deployable"])
        self.assertEqual(self.result["compilationDisposition"], "REJECTED")
        self.assertEqual(self.result["runtimeDisposition"], "UNOBSERVED")
        self.assertIn("executable_identity_not_exact", self.result["diagnostics"])
        self.assertNotEqual(self.result["monotonicity"], "demonstrated")
        forced = self.adapter.compile_policy(self.ir, self._stamp_full(), self.manifest, self.profile, document=self.policy)
        self.assertIsNone(forced["generatedPolicy"])
        self.assertFalse(forced["deployable"])
        self.assertIn("executable_identity_not_exact", forced["diagnostics"])
        self.assertEqual(forced["runtimeDisposition"], "UNOBSERVED")

    def test_query_component_fails_closed(self):
        stamped = self._stamp_full()
        clean = self.adapter.compile_policy(self.ir, stamped, self.manifest, self.profile, document=self.policy)
        self.assertNotIn("query_precision_unsupported", clean["diagnostics"])
        queried_policy = copy.deepcopy(self.policy)
        source = next(item for item in queried_policy["executionBindings"] if item["bindingId"] == "weather-get")
        source["locator"]["uri"] = "https://weather.example.com/weather?station=LAX"
        queried = project(queried_policy)["operationalIr"]
        result = self.adapter.compile_policy(queried, stamped, self.manifest, self.profile, document=queried_policy)
        self.assertIsNone(result["generatedPolicy"])
        self.assertFalse(result["deployable"])
        self.assertEqual(result["compilationDisposition"], "REJECTED")
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        self.assertIn("query_precision_unsupported", result["diagnostics"])
        self.assertIn("executable_identity_not_exact", result["diagnostics"])

    def test_gate_refuses_partial_rejected_and_not_compiled(self):
        rest_policy = load(EXAMPLES / "rest-get.json")
        rest = project(rest_policy)
        partial = assess_coverage(rest["operationalIr"], self.manifest, self.profile, document=rest_policy)
        self.assertEqual(partial["compilationDisposition"], "PARTIAL")
        refused = self.adapter.compile_policy(rest["operationalIr"], partial, self.manifest, self.profile, document=rest_policy)
        self.assertIsNone(refused["generatedPolicy"])
        self.assertEqual(refused["compilationDisposition"], "PARTIAL")
        self.assertEqual(refused["runtimeDisposition"], "UNOBSERVED")
        rejected_policy = load(EXAMPLES / "filesystem-read-write.json")
        rejected_ir = project(rejected_policy)["operationalIr"]
        rejected = assess_coverage(rejected_ir, self.manifest, self.profile, document=rejected_policy)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")
        refused = self.adapter.compile_policy(rejected_ir, rejected, self.manifest, self.profile, document=rejected_policy)
        self.assertIsNone(refused["generatedPolicy"])
        self.assertEqual(refused["compilationDisposition"], "REJECTED")
        uncompiled = assess_coverage({"projection": "semantic"}, self.manifest, self.profile)
        self.assertEqual(uncompiled["compilationDisposition"], "NOT_COMPILED")
        refused = self.adapter.compile_policy(None, uncompiled, self.manifest, self.profile)
        self.assertIsNone(refused["generatedPolicy"])
        self.assertEqual(refused["compilationDisposition"], "NOT_COMPILED")

    def test_effective_policy_rejects_same_host_widening(self):
        policy = self._base_policy()
        self.assertEqual(
            self.adapter.verify_effective_policy(policy, self.grants, self.substrate, self.binaries),
            [],
        )
        mutations = [
            ("port_widened", self._extra_port),
            ("binary_restriction_widened", self._extra_binary),
            ("method_widened", self._broader_method),
            ("path_widened", self._broader_path),
            ("access_preset_widens", self._read_only_preset),
            ("audit_enforcement_does_not_block", self._audit_enforcement),
            ("protocol_downgraded", self._downgrade_tcp),
            ("tls_inspection_disabled", self._skip_tls),
            ("provider_authority_not_a_grant", self._provider_rule),
        ]
        for diagnostic, mutate in mutations:
            candidate = copy.deepcopy(policy)
            mutate(candidate)
            reasons = self.adapter.verify_effective_policy(
                candidate, self.grants, self.substrate, self.binaries
            )
            self.assertIn(diagnostic, reasons, diagnostic)
            self.assertNotEqual(reasons, [], diagnostic)

    def test_filesystem_policy_hash_is_unchanged(self):
        filesystem = load_module("openshell_adapter_filesystem_guard", TARGET / "adapter.py")
        document = load(EXAMPLES / "openshell-filesystem-read-write.json")
        ir = project(document)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
        result = filesystem.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertNotIn("network_policies", result["generatedPolicy"])
        self.assertEqual(self.runtime.canonical_policy_hash(result["generatedPolicy"]), FILESYSTEM_HASH)

    def _stamp_full(self):
        stamped = copy.deepcopy(self.coverage)
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        stamped["selectedRequirementIds"] = ["req-no-other-network", "req-weather-get"]
        for item in stamped["requirements"]:
            item["status"] = "enforced"
        return stamped

    def _base_policy(self):
        return {
            "version": 1,
            "filesystem_policy": {
                "include_workdir": False,
                "read_only": [item["path"] for item in self.substrate if item["operation"] == "read"],
                "read_write": [item["path"] for item in self.substrate if item["operation"] == "write"],
            },
            "landlock": {"compatibility": "hard_requirement"},
            "network_policies": {
                "req-weather-get": {
                    "endpoints": [{
                        "host": "weather.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "enforcement": "enforce",
                        "rules": [{"allow": {"method": "GET", "path": "/weather"}}],
                    }],
                    "binaries": [{"path": "/usr/bin/curl"}],
                },
            },
        }

    def _endpoint(self, policy):
        return policy["network_policies"]["req-weather-get"]["endpoints"][0]

    def _extra_port(self, policy):
        self._endpoint(policy)["port"] = 8443

    def _extra_binary(self, policy):
        policy["network_policies"]["req-weather-get"]["binaries"].append({"path": "/usr/bin/wget"})

    def _broader_method(self, policy):
        self._endpoint(policy)["rules"][0]["allow"]["method"] = "*"

    def _broader_path(self, policy):
        self._endpoint(policy)["rules"][0]["allow"]["path"] = "/weather/**"

    def _read_only_preset(self, policy):
        endpoint = self._endpoint(policy)
        endpoint.pop("rules", None)
        endpoint["access"] = "read-only"

    def _audit_enforcement(self, policy):
        self._endpoint(policy)["enforcement"] = "audit"

    def _downgrade_tcp(self, policy):
        endpoint = self._endpoint(policy)
        endpoint["protocol"] = "tcp"
        endpoint.pop("rules", None)

    def _skip_tls(self, policy):
        self._endpoint(policy)["tls"] = "skip"

    def _provider_rule(self, policy):
        policy["network_policies"]["_provider_work_github"] = {
            "endpoints": [{
                "host": "weather.example.com",
                "port": 443,
                "protocol": "rest",
                "enforcement": "enforce",
                "rules": [{"allow": {"method": "GET", "path": "/weather"}}],
            }],
            "binaries": [{"path": "/usr/bin/curl"}],
        }


if __name__ == "__main__":
    unittest.main()
