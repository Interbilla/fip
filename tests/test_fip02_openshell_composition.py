"""Adapter composition checks. These are not Q13 results."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess_coverage, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
TARGET = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OpenShellCompositionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_module("openshell_adapter_composition", TARGET / "adapter.py")
        cls.slices = load_module("openshell_slices_composition", TARGET / "network_slices.py")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")

    def compiled(self, name):
        document = load(EXAMPLES / name)
        ir = project(document)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile)
        return ir, coverage, self.adapter.compile_policy(ir, coverage, self.manifest, self.profile)

    def test_rest_authority_is_not_laundered_through_tcp(self):
        ir, _coverage, result = self.compiled("openshell-rest-target-restricted.json")
        laundered = copy.deepcopy(result["generatedPolicy"])
        endpoint = laundered["network_policies"]["req-weather-api"]["endpoints"][0]
        endpoint["protocol"] = "tcp"
        endpoint.pop("rules", None)
        endpoint.pop("enforcement", None)
        reasons = self.adapter.verify_effective_policy(
            laundered,
            result["networkGrants"],
            result["substrateMappings"],
            result["binaryRestrictions"],
        )
        self.assertTrue(reasons)
        connect = copy.deepcopy(ir)
        for binding in connect["bindings"]:
            if binding.get("kind") == "api":
                binding["kind"] = "service"
                binding["operation"] = "connect"
        rejected = assess_coverage(connect, self.manifest, self.profile)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")

    def test_provider_endpoint_after_compile_fails_verification(self):
        _ir, _coverage, result = self.compiled("openshell-tcp-connect.json")
        changed = copy.deepcopy(result["generatedPolicy"])
        changed["network_policies"]["_provider_added"] = {
            "endpoints": [{"host": "other.example.com", "port": 443, "protocol": "tcp"}],
            "binaries": [{"path": "/usr/bin/curl"}],
        }
        grant = {"host": "example.com", "port": 443}
        reasons = self.slices.verify_tcp_policy(changed, grant, result["substrateMappings"], "/usr/bin/curl")
        self.assertIn("endpoint_outside_grant", reasons)

    def test_executable_restriction_replacement_fails(self):
        _ir, _coverage, result = self.compiled("openshell-rest-target-restricted.json")
        replaced = copy.deepcopy(result["generatedPolicy"])
        replaced["network_policies"]["req-weather-api"]["binaries"] = [{"path": "/usr/bin/wget"}]
        reasons = self.adapter.verify_effective_policy(
            replaced,
            result["networkGrants"],
            result["substrateMappings"],
            result["binaryRestrictions"],
        )
        self.assertIn("binary_restriction_widened", reasons)

    def test_inference_provider_is_not_a_network_escape(self):
        ir, coverage, result = self.compiled("model-inference.json")
        self.assertIsNone(result["generatedPolicy"])
        self.assertIn("model_identity_unsupported", result["diagnostics"])
        stamped = copy.deepcopy(coverage)
        stamped["authorityDecision"] = "AUTHORIZED"
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        forced = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile)
        self.assertIsNone(forced["generatedPolicy"])

    def test_mcp_server_is_not_a_generic_network_escape(self):
        _ir, _coverage, result = self.compiled("openshell-mcp-tool.json")
        escaped = copy.deepcopy(result["generatedPolicy"])
        endpoint = escaped["network_policies"]["req-list-issues"]["endpoints"][0]
        endpoint["protocol"] = "tcp"
        endpoint.pop("rules", None)
        endpoint.pop("enforcement", None)
        grant = {"host": "mcp.example.com", "port": 443, "method": "tools/call", "tool": "list_issues"}
        reasons = self.slices.verify_mcp_policy(escaped, grant, result["substrateMappings"], "/usr/bin/curl")
        self.assertIn("protocol_not_mcp", reasons)

    def test_filesystem_substrate_is_not_a_semantic_grant(self):
        _ir, coverage, result = self.compiled("openshell-tcp-connect.json")
        self.assertNotIn("/tmp", json.dumps(coverage["coverage"]["fipGrants"]))
        self.assertNotIn("/usr", json.dumps(coverage["coverage"]["fipGrants"]))
        self.assertTrue(all(item.get("source") == "execution-substrate" for item in result["substrateMappings"]))

    def test_credential_does_not_authorize_another_endpoint(self):
        document = load(EXAMPLES / "proxy-mediated-credential.json")
        ir = project(document)["operationalIr"]
        for binding in ir["bindings"]:
            if binding.get("kind") == "credential":
                binding["locator"] = {"host": "other.example.com", "port": 443}
        coverage = assess_coverage(ir, self.manifest, self.profile)
        self.assertNotEqual(coverage["compilationDisposition"], "FULL")
        self.assertIsNone(self.adapter.compile_policy(ir, coverage, self.manifest, self.profile)["generatedPolicy"])

    def test_policy_after_verification_is_a_different_document(self):
        _ir, _coverage, result = self.compiled("openshell-rest-target-restricted.json")
        verified = self.adapter.verify_effective_policy(
            result["generatedPolicy"],
            result["networkGrants"],
            result["substrateMappings"],
            result["binaryRestrictions"],
        )
        self.assertEqual(verified, [])
        later = copy.deepcopy(result["generatedPolicy"])
        later["network_policies"]["req-weather-api"]["endpoints"][0]["rules"][0]["allow"]["path"] = "/*"
        self.assertTrue(self.adapter.verify_effective_policy(
            later,
            result["networkGrants"],
            result["substrateMappings"],
            result["binaryRestrictions"],
        ))


if __name__ == "__main__":
    unittest.main()
