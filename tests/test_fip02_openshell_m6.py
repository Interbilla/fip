"""Pinned OpenShell v0.1.2 surfaces beyond filesystem and REST.

These tests do not start a sandbox. TCP and MCP runtime stay unobserved.
Credential use, exact model identity, and process identity do not compile.
"""

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
CONFORMANCE = ROOT / "conformance" / "fip-0.2" / "openshell"
TCP_HASH = "d7a2c6495adbf67144be31e14ac4237d9db9876eeb3a2d913bff0c63fcbf103b"
MCP_HASH = "5e24f694358aa4c1566546e2df8d5d369afdbc24bb4f49d5f68fee261dc5ba3a"
FILESYSTEM_HASH = "6cf6240b86186a0d94fcffe49034e8cb2fb5a03835dea68c765ceddb47456afb"
REST_HASH = "487cf5c82708397a7a45e48d6d7f2b97d7d948715f235dba215ca2ab53c8b504"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OpenShellRemainingSurfacesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import jsonschema
        from referencing import Registry, Resource

        cls.adapter = load_module("openshell_adapter_m6", TARGET / "adapter.py")
        cls.runtime = load_module("openshell_runtime_m6", TARGET / "runtime.py")
        cls.slices = load_module("openshell_slices_m6", TARGET / "network_slices.py")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")
        schema_dir = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
        common = load(schema_dir / "common.schema.json")
        policy_schema = load(schema_dir / "authority-policy.schema.json")
        registry = Registry().with_resources([
            ("urn:fip:0.2:common", Resource.from_contents(common)),
        ])
        validator = jsonschema.Draft202012Validator(policy_schema, registry=registry)
        for name in ("openshell-tcp-connect.json", "openshell-mcp-tool.json", "openshell-process-execute.json"):
            validator.validate(load(EXAMPLES / name))

    def compile_example(self, name):
        document = load(EXAMPLES / name)
        authority = assess(document)
        ir = project(document)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile)
        result = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile)
        return authority, ir, coverage, result

    def test_tcp_connect_compiles_without_application_fields(self):
        authority, _ir, coverage, result = self.compile_example("openshell-tcp-connect.json")
        self.assertEqual(authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(coverage["compilationDisposition"], "FULL")
        self.assertTrue(coverage["deployable"])
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        self.assertEqual(result["effectivePolicy"], "unverified")
        self.assertEqual(result["monotonicity"], "demonstrated")
        policy = result["generatedPolicy"]
        endpoint = policy["network_policies"]["req-example-connect"]["endpoints"][0]
        self.assertEqual(endpoint, {"host": "example.com", "port": 443, "protocol": "tcp"})
        self.assertNotIn("rules", endpoint)
        self.assertNotIn("enforcement", endpoint)
        self.assertNotIn("access", endpoint)
        self.assertEqual(policy, load(CONFORMANCE / "tcp-connect-policy.json"))
        again = self.compile_example("openshell-tcp-connect.json")[3]["generatedPolicy"]
        self.assertEqual(self.runtime.canonical_policy_hash(policy), TCP_HASH)
        self.assertEqual(self.runtime.canonical_policy_hash(again), TCP_HASH)
        grant = {"requirementId": "req-example-connect", "bindingId": "example-connect", "host": "example.com", "port": 443}
        substrate = result["substrateMappings"]
        self.assertEqual(self.slices.verify_tcp_policy(policy, grant, substrate, "/usr/bin/curl"), [])
        self.assertTrue(all(item.get("source") == "execution-substrate" for item in substrate))
        self.assertNotIn("/usr", json.dumps(coverage["coverage"]["fipGrants"]))

    def test_tcp_negative_cases_fail_closed(self):
        _authority, ir, coverage, result = self.compile_example("openshell-tcp-connect.json")
        grant = {"host": "example.com", "port": 443}
        substrate = result["substrateMappings"]
        widened = copy.deepcopy(result["generatedPolicy"])
        widened["network_policies"]["req-example-connect"]["endpoints"][0]["host"] = "example.org"
        self.assertIn("host_widened", self.slices.verify_tcp_policy(widened, grant, substrate, "/usr/bin/curl"))
        extra_port = copy.deepcopy(result["generatedPolicy"])
        extra_port["network_policies"]["req-example-connect"]["endpoints"][0]["port"] = 8443
        self.assertIn("port_widened", self.slices.verify_tcp_policy(extra_port, grant, substrate, "/usr/bin/curl"))
        extra_binary = copy.deepcopy(result["generatedPolicy"])
        extra_binary["network_policies"]["req-example-connect"]["binaries"] = [{"path": "/usr/bin/wget"}]
        self.assertIn("binary_restriction_widened", self.slices.verify_tcp_policy(extra_binary, grant, substrate, "/usr/bin/curl"))
        provider = copy.deepcopy(result["generatedPolicy"])
        provider["network_policies"]["_provider_extra"] = provider["network_policies"]["req-example-connect"]
        self.assertIn("endpoint_outside_grant", self.slices.verify_tcp_policy(provider, grant, substrate, "/usr/bin/curl"))
        mutated = copy.deepcopy(ir)
        mutated["bindings"][0]["protocol"] = {"family": "http", "http": {"method": "GET", "path": "/"}}
        rejected = assess_coverage(mutated, self.manifest, self.profile)
        self.assertEqual(rejected["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", rejected["codes"])
        globbed = copy.deepcopy(ir)
        globbed["bindings"][0]["locator"]["host"] = "*.example.com"
        glob_coverage = assess_coverage(globbed, self.manifest, self.profile)
        self.assertEqual(glob_coverage["compilationDisposition"], "REJECTED")

    def test_mcp_tool_compiles_only_the_named_tool(self):
        authority, _ir, coverage, result = self.compile_example("openshell-mcp-tool.json")
        self.assertEqual(authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(coverage["compilationDisposition"], "FULL")
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        policy = result["generatedPolicy"]
        endpoint = policy["network_policies"]["req-list-issues"]["endpoints"][0]
        self.assertEqual(endpoint["protocol"], "mcp")
        self.assertEqual(endpoint["enforcement"], "enforce")
        self.assertEqual(endpoint["rules"], [{"allow": {"method": "tools/call", "tool": "list_issues"}}])
        rendered = json.dumps(policy)
        self.assertNotIn("initialize", rendered)
        self.assertNotIn("allow_all_known_mcp_methods", rendered)
        self.assertEqual(policy, load(CONFORMANCE / "mcp-tool-policy.json"))
        self.assertEqual(self.runtime.canonical_policy_hash(policy), MCP_HASH)
        grant = {
            "host": "mcp.example.com",
            "port": 443,
            "method": "tools/call",
            "tool": "list_issues",
        }
        self.assertEqual(self.slices.verify_mcp_policy(policy, grant, result["substrateMappings"], "/usr/bin/curl"), [])
        stripped = copy.deepcopy(policy)
        del stripped["network_policies"]["req-list-issues"]["endpoints"][0]["rules"][0]["allow"]["tool"]
        self.assertIn("tool_widened", self.slices.verify_mcp_policy(stripped, grant, result["substrateMappings"], "/usr/bin/curl"))
        aliased = copy.deepcopy(policy)
        aliased["network_policies"]["req-list-issues"]["endpoints"][0]["rules"][0]["allow"]["tool"] = "list_issues_alias"
        self.assertIn("tool_widened", self.slices.verify_mcp_policy(aliased, grant, result["substrateMappings"], "/usr/bin/curl"))

    def test_mcp_broader_tool_set_is_rejected(self):
        document = load(EXAMPLES / "openshell-mcp-tool.json")
        ir = project(document)["operationalIr"]
        ir["bindings"][0]["protocol"]["mcp"]["tool"] = "list_*"
        coverage = assess_coverage(ir, self.manifest, self.profile)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        missing = copy.deepcopy(project(document)["operationalIr"])
        del missing["bindings"][0]["protocol"]["mcp"]["tool"]
        missing_coverage = assess_coverage(missing, self.manifest, self.profile)
        self.assertEqual(missing_coverage["compilationDisposition"], "REJECTED")

    def test_process_execute_is_not_a_grant(self):
        authority, _ir, coverage, result = self.compile_example("openshell-process-execute.json")
        self.assertEqual(authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertEqual(coverage["codes"], ["unsupported_requirement"])
        self.assertIsNone(result["generatedPolicy"])
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        self.assertNotIn("process", self.manifest["kinds"])

    def test_credential_with_host_and_port_stays_rejected(self):
        document = load(EXAMPLES / "proxy-mediated-credential.json")
        ir = project(document)["operationalIr"]
        for binding in ir["bindings"]:
            if binding.get("kind") == "credential":
                binding["locator"] = {"host": "api.example.com", "port": 443, "serviceId": binding["locator"]["serviceId"]}
        coverage = assess_coverage(ir, self.manifest, self.profile)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        stamped = copy.deepcopy(coverage)
        stamped["authorityDecision"] = "AUTHORIZED"
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        forced = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile)
        self.assertIsNone(forced["generatedPolicy"])
        self.assertIn("credential_use_not_independent", forced["diagnostics"])

    def test_model_provider_is_not_model_authorization(self):
        _authority, ir, coverage, result = self.compile_example("model-inference.json")
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("model_identity_unsupported", result["diagnostics"])
        self.assertIsNone(result["generatedPolicy"])
        self.assertFalse(self.manifest["precision"]["modelId"])
        stamped = copy.deepcopy(coverage)
        stamped["authorityDecision"] = "AUTHORIZED"
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        forced = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile)
        self.assertIsNone(forced["generatedPolicy"])
        self.assertIn("model_identity_unsupported", forced["diagnostics"])

    def test_filesystem_and_rest_hashes_remain(self):
        filesystem = load(CONFORMANCE / "filesystem-policy.json")
        rest = load(CONFORMANCE / "rest-target-policy.json")
        self.assertEqual(self.runtime.canonical_policy_hash(filesystem), FILESYSTEM_HASH)
        self.assertEqual(self.runtime.canonical_policy_hash(rest), REST_HASH)


if __name__ == "__main__":
    unittest.main()
