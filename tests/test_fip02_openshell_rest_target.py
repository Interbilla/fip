"""Target-restricted REST slice. The binary path is deployment configuration."""

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
GOLDEN = ROOT / "conformance" / "fip-0.2" / "openshell" / "rest-target-policy.json"
FILESYSTEM_HASH = "6cf6240b86186a0d94fcffe49034e8cb2fb5a03835dea68c765ceddb47456afb"
REST_HASH = "487cf5c82708397a7a45e48d6d7f2b97d7d948715f235dba215ca2ab53c8b504"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class TargetRestrictedRestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import jsonschema
        from referencing import Registry, Resource

        schema_dir = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
        common = load(schema_dir / "common.schema.json")
        policy_schema = load(schema_dir / "authority-policy.schema.json")
        profile_schema = load(schema_dir / "compilation-profile.schema.json")
        registry = Registry().with_resources([
            ("urn:fip:0.2:common", Resource.from_contents(common)),
        ])
        jsonschema.Draft202012Validator(policy_schema, registry=registry).validate(
            load(EXAMPLES / "openshell-rest-target-restricted.json")
        )
        cls.adapter = load_module("openshell_adapter_target_rest", TARGET / "adapter.py")
        cls.runtime = load_module("openshell_runtime_target_rest", TARGET / "runtime.py")
        cls.rest = load_module("openshell_rest_target", TARGET / "rest.py")
        cls.manifest = load(TARGET / "manifest.json")
        cls.profile = load(TARGET / "execution-profile.json")
        jsonschema.Draft202012Validator(profile_schema, registry=registry).validate(cls.profile)
        cls.document = load(EXAMPLES / "openshell-rest-target-restricted.json")
        cls.strict = load(EXAMPLES / "openshell-rest-get.json")
        cls.authority = assess(cls.document)
        cls.projection = project(cls.document)
        cls.ir = cls.projection["operationalIr"]
        cls.coverage = assess_coverage(cls.ir, cls.manifest, cls.profile, document=cls.document)
        cls.result = cls.adapter.compile_policy(cls.ir, cls.coverage, cls.manifest, cls.profile, document=cls.document)

    def test_semantic_grant_has_no_executable_binding(self):
        text = (EXAMPLES / "openshell-rest-target-restricted.json").read_text(encoding="utf-8")
        self.assertNotIn("/usr/bin/curl", text)
        self.assertNotIn('"kind": "executable"', text)
        kinds = {item["kind"] for item in self.document["executionBindings"]}
        self.assertEqual(kinds, {"api"})
        self.assertEqual(self.document["enforcementRequirements"][0]["bindingIds"], ["weather-get"])
        self.assertEqual(self.coverage["coverage"]["fipGrants"], ["req-weather-api"])
        self.assertEqual(self.authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(self.projection["compilationDisposition"], "NOT_COMPILED")
        self.assertEqual(self.coverage["compilationDisposition"], "FULL")
        self.assertTrue(self.coverage["deployable"])

    def test_profile_binary_is_compiled_as_a_target_restriction(self):
        result = self.result
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertTrue(result["deployable"])
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        self.assertEqual(result["effectivePolicy"], "unverified")
        self.assertEqual(result["monotonicity"], "demonstrated")
        self.assertEqual(result["targetExecutableRestriction"], "/usr/bin/curl")
        self.assertEqual(result["executableIdentity"], "approximated")
        self.assertTrue(result["descendantInheritance"])
        self.assertEqual(result["authorityRole"], "target-side restriction")
        self.assertEqual(result["sourceBindingIds"], ["weather-get"])
        policy = result["generatedPolicy"]
        endpoint = policy["network_policies"]["req-weather-api"]["endpoints"][0]
        self.assertEqual(endpoint["host"], "weather.example.com")
        self.assertEqual(endpoint["port"], 443)
        self.assertEqual(endpoint["protocol"], "rest")
        self.assertEqual(endpoint["enforcement"], "enforce")
        self.assertEqual(endpoint["rules"], [{"allow": {"method": "GET", "path": "/weather"}}])
        self.assertNotIn("access", endpoint)
        self.assertNotIn("tls", endpoint)
        self.assertEqual(policy["network_policies"]["req-weather-api"]["binaries"], [{"path": "/usr/bin/curl"}])
        restriction = next(item for item in result["ruleMappings"] if item["source"] == "target-restriction")
        self.assertNotIn("bindingId", restriction)
        self.assertEqual(restriction["profileId"], "openshell-v0.1.2-execution-substrate")
        self.assertEqual(result["generatedPolicy"], load(GOLDEN))
        self.assertEqual(self.rest.parse_network_yaml(result["policyYaml"]), policy)
        self.assertEqual(self.runtime.canonical_policy_hash(policy), REST_HASH)
        self.assertEqual(self.runtime.canonical_policy_hash(load(GOLDEN)), REST_HASH)

    def test_round_trip_keeps_semantic_authority_separate_from_the_restriction(self):
        extracted = self.result["extractedAuthority"]
        semantic = extracted["semanticAuthority"]
        self.assertEqual(semantic, [{
            "host": "weather.example.com",
            "port": 443,
            "method": "GET",
            "path": "/weather",
            "requirementId": "req-weather-api",
            "bindingId": "weather-get",
        }])
        self.assertEqual(extracted["targetRestrictions"], [{
            "path": "/usr/bin/curl",
            "executableIdentity": "approximated",
            "descendantInheritance": True,
            "authorityRole": "target-side restriction",
        }])
        self.assertNotIn("/usr/bin/curl", json.dumps(semantic))
        grant = self.result["networkGrants"][0]
        for item in semantic:
            self.assertEqual(item["host"], grant["host"])
            self.assertEqual(item["port"], grant["port"])
            self.assertEqual(item["method"], grant["method"])
            self.assertEqual(item["path"], grant["path"])
        self.assertEqual(
            self.adapter.verify_effective_policy(
                self.result["generatedPolicy"],
                self.result["networkGrants"],
                extracted["substrate"],
                self.result["binaryRestrictions"],
            ),
            [],
        )

    def test_strict_executable_probe_stays_rejected(self):
        ir = project(self.strict)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile, document=self.strict)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        self.assertFalse(coverage["deployable"])
        result = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=self.strict)
        self.assertIsNone(result["generatedPolicy"])
        self.assertIn("executable_identity_not_exact", result["diagnostics"])
        self.assertEqual(result["runtimeDisposition"], "UNOBSERVED")
        stamped = copy.deepcopy(coverage)
        stamped["compilationDisposition"] = "FULL"
        stamped["deployable"] = True
        stamped["selectedRequirementIds"] = ["req-weather-get", "req-no-other-network"]
        for item in stamped["requirements"]:
            item["status"] = "enforced"
        forced = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile, document=self.strict)
        self.assertIsNone(forced["generatedPolicy"])
        self.assertIn("executable_identity_not_exact", forced["diagnostics"])

    def test_missing_or_inferred_profile_binary_is_not_compiled(self):
        missing = copy.deepcopy(self.profile)
        missing.pop("targetExecutableRestrictions")
        result = self.adapter.compile_policy(self.ir, self.coverage, self.manifest, missing, document=self.document)
        self.assertIsNone(result["generatedPolicy"])
        self.assertFalse(result["deployable"])
        self.assertIn("target_binary_not_configured", result["diagnostics"])
        inferred = copy.deepcopy(missing)
        inferred["inferredBinary"] = "/usr/bin/curl"
        result = self.adapter.compile_policy(self.ir, self.coverage, self.manifest, inferred, document=self.document)
        self.assertIsNone(result["generatedPolicy"])
        self.assertIn("target_binary_not_configured", result["diagnostics"])
        self.assertNotIn("/usr/bin/curl", json.dumps(result["generatedPolicy"]))

    def test_query_host_port_method_and_path_widening_are_rejected(self):
        stamped = copy.deepcopy(self.coverage)
        cases = {
            "host_not_exact": self._faithful(locator={"host": "*.example.com", "uri": "https://*.example.com/weather"}),
            "uri_disagrees": self._faithful(locator={"port": 8443}),
            "method_not_exact": self._faithful(http={"method": "*"}),
            "path_not_exact": self._faithful(http={"path": "/weather/*"}),
            "query_precision_unsupported": self._faithful(locator={"uri": "https://weather.example.com/weather?station=LAX"}),
        }
        for diagnostic, (document, ir) in cases.items():
            coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
            self.assertNotEqual(coverage["compilationDisposition"], "FULL", diagnostic)
            self.assertFalse(coverage["deployable"], diagnostic)
            result = self.adapter.compile_policy(ir, stamped, self.manifest, self.profile, document=document)
            self.assertIsNone(result["generatedPolicy"], diagnostic)
            self.assertFalse(result["deployable"], diagnostic)
            self.assertIn(diagnostic, result["diagnostics"], diagnostic)
            self.assertEqual(result["runtimeDisposition"], "UNOBSERVED", diagnostic)

    def test_effective_policy_rejects_same_host_and_provider_widening(self):
        policy = self.result["generatedPolicy"]
        grants = self.result["networkGrants"]
        binaries = self.result["binaryRestrictions"]
        substrate = self.result["extractedAuthority"]["substrate"]
        def rule(candidate):
            return candidate["network_policies"]["req-weather-api"]

        mutations = [
            ("host_widened", lambda candidate: rule(candidate)["endpoints"][0].__setitem__("host", "*.example.com")),
            ("port_widened", lambda candidate: rule(candidate)["endpoints"][0].__setitem__("port", 8443)),
            ("method_widened", lambda candidate: rule(candidate)["endpoints"][0]["rules"][0]["allow"].__setitem__("method", "*")),
            ("path_widened", lambda candidate: rule(candidate)["endpoints"][0]["rules"][0]["allow"].__setitem__("path", "/weather/**")),
            ("binary_restriction_widened", lambda candidate: rule(candidate)["binaries"].append({"path": "/usr/bin/wget"})),
            ("audit_enforcement_does_not_block", lambda candidate: rule(candidate)["endpoints"][0].__setitem__("enforcement", "audit")),
            ("protocol_downgraded", lambda candidate: self._downgrade(rule(candidate))),
            ("tls_inspection_disabled", lambda candidate: rule(candidate)["endpoints"][0].__setitem__("tls", "skip")),
            ("access_preset_widens", lambda candidate: self._preset(rule(candidate))),
            ("provider_authority_not_a_grant", self._provider_other_host),
            ("method_widened", self._provider_broader_method),
        ]
        for diagnostic, mutate in mutations:
            candidate = copy.deepcopy(policy)
            mutate(candidate)
            reasons = self.adapter.verify_effective_policy(candidate, grants, substrate, binaries)
            self.assertIn(diagnostic, reasons, mutate.__name__ if hasattr(mutate, "__name__") else diagnostic)

    def test_filesystem_hash_is_unchanged(self):
        document = load(EXAMPLES / "openshell-filesystem-read-write.json")
        ir = project(document)["operationalIr"]
        coverage = assess_coverage(ir, self.manifest, self.profile, document=document)
        result = self.adapter.compile_policy(ir, coverage, self.manifest, self.profile, document=document)
        self.assertEqual(result["compilationDisposition"], "FULL")
        self.assertNotIn("network_policies", result["generatedPolicy"])
        self.assertEqual(self.runtime.canonical_policy_hash(result["generatedPolicy"]), FILESYSTEM_HASH)

    def _binding(self, ir):
        return next(item for item in ir["bindings"] if item["bindingId"] == "weather-get")

    def _faithful(self, locator=None, http=None):
        document = copy.deepcopy(self.document)
        binding = next(item for item in document["executionBindings"] if item["bindingId"] == "weather-get")
        if locator:
            binding["locator"].update(locator)
        if http:
            binding["protocol"]["http"].update(http)
        return document, project(document)["operationalIr"]

    def _set_locator(self, host=None, port=None, uri=None):
        ir = copy.deepcopy(self.ir)
        locator = self._binding(ir)["locator"]
        if host is not None:
            locator["host"] = host
        if port is not None:
            locator["port"] = port
        if uri is not None:
            locator["uri"] = uri
        return ir

    def _set_http(self, method=None, path=None):
        ir = copy.deepcopy(self.ir)
        http = self._binding(ir)["protocol"]["http"]
        if method is not None:
            http["method"] = method
        if path is not None:
            http["path"] = path
        return ir

    def _downgrade(self, rule):
        rule["endpoints"][0]["protocol"] = "tcp"
        rule["endpoints"][0].pop("rules", None)

    def _preset(self, rule):
        rule["endpoints"][0].pop("rules", None)
        rule["endpoints"][0]["access"] = "read-only"

    def _provider_other_host(self, policy):
        policy["network_policies"]["_provider_work_github"] = {
            "endpoints": [{
                "host": "api.github.com",
                "port": 443,
                "protocol": "rest",
                "enforcement": "enforce",
                "rules": [{"allow": {"method": "GET", "path": "/"}}],
            }],
            "binaries": [{"path": "/usr/bin/curl"}],
        }

    def _provider_broader_method(self, policy):
        policy["network_policies"]["_provider_same_endpoint"] = {
            "endpoints": [{
                "host": "weather.example.com",
                "port": 443,
                "protocol": "rest",
                "enforcement": "enforce",
                "rules": [{"allow": {"method": "*", "path": "/weather/**"}}],
            }],
            "binaries": [{"path": "/usr/bin/curl"}],
        }


if __name__ == "__main__":
    unittest.main()
