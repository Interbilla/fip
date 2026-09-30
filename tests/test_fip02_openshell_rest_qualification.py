"""OpenShell v0.1.2 REST qualification. No network policy is emitted."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
PROFILE = ROOT / "reference" / "fip-0.2" / "targets" / "openshell"


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OpenShellRestQualificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import jsonschema
        from referencing import Registry, Resource

        schema_dir = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
        common = load_json(schema_dir / "common.schema.json")
        policy_schema = load_json(schema_dir / "authority-policy.schema.json")
        registry = Registry().with_resources([
            ("urn:fip:0.2:common", Resource.from_contents(common)),
        ])
        validator = jsonschema.Draft202012Validator(policy_schema, registry=registry)
        cls.manifest = load_json(PROFILE / "manifest.json")
        cls.profile = load_json(PROFILE / "execution-profile.json")
        cls.probe = load_json(EXAMPLES / "openshell-rest-get.json")
        cls.architectural = load_json(EXAMPLES / "rest-get.json")
        validator.validate(cls.probe)
        validator.validate(cls.architectural)

    def assess_document(self, document, manifest=None):
        authority = assess(document)
        projected = project(document)
        coverage = None
        if projected["operationalIr"] is not None:
            coverage = assess_coverage(
                projected["operationalIr"], manifest or self.manifest, self.profile, document=document
            )
        return authority, projected, coverage

    def test_architectural_rest_probe_stays_partial(self):
        authority, projected, coverage = self.assess_document(self.architectural)
        self.assertEqual(authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(authority["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(authority["deployable"])
        self.assertEqual(projected["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(projected["deployable"])
        self.assertEqual(coverage["compilationDisposition"], "PARTIAL")
        self.assertFalse(coverage["deployable"])
        statuses = {item["requirementId"]: item["status"] for item in coverage["requirements"]}
        self.assertEqual(statuses["req-weather"], "unenforced")
        self.assertEqual(statuses["req-no-other-network"], "enforced")
        audit = {item["requirementId"]: item for item in coverage["audit"]}
        self.assertEqual(audit["req-weather"]["required"], "correlated")
        self.assertEqual(audit["req-weather"]["status"], "unenforced")

    def test_dedicated_probe_is_authorized_and_rejected_for_executable_identity(self):
        authority, projected, coverage = self.assess_document(self.probe)
        self.assertEqual(authority["authorityDecision"], "AUTHORIZED")
        self.assertEqual(authority["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(authority["deployable"])
        self.assertEqual(projected["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(projected["deployable"])
        self.assertIsNone(projected.get("generatedPolicy"))
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertFalse(coverage["deployable"])
        self.assertIn("subset_not_demonstrated", coverage["codes"])
        statuses = {item["requirementId"]: item["status"] for item in coverage["requirements"]}
        self.assertEqual(statuses["req-weather-get"], "rejected")
        self.assertEqual(statuses["req-no-other-network"], "enforced")
        bindings = {item["bindingId"]: item["status"] for item in coverage["bindings"]}
        self.assertEqual(bindings["weather-get"], "enforced")
        self.assertEqual(bindings["weather-curl"], "rejected")
        self.assertNotIn("weather.example.com", json.dumps(coverage["coverage"]["targetBaseline"]))

    def test_query_component_is_not_full(self):
        document = copy.deepcopy(self.probe)
        binding = next(item for item in document["executionBindings"] if item["bindingId"] == "weather-get")
        binding["locator"]["uri"] = "https://weather.example.com/weather?station=LAX"
        _authority, _projected, coverage = self.assess_document(document)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertFalse(coverage["deployable"])
        self.assertIn("subset_not_demonstrated", coverage["codes"])

    def test_wider_or_unsupported_dimensions_are_not_full(self):
        cases = {
            "wildcard-host": lambda document: self._set_host(document, "*.example.com"),
            "wildcard-path": lambda document: self._set_http(document, path="/weather/*"),
            "any-method": lambda document: self._set_http(document, method="*"),
            "missing-port": lambda document: self._drop_port(document),
            "port-mismatch": lambda document: self._set_port(document, 8443),
            "binary-glob": lambda document: self._set_binary(document, "/usr/bin/*"),
            "validity-bound": lambda document: self._set_lifetime(document, "validity-bound"),
            "correlated-audit": lambda document: self._set_audit(document, "correlated"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                document = mutate(copy.deepcopy(self.probe))
                _authority, projected, coverage = self.assess_document(document)
                self.assertIsNotNone(projected["operationalIr"])
                self.assertNotEqual(coverage["compilationDisposition"], "FULL")
                self.assertFalse(coverage["deployable"])

    def test_audit_only_effects_cannot_cover_a_permit(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["effects"] = ["audit-only"]
        _authority, _projected, coverage = self.assess_document(self.probe, manifest)
        self.assertNotEqual(coverage["compilationDisposition"], "FULL")
        self.assertFalse(coverage["deployable"])
        permit = next(item for item in coverage["requirements"] if item["requirementId"] == "req-weather-get")
        self.assertEqual(permit["status"], "rejected")

    def test_provider_host_outside_the_grant_is_not_full(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["substrate"] = list(manifest["substrate"]) + [{
            "substrateId": "provider-other-api",
            "description": "Attached provider endpoint outside the FIP grant",
            "kind": "api",
            "operation": "query",
            "locator": {"host": "other.example.com", "port": 443},
            "authorityBearing": False,
        }]
        _authority, _projected, coverage = self.assess_document(self.probe, manifest)
        self.assertEqual(coverage["compilationDisposition"], "REJECTED")
        self.assertIn("baseline_exceeds_grant", coverage["codes"])
        self.assertFalse(coverage["deployable"])

    def _binding(self, document, binding_id):
        return next(item for item in document["executionBindings"] if item["bindingId"] == binding_id)

    def _set_host(self, document, host):
        binding = self._binding(document, "weather-get")
        binding["locator"]["host"] = host
        binding["locator"]["uri"] = "https://weather.example.com/weather"
        return document

    def _set_http(self, document, method=None, path=None):
        http = self._binding(document, "weather-get")["protocol"]["http"]
        if method is not None:
            http["method"] = method
        if path is not None:
            http["path"] = path
        return document

    def _drop_port(self, document):
        locator = self._binding(document, "weather-get")["locator"]
        locator.pop("port")
        locator.pop("uri", None)
        return document

    def _set_port(self, document, port):
        self._binding(document, "weather-get")["locator"]["port"] = port
        return document

    def _set_binary(self, document, path):
        self._binding(document, "weather-curl")["locator"]["path"] = path
        return document

    def _set_lifetime(self, document, lifetime):
        for binding in document["executionBindings"]:
            binding["lifetime"] = lifetime
        for requirement in document["enforcementRequirements"]:
            if "lifetime" in requirement:
                requirement["lifetime"] = lifetime
        return document

    def _set_audit(self, document, audit):
        for requirement in document["enforcementRequirements"]:
            if requirement["requirementId"] == "req-weather-get":
                requirement["audit"] = audit
        return document
