"""Target-neutral Enforcement IR projection. No target policy is emitted."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, project  # noqa: E402

EXAMPLES = ROOT / "examples" / "fip-0.2"
SCHEMA_DIR = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
FORBIDDEN_KEYS = {
    "openshell",
    "landlock",
    "seccomp",
    "network_policies",
    "filesystem_policy",
    "kubernetes",
    "opa",
}


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def ir_validator():
    import jsonschema
    from referencing import Registry, Resource

    common = json.loads((SCHEMA_DIR / "common.schema.json").read_text(encoding="utf-8"))
    schema = json.loads((SCHEMA_DIR / "enforcement-ir.schema.json").read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        [
            ("urn:fip:0.2:common", Resource.from_contents(common)),
            ("urn:fip:0.2:enforcement-ir", Resource.from_contents(schema)),
        ]
    )
    return jsonschema.Draft202012Validator(schema, registry=registry)


def exchange_for(policy, action, resource):
    return {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-" + action,
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": policy["traceId"],
        "actor": {"id": "agent-field"},
        "resource": {"id": resource},
        "action": action,
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"id": policy["authorizations"][0]["authorizationId"], "validity": "valid"},
        "provenance": policy["provenance"],
    }


def keys_of(value, found=None):
    found = found if found is not None else set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(str(key).lower())
            keys_of(item, found)
    elif isinstance(value, list):
        for item in value:
            keys_of(item, found)
    return found


class ProjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = ir_validator()

    def assert_operational(self, result):
        self.assertEqual(result["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(result["deployable"])
        self.assertIsNone(result["semanticProjection"])
        ir = result["operationalIr"]
        self.assertIsNotNone(ir)
        self.assertEqual(ir["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(ir["deployable"])
        self.assertEqual(ir["authorityDecision"], "AUTHORIZED")
        self.assertNotIn(ir["compilationDisposition"], ("FULL", "PARTIAL", "REJECTED"))
        self.validator.validate(ir)
        self.assertFalse(keys_of(ir) & FORBIDDEN_KEYS)
        self.assertEqual(ir["coverage"]["auditCoverage"], "unassessed")
        self.assertEqual(ir["coverage"]["targetBaseline"], [])
        for node in ir["requirements"]:
            self.assertEqual(node["coverage"], "unassessed")
            self.assertEqual(node["auditCoverage"], "unassessed")
        for entry in ir["coverage"]["targetEnforcement"]:
            self.assertEqual(entry["status"], "unassessed")
        return ir

    def test_filesystem_read_and_write_bindings(self):
        ir = self.assert_operational(project(load("filesystem-read-write.json")))
        bindings = {item["bindingId"]: item for item in ir["bindings"]}
        self.assertEqual(bindings["in-read"]["kind"], "filesystem")
        self.assertEqual(bindings["in-read"]["operation"], "read")
        self.assertEqual(bindings["in-read"]["locator"], {"path": "/mission/input"})
        self.assertEqual(bindings["in-read"]["lifetime"], "establishment-bound")
        self.assertEqual(bindings["out-write"]["operation"], "write")
        self.assertEqual(bindings["out-write"]["locator"]["path"], "/mission/output")
        self.assertNotEqual(bindings["in-read"]["locator"]["path"], "mission:InspectionInput")
        read = next(item for item in ir["requirements"] if item["requirementId"] == "req-read")
        self.assertEqual(read["audit"], "correlated")
        self.assertEqual(read["lifetime"], "establishment-bound")
        self.assertEqual(read["authorityId"], "auth-mission-control")
        self.assertEqual(read["authorizationId"], "az-files")
        self.assertEqual(read["traceId"], "trace-files")
        self.assertEqual(ir["policyId"], "pol-files")
        self.assertNotIn("exchangeId", ir)

    def test_rest_get_preserves_method_and_path(self):
        ir = self.assert_operational(project(load("rest-get.json")))
        binding = ir["bindings"][0]
        self.assertEqual(binding["kind"], "api")
        self.assertEqual(binding["protocol"]["http"], {"method": "GET", "path": "/weather"})
        weather = next(item for item in ir["requirements"] if item["requirementId"] == "req-weather")
        self.assertEqual(weather["constraints"][0]["method"], "GET")
        self.assertEqual(weather["constraints"][0]["path"], "/weather")
        self.assertNotEqual(binding["protocol"]["http"]["method"], "GetWeather")
        self.assertEqual(binding["lifetime"], "revocable")
        self.assertEqual(weather["lifetime"], "revocable")

    def test_model_invocation(self):
        ir = self.assert_operational(project(load("model-inference.json")))
        bindings = {item["bindingId"]: item for item in ir["bindings"]}
        self.assertEqual(bindings["model-invoke"]["kind"], "model")
        self.assertEqual(bindings["model-invoke"]["operation"], "invoke")
        self.assertEqual(bindings["model-invoke"]["locator"], {"modelId": "field-summary-v1"})
        self.assertNotIn("path", bindings["model-invoke"]["locator"])
        self.assertEqual(bindings["provider-invoke"]["kind"], "inference-provider")
        self.assertEqual(bindings["provider-invoke"]["locator"]["serviceId"], "inference-provider:field-summary")

    def test_proxy_mediated_credential(self):
        ir = self.assert_operational(project(load("proxy-mediated-credential.json")))
        binding = next(item for item in ir["bindings"] if item["bindingId"] == "model-credential")
        self.assertEqual(binding["kind"], "credential")
        self.assertEqual(binding["disclosure"], "proxy-mediated")
        self.assertNotIn("secret", keys_of(ir))

    def test_model_and_credential_all_of_group(self):
        policy = load("model-inference.json")
        policy["resources"].append({"id": "credential:FieldModel"})
        policy["executionBindings"].append({
            "bindingId": "model-credential",
            "resourceId": "credential:FieldModel",
            "actionId": "SummarizeWithModel",
            "kind": "credential",
            "operation": "invoke",
            "locator": {"serviceId": "credential:FieldModel"},
            "disclosure": "proxy-mediated",
            "lifetime": "revocable",
        })
        policy["enforcementRequirements"].append({
            "requirementId": "req-credential",
            "effect": "permit",
            "bindingIds": ["model-credential"],
            "composition": "allOf",
            "groupId": "model-call",
            "audit": "correlated",
            "lifetime": "revocable",
        })
        policy["authorizations"][0]["requirementIds"].append("req-credential")
        policy["authorizations"][0]["resourceIds"].append("credential:FieldModel")
        ir = self.assert_operational(project(policy))
        group = next(item for item in ir["groups"] if item["groupId"] == "model-call")
        self.assertEqual(group["composition"], "allOf")
        self.assertEqual(group["requirementIds"], ["req-credential", "req-model", "req-provider"])

    def test_multi_binding_action_keeps_all_of_members(self):
        ir = self.assert_operational(project(load("multi-binding-action.json")))
        group = ir["groups"][0]
        self.assertEqual(group["composition"], "allOf")
        self.assertEqual(group["requirementIds"], ["req-connect", "req-credential", "req-get"])
        self.assertEqual(
            {item["bindingId"] for item in ir["bindings"]},
            {"status-connect", "status-credential", "status-get"},
        )
        self.assertEqual(ir["coverage"]["fipGrants"], ["req-connect", "req-credential", "req-get"])

    def test_explicit_prohibition_survives_on_the_authorized_slice(self):
        policy = load("prohibition.json")
        whole = project(policy)
        self.assertEqual(whole["authorityDecision"], "DENIED")
        self.assertIsNone(whole["operationalIr"])
        allowed = exchange_for(policy, "ReadInspectionInput", "mission:InspectionInput")
        ir = self.assert_operational(project(allowed, policy=policy))
        self.assertEqual(ir["exchangeId"], "ex-ReadInspectionInput")
        self.assertEqual(ir["prohibitions"][0]["prohibitionId"], "proh-output-read")
        effects = {item["requirementId"]: item["effect"] for item in ir["requirements"]}
        self.assertEqual(effects["req-read-input"], "permit")
        self.assertEqual(effects["req-deny-output"], "deny")
        self.assertNotIn("req-read-output", effects)
        self.assertEqual(ir["coverage"]["fipGrants"], ["req-read-input"])
        self.assertIn("out-read", {item["bindingId"] for item in ir["bindings"]})

    def test_lifetimes_and_audit_are_preserved_and_unassessed(self):
        files = self.assert_operational(project(load("filesystem-read-write.json")))
        self.assertTrue(all(item["lifetime"] == "establishment-bound" for item in files["bindings"]))
        rest = self.assert_operational(project(load("rest-get.json")))
        self.assertEqual(rest["bindings"][0]["lifetime"], "revocable")
        policy = load("filesystem-read-write.json")
        for binding in policy["executionBindings"]:
            binding["lifetime"] = "validity-bound"
        for requirement in policy["enforcementRequirements"]:
            requirement["lifetime"] = "validity-bound"
        bounded = self.assert_operational(project(policy))
        self.assertTrue(all(item["lifetime"] == "validity-bound" for item in bounded["requirements"]))
        self.assertTrue(all(item["auditCoverage"] == "unassessed" for item in bounded["requirements"]))

    def test_unknown_kind_and_operation_fail_closed(self):
        unknown_kind = load("filesystem-read-write.json")
        unknown_kind["executionBindings"][0]["kind"] = "sandbox"
        kind_result = project(unknown_kind)
        self.assertEqual(kind_result["authorityDecision"], "AUTHORIZED")
        self.assertIsNone(kind_result["operationalIr"])
        self.assertIn("unknown_binding_kind", kind_result["reasons"])
        unknown_operation = load("filesystem-read-write.json")
        unknown_operation["executionBindings"][0]["operation"] = "mmap"
        operation_result = project(unknown_operation)
        self.assertIsNone(operation_result["operationalIr"])
        self.assertIn("unknown_operation", operation_result["reasons"])

    def test_dangling_references_produce_no_operational_ir(self):
        dangling_binding = load("filesystem-read-write.json")
        dangling_binding["executionBindings"] = [
            item for item in dangling_binding["executionBindings"] if item["bindingId"] != "in-read"
        ]
        binding_result = project(dangling_binding)
        self.assertEqual(binding_result["authorityDecision"], "INCOMPLETE")
        self.assertIsNone(binding_result["operationalIr"])
        dangling_requirement = load("filesystem-read-write.json")
        dangling_requirement["authorizations"][0]["requirementIds"] = ["req-missing"]
        requirement_result = project(dangling_requirement)
        self.assertEqual(requirement_result["authorityDecision"], "INCOMPLETE")
        self.assertIsNone(requirement_result["operationalIr"])

    def test_denied_incomplete_and_review_produce_no_operational_ir(self):
        policy = load("prohibition.json")
        denied = project(exchange_for(policy, "ReadInspectionOutput", "mission:InspectionOutput"), policy=policy)
        self.assertEqual(denied["authorityDecision"], "DENIED")
        self.assertIsNone(denied["operationalIr"])
        incomplete_policy = load("filesystem-read-write.json")
        incomplete_policy["authorities"] = []
        incomplete = project(incomplete_policy)
        self.assertEqual(incomplete["authorityDecision"], "INCOMPLETE")
        self.assertIsNone(incomplete["operationalIr"])
        review_doc = load("lifted-0.1-exchange.json")
        review_doc["normative"]["state"] = "unknown"
        review = project(review_doc)
        self.assertEqual(review["authorityDecision"], "REVIEW")
        self.assertIsNone(review["operationalIr"])
        self.assertIsNone(review["semanticProjection"])

    def test_semantic_only_has_no_execution_ir(self):
        result = project(load("lifted-0.1-exchange.json"))
        self.assertEqual(result["authorityDecision"], "AUTHORIZED")
        self.assertIsNone(result["operationalIr"])
        projection = result["semanticProjection"]
        self.assertFalse(projection["operational"])
        self.assertEqual(projection["executionBindings"], [])
        self.assertNotIn("locator", keys_of(projection))
        self.assertEqual(projection["exchangeId"], "lift-share-status")
        self.assertEqual(projection["traceId"], "t-lift")

    def test_author_stamped_target_fields_are_rejected(self):
        policy = load("filesystem-read-write.json")
        policy["filesystem_policy"] = {"read_only": ["/tmp"]}
        result = project(policy)
        self.assertIsNone(result["operationalIr"])
        self.assertIn("author_supplied_target_field", result["reasons"])
        self.assertFalse(keys_of(result["operationalIr"]) & FORBIDDEN_KEYS)

    def test_semantic_identifiers_are_not_guessed_into_locators(self):
        policy = load("filesystem-read-write.json")
        policy["executionBindings"][0]["locator"] = {}
        result = project(policy)
        self.assertIsNone(result["operationalIr"])
        self.assertIn("missing_locator", result["reasons"])
        self.assertNotIn("mission:InspectionInput", json.dumps(result["operationalIr"]))
        service = load("rest-get.json")
        service["executionBindings"][0]["locator"] = {}
        service["executionBindings"][0]["protocol"] = {"family": "http", "http": {"method": "GET", "path": "/weather"}}
        service_result = project(service)
        self.assertIsNone(service_result["operationalIr"])
        self.assertNotIn("service:Weather", json.dumps(service_result["operationalIr"]))

    def test_any_of_structure_survives(self):
        policy = load("multi-binding-action.json")
        for requirement in policy["enforcementRequirements"]:
            requirement["composition"] = "anyOf"
        ir = self.assert_operational(project(policy))
        self.assertEqual(len(ir["groups"]), 1)
        self.assertEqual(ir["groups"][0]["composition"], "anyOf")
        self.assertEqual(len(ir["groups"][0]["requirementIds"]), 3)
        self.assertEqual(len(ir["requirements"]), 3)

    def test_approval_provenance_survives_and_effect_stays_require_approval(self):
        policy = load("human-approval.json")
        waiting = project(policy)
        self.assertEqual(waiting["authorityDecision"], "AUTHORIZED")
        self.assertIn("approval_required", waiting["codes"])
        self.assertIsNone(waiting["operationalIr"])
        self.assertEqual(assess(policy)["authorityDecision"], "AUTHORIZED")
        satisfied = project(policy, approvals=[load("human-approval-decision.json")])
        ir = self.assert_operational(satisfied)
        requirement = ir["requirements"][0]
        self.assertEqual(requirement["effect"], "require-approval")
        self.assertNotIn(requirement["requirementId"], ir["coverage"]["fipGrants"])
        approval = ir["approvals"][0]
        self.assertTrue(approval["satisfied"])
        self.assertEqual(approval["effect"], "require-approval")
        self.assertEqual(approval["decisionId"], "dec-approve-delete")
        self.assertEqual(approval["exchangeId"], "ex-approve-delete")
        self.assertEqual(approval["provenance"]["traceId"], "trace-approval-decision")
        self.assertEqual(approval["provenance"]["assertedBy"], "approver-mission")

    def test_projection_catalog_lists_the_required_cases(self):
        catalog = json.loads(
            (ROOT / "conformance" / "fip-0.2" / "projection" / "catalog.json").read_text(encoding="utf-8")
        )
        self.assertEqual(catalog["compilationDisposition"], "NOT_COMPILED")
        self.assertFalse(catalog["deployable"])
        self.assertEqual(len(catalog["cases"]), 25)
        self.assertEqual(len({item["id"] for item in catalog["cases"]}), 25)

    def test_conformance_vectors_match_projection(self):
        vectors = ROOT / "conformance" / "fip-0.2" / "projection"
        self.assertEqual(
            self.assert_operational(project(load("filesystem-read-write.json"))),
            json.loads((vectors / "filesystem-ir.json").read_text(encoding="utf-8")),
        )
        self.assertEqual(
            self.assert_operational(project(load("rest-get.json"))),
            json.loads((vectors / "rest-get-ir.json").read_text(encoding="utf-8")),
        )
        self.assertEqual(
            self.assert_operational(project(load("multi-binding-action.json"))),
            json.loads((vectors / "multi-binding-ir.json").read_text(encoding="utf-8")),
        )
        policy = load("prohibition.json")
        prohibited = self.assert_operational(
            project(exchange_for(policy, "ReadInspectionInput", "mission:InspectionInput"), policy=policy)
        )
        self.assertEqual(prohibited, json.loads((vectors / "prohibition-ir.json").read_text(encoding="utf-8")))
        approved = self.assert_operational(
            project(load("human-approval.json"), approvals=[load("human-approval-decision.json")])
        )
        self.assertEqual(approved, json.loads((vectors / "approval-ir.json").read_text(encoding="utf-8")))

    def test_projection_does_not_mutate_inputs(self):
        policy = load("rest-get.json")
        snapshot = copy.deepcopy(policy)
        project(policy)
        self.assertEqual(policy, snapshot)


if __name__ == "__main__":
    unittest.main()
