"""Q13D deterministic combinatorial qualification.

The oracle is the case specification. It does not ask the evaluator what the
expected decision should be. Re-running the same generator version and seed
rebuilds the same ordered case ids.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project, verify_derivation  # noqa: E402

GENERATOR = "q13d-generator-4"
RUN_ID = "q13d-run-4"
OUT = ROOT / "docs" / "evidence" / "fip-0.2" / "q13" / "q13d-combinatorial" / RUN_ID
EXAMPLES = ROOT / "examples" / "fip-0.2"
REFERENCE = ROOT / "reference" / "fip-0.2"
SEEDS = [f"q13d-seed-{index:04d}" for index in range(1, 7)]

_spec = importlib.util.spec_from_file_location("openshell_adapter", REFERENCE / "targets" / "openshell" / "adapter.py")
ADAPTER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ADAPTER)
MANIFEST = json.loads((REFERENCE / "targets" / "openshell" / "manifest.json").read_text(encoding="utf-8"))
PROFILE = json.loads((REFERENCE / "targets" / "openshell" / "execution-profile.json").read_text(encoding="utf-8"))

DIMENSIONS = {
    "actor": ("exact", "substituted", "absent"),
    "resource": ("exact", "substituted", "missing"),
    "action": ("exact", "unauthorized"),
    "purpose": ("exact", "substituted", "missing"),
    "scope": ("absent", "exact", "substituted"),
    "authority": ("exact", "substituted", "foreign"),
    "authorization_ref": ("exact", "substituted", "expired", "revoked"),
    "delegation": ("none", "valid", "false", "expired", "revoked", "foreign"),
    "policy_validity": ("valid", "expired", "revoked", "not-yet-valid", "superseded"),
    "approval": ("none", "valid", "expired", "foreign"),
    "binding": ("exact", "glob", "ancestor_ir"),
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()


def file_digest(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def substrate_rows():
    rows = []
    for item in PROFILE.get("acceptedExecutionSubstrate") or []:
        path = (item.get("locator") or {}).get("path")
        if isinstance(path, str) and path:
            rows.append({"operation": item.get("operation"), "path": path})
    return rows


def substrate_paths():
    return {item["path"] for item in substrate_rows()}


def defaults():
    return {
        "actor": "exact",
        "resource": "exact",
        "action": "exact",
        "purpose": "exact",
        "scope": "absent",
        "authority": "exact",
        "authorization_ref": "exact",
        "delegation": "none",
        "policy_validity": "valid",
        "approval": "none",
        "binding": "exact",
        "role": "absent",
        "surface": "filesystem",
        "approval_required": False,
        "prohibition": False,
        "condition": "satisfied",
        "historical": None,
        "target_mutation": None,
        "cross_surface": None,
        "sequence": None,
    }


def semantic_block(facts):
    if facts["policy_validity"] != "valid":
        return True
    if facts["actor"] in ("substituted", "absent"):
        return True
    if facts["resource"] == "substituted":
        return True
    if facts["resource"] == "missing" and facts["delegation"] == "none":
        return True
    if facts["action"] == "unauthorized":
        return True
    if facts["purpose"] == "substituted":
        return True
    if facts["purpose"] == "missing" and facts["delegation"] == "none":
        return True
    if facts["scope"] == "substituted":
        return True
    if facts["authority"] in ("substituted", "foreign"):
        return True
    if facts["authorization_ref"] in ("substituted", "expired", "revoked"):
        return True
    if facts["delegation"] in ("false", "expired", "revoked", "foreign", "forged"):
        return True
    if facts["condition"] == "false":
        return True
    if facts["prohibition"]:
        return True
    if facts["approval_required"] and facts["approval"] in ("none", "expired", "foreign", "replay"):
        return True
    return False


def expectation(facts):
    if facts["historical"] == "higher-G" or facts["sequence"] == "D-contracted":
        return "contracted"
    if facts["historical"] == "approval-withheld" or (
        facts["approval_required"] and facts["approval"] in ("none", "expired", "foreign", "replay") and not _other_block(facts)
    ):
        return "approval_withheld"
    if facts["target_mutation"]:
        return "target_rejected"
    if facts["cross_surface"]:
        return "derivation_closed"
    if facts["binding"] == "glob" and not semantic_block(facts):
        return "coverage_closed"
    if facts["binding"] in ("ancestor_ir", "composition_ir", "stale_ir") and not semantic_block(facts):
        return "derivation_closed"
    if facts["surface"] in ("model", "credential", "strict-executable"):
        return "target_limited"
    if semantic_block(facts):
        return "no_execute"
    if facts["surface"] == "approval" and facts["approval"] == "valid":
        return "positive_semantic"
    return "positive_deploy"


def _other_block(facts):
    saved = facts["approval_required"]
    facts["approval_required"] = False
    blocked = semantic_block(facts)
    facts["approval_required"] = saved
    return blocked


def filesystem_policy():
    policy = load("openshell-filesystem-read-write.json")
    policy["enforcementRequirements"] = [
        item for item in policy["enforcementRequirements"] if item["requirementId"] == "req-read"
    ]
    policy["enforcementRequirements"][0]["groupId"] = "read-only"
    policy["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
    policy["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
    policy["authorizations"][0]["requirementIds"] = ["req-read"]
    policy["authorizations"][0]["purpose"] = "FieldInspection"
    return policy


def request_for(policy, action, resource_id):
    return {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-q13d",
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": "trace-q13d",
        "actor": {"id": policy["authorizations"][0]["actorId"], "identity": "id-agent-field"},
        "resource": {"id": resource_id},
        "action": action,
        "purpose": policy["authorizations"][0].get("purpose") or "FieldInspection",
        "authority": {"id": policy["authorizations"][0]["authorityId"], "kind": "direct"},
        "authorization": {"id": policy["authorizations"][0]["authorizationId"], "validity": {"state": "valid"}},
        "provenance": copy.deepcopy(policy["provenance"]),
    }


def materialize(facts):
    if facts["surface"] == "rest":
        policy = load("openshell-rest-target-restricted.json")
    elif facts["surface"] == "tcp":
        policy = load("openshell-tcp-connect.json")
    elif facts["surface"] == "mcp":
        policy = load("openshell-mcp-tool.json")
    elif facts["surface"] == "approval" or facts["approval_required"] or facts["historical"] == "approval-withheld":
        policy = load("human-approval.json")
    elif facts["prohibition"]:
        policy = load("prohibition.json")
    elif facts["surface"] == "model":
        policy = load("model-inference.json")
    elif facts["surface"] == "credential":
        policy = load("proxy-mediated-credential.json")
    elif facts["surface"] == "strict-executable":
        policy = load("openshell-rest-get.json")
    else:
        policy = filesystem_policy()
    policy = copy.deepcopy(policy)
    policy["validity"] = {"state": facts["policy_validity"]}
    if facts["scope"] in ("exact", "substituted"):
        policy["scopes"] = [{"scopeId": "scope-mission", "dimension": "spatial", "value": "inspection"}]
        policy["authorizations"][0]["conditions"] = [
            {"conditionId": "cond-scope", "type": "scope-match", "scopeId": "scope-mission"}
        ]
    if facts["condition"] == "false":
        policy["validities"] = [{"validityId": "val-window", "state": "expired"}]
        policy["authorizations"][0]["conditions"] = [
            {"conditionId": "cond-window", "type": "validity-window", "validityId": "val-window"}
        ]
    if facts["delegation"] in ("valid", "expired", "revoked"):
        policy["authorities"][0]["kind"] = "delegable"
    if facts["binding"] == "glob":
        policy["executionBindings"][0]["locator"]["path"] = "/mission/*"
    action = policy["authorizations"][0]["actionIds"][0]
    resource_id = (policy["authorizations"][0].get("resourceIds") or ["mission:InspectionInput"])[0]
    if facts["prohibition"]:
        action = "ReadInspectionOutput"
        resource_id = "mission:InspectionOutput"
    if facts["action"] == "unauthorized":
        action = "UnlistedAction"
    if facts["resource"] == "substituted":
        resource_id = "mission:Other"
    document = request_for(policy, action, resource_id)
    if facts["delegation"] != "none":
        document["exchangeType"] = "Delegation"
        document["delegation"] = {
            "authorityId": policy["authorizations"][0]["authorityId"],
            "canDelegate": facts["delegation"] == "valid" or facts["delegation"] in ("expired", "revoked", "foreign"),
        }
        document["authority"]["kind"] = "delegable" if facts["delegation"] in ("valid", "expired", "revoked") else "direct"
        if facts["delegation"] == "false" or facts["delegation"] == "forged":
            document["delegation"]["canDelegate"] = False
            document["authority"]["kind"] = "direct"
        if facts["delegation"] in ("expired", "revoked"):
            document["validity"] = {"state": facts["delegation"]}
        if facts["delegation"] == "foreign":
            document["policyId"] = "pol-foreign"
            document["delegation"]["canDelegate"] = True
    if facts["actor"] == "substituted":
        document["actor"] = {"id": "other-agent", "identity": "id-other"}
    elif facts["actor"] == "absent":
        document.pop("actor", None)
    if facts["resource"] == "missing":
        document.pop("resource", None)
    if facts["purpose"] == "substituted":
        document["purpose"] = "OtherPurpose"
    elif facts["purpose"] == "missing":
        document.pop("purpose", None)
    if facts["authority"] == "substituted":
        document["authority"] = {"id": "auth-other", "kind": document["authority"]["kind"]}
    elif facts["authority"] == "foreign":
        document["authority"] = {"id": "auth-foreign", "kind": "direct"}
        document["foreignAuthorityEvidence"] = {"enterprise": "other", "state": "active"}
    if facts["authorization_ref"] == "substituted":
        document["authorization"] = {"id": "az-other", "validity": {"state": "valid"}}
    elif facts["authorization_ref"] in ("expired", "revoked"):
        document["authorization"] = {"id": policy["authorizations"][0]["authorizationId"], "validity": {"state": facts["authorization_ref"]}}
    if facts["scope"] == "exact":
        document["scope"] = [{"dimension": "spatial", "value": "inspection"}]
    elif facts["scope"] == "substituted":
        document["scope"] = [{"dimension": "spatial", "value": "other"}]
    if facts["role"] == "label":
        document["role"] = "observer"
    approvals = []
    if facts["approval"] in ("valid", "expired", "foreign", "replay"):
        decision = load("human-approval-decision.json")
        if facts["approval"] == "expired":
            decision["decision"]["validity"] = {"state": "expired"}
        if facts["approval"] in ("foreign", "replay") or facts["historical"] == "foreign-decision":
            decision["policyId"] = "pol-foreign"
            decision["decision"]["requirementId"] = "req-foreign"
        if facts["purpose"] == "substituted" and facts["surface"] == "approval":
            document["purpose"] = "OtherPurpose"
        approvals.append(decision)
    if facts["historical"] == "expired-policy":
        policy["validity"] = {"state": "expired"}
        return policy, None, []
    if facts["historical"] == "approval-withheld":
        return policy, None, []
    return policy, document, approvals


def realize(document, policy=None, approvals=None):
    authority = assess(document, policy=policy, approvals=approvals)
    projected = project(document, policy=policy, approvals=approvals)
    ir = projected.get("operationalIr")
    result = {
        "semantic": authority["authorityDecision"],
        "codes": list(authority.get("codes") or []),
        "reasons": list(authority.get("reasons") or []),
        "ir": ir,
        "derivationMatched": None,
        "coverageDisposition": None,
        "compilation": "NOT_COMPILED",
        "deployable": False,
        "policy": None,
        "compiled": None,
    }
    if ir is None:
        return result
    verdict = verify_derivation(ir, document, policy=policy, approvals=approvals)
    coverage = assess_coverage(ir, MANIFEST, PROFILE, document=document, policy=policy, approvals=approvals)
    compiled = ADAPTER.compile_policy(ir, coverage, MANIFEST, PROFILE, document=document, policy=policy, approvals=approvals)
    result.update({
        "derivationMatched": verdict["matched"] is True,
        "coverageDisposition": coverage.get("compilationDisposition"),
        "compilation": compiled.get("compilationDisposition"),
        "deployable": compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL",
        "policy": compiled.get("generatedPolicy"),
        "compiled": compiled,
    })
    return result


def grant_paths(ir):
    found = set()
    for binding in (ir or {}).get("bindings") or []:
        path = (binding.get("locator") or {}).get("path")
        if isinstance(path, str):
            found.add(path)
    return found


def filesystem_extra(policy, ir):
    if not isinstance(policy, dict) or "filesystem_policy" not in policy:
        return []
    filesystem = policy.get("filesystem_policy") or {}
    emitted = set(filesystem.get("read_only") or []) | set(filesystem.get("read_write") or [])
    return sorted(emitted - grant_paths(ir) - substrate_paths())


def executable(observed):
    if observed["deployable"]:
        return True
    if "approval_required" in (observed["codes"] or []):
        return observed["ir"] is not None
    return observed["semantic"] == "AUTHORIZED"


def violates(expect, observed, extra=None):
    extra = extra or {}
    if expect == "no_execute":
        return executable(observed) or observed["deployable"]
    if expect == "approval_withheld":
        return (
            observed["ir"] is not None
            or observed["deployable"]
            or "approval_required" not in observed["codes"]
            or observed["semantic"] != "AUTHORIZED"
        )
    if expect == "positive_deploy":
        return not (
            observed["semantic"] == "AUTHORIZED"
            and observed["ir"] is not None
            and observed["derivationMatched"] is True
            and observed["deployable"]
            and observed["coverageDisposition"] == "FULL"
            and not extra.get("filesystemExtra")
        )
    if expect == "positive_semantic":
        return not (observed["semantic"] == "AUTHORIZED" and observed["ir"] is not None and not observed["deployable"])
    if expect == "coverage_closed":
        return observed["deployable"] or observed["coverageDisposition"] == "FULL"
    if expect == "derivation_closed":
        return extra.get("staleMatched") is True or extra.get("staleDeployable") is True
    if expect == "target_rejected":
        return not extra.get("wideningDetected")
    if expect == "target_limited":
        return observed["deployable"] or observed["coverageDisposition"] == "FULL"
    if expect == "contracted":
        return executable(observed) or observed["deployable"] or not extra.get("wideningDetected")
    return True


def primary_for(expect, facts):
    if facts["target_mutation"] == "stale-policy":
        return "TARGET_STALE_DETECTED"
    return {
        "no_execute": "SEMANTICALLY_PREVENTED",
        "approval_withheld": "APPROVAL_WITHHELD",
        "positive_deploy": "POSITIVE_CONTROL_AUTHORIZED",
        "positive_semantic": "POSITIVE_CONTROL_AUTHORIZED",
        "coverage_closed": "COVERAGE_REJECTED",
        "derivation_closed": "DERIVATION_REJECTED",
        "target_rejected": "TARGET_POLICY_REJECTED",
        "target_limited": "TARGET_LIMITED",
        "contracted": "TARGET_STALE_DETECTED",
    }[expect]


def attack_ir(ir, mode):
    mutated = copy.deepcopy(ir)
    if mode == "ancestor_ir":
        for binding in mutated.get("bindings") or []:
            if (binding.get("locator") or {}).get("path") == "/mission/input":
                binding["locator"]["path"] = "/mission"
    elif mode == "composition_ir":
        for requirement in mutated.get("requirements") or []:
            requirement["composition"] = "anyOf"
    elif mode == "stale_ir":
        for binding in mutated.get("bindings") or []:
            locator = binding.get("locator") or {}
            if "path" in locator:
                locator["path"] = "/mission/archive"
    return mutated


def widen_filesystem(policy):
    mutated = copy.deepcopy(policy)
    mutated["filesystem_policy"]["read_only"] = list(mutated["filesystem_policy"]["read_only"]) + ["/mission/secret"]
    return mutated


def widen_network(policy, field, value):
    mutated = copy.deepcopy(policy)
    for rule in (mutated.get("network_policies") or {}).values():
        for endpoint in rule.get("endpoints") or []:
            if field in ("host", "port"):
                endpoint[field] = value
            for item in endpoint.get("rules") or []:
                allow = item.get("allow") or {}
                if field in allow:
                    allow[field] = value
    return mutated


def network_widening_detected(compiled, mutated, surface):
    if surface == "rest":
        reasons = ADAPTER.verify_network_policy(
            mutated, compiled.get("networkGrants") or [], substrate_rows(), compiled.get("binaryRestrictions") or []
        )
        return bool(reasons), list(reasons or [])
    grant = {
        "host": "example.com" if surface == "tcp" else "mcp.example.com",
        "port": 443,
        "requirementId": compiled["generatedPolicy"]["network_policies"].__iter__().__next__(),
    }
    rule_id = grant["requirementId"]
    if surface == "mcp":
        grant.update({"method": "tools/call", "tool": "list_issues", "bindingId": "list-issues"})
        reasons = ADAPTER._network_slices().verify_mcp_policy(mutated, grant, substrate_rows(), compiled.get("targetExecutableRestriction"))
    else:
        grant["bindingId"] = "example-connect"
        reasons = ADAPTER._network_slices().verify_tcp_policy(mutated, grant, substrate_rows(), compiled.get("targetExecutableRestriction"))
    del rule_id
    return bool(reasons), list(reasons or [])


def evaluate(facts):
    policy, document, approvals = materialize(facts)
    expect = expectation(facts)
    extra = {}
    if facts["historical"] in ("expired-policy", "approval-withheld"):
        observed = realize(policy, approvals=approvals)
    else:
        observed = realize(document, policy=policy, approvals=approvals)
    if expect == "positive_deploy" and observed["policy"] and "filesystem_policy" in (observed["policy"] or {}):
        extra["filesystemExtra"] = filesystem_extra(observed["policy"], observed["ir"])
    if facts["binding"] in ("ancestor_ir", "composition_ir", "stale_ir") and observed["ir"] is not None:
        mutated = attack_ir(observed["ir"], facts["binding"])
        verdict = verify_derivation(mutated, document, policy=policy, approvals=approvals)
        coverage = assess_coverage(mutated, MANIFEST, PROFILE, document=document, policy=policy, approvals=approvals)
        compiled = ADAPTER.compile_policy(mutated, coverage, MANIFEST, PROFILE, document=document, policy=policy, approvals=approvals)
        extra["staleMatched"] = verdict["matched"] is True
        extra["staleDeployable"] = compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL"
    if expect == "contracted":
        base = filesystem_policy()
        fresh = realize(request_for(base, "ReadInspectionInput", "mission:InspectionInput"), policy=base)
        reasons = []
        structural = []
        if fresh["policy"] is not None:
            reasons = ADAPTER.verify_policy(fresh["policy"], [], substrate_rows())
            structural = filesystem_extra(fresh["policy"], None)
        extra["wideningDetected"] = bool(reasons) and bool(structural)
        extra["staleReasons"] = list(reasons)
    if facts["target_mutation"] and observed["policy"] is not None:
        if facts["target_mutation"] == "filesystem-secret" or facts["target_mutation"] == "stale-policy":
            mutated = widen_filesystem(observed["policy"])
            reasons = ADAPTER.verify_policy(mutated, [(binding.get("operation"), (binding.get("locator") or {}).get("path")) for binding in observed["ir"]["bindings"] if (binding.get("locator") or {}).get("path")], substrate_rows())
            structural = filesystem_extra(mutated, observed["ir"])
            extra["wideningDetected"] = bool(reasons) and bool(structural)
            extra["staleReasons"] = list(reasons)
        elif facts["surface"] in ("rest", "tcp", "mcp"):
            field, value = {"rest": ("host", "evil.example.com"), "tcp": ("port", 444), "mcp": ("tool", "other_tool")}[facts["surface"]]
            if facts["target_mutation"] == "rest-method":
                field, value = "method", "POST"
            mutated = widen_network(observed["policy"], field, value)
            detected, reasons = network_widening_detected(observed["compiled"], mutated, facts["surface"])
            extra["wideningDetected"] = detected
            extra["staleReasons"] = reasons
    if facts["cross_surface"] == "filesystem-as-rest":
        filesystem = realize(request_for(filesystem_policy(), "ReadInspectionInput", "mission:InspectionInput"), policy=filesystem_policy())
        rest = load("openshell-rest-target-restricted.json")
        verdict = verify_derivation(filesystem["ir"], rest)
        compiled = ADAPTER.compile_policy(filesystem["ir"], {"authorityDecision": "AUTHORIZED", "compilationDisposition": "FULL", "deployable": True, "coverage": {"compilationDisposition": "FULL"}}, MANIFEST, PROFILE, document=rest)
        extra["staleMatched"] = verdict["matched"] is True
        extra["staleDeployable"] = compiled.get("deployable") is True
    violation = violates(expect, observed, extra)
    record = {
        "caseId": facts["caseId"],
        "seed": facts["seed"],
        "expect": expect,
        "primary": "UNAUTHORIZED_DEPLOYABLE_AUTHORITY" if violation and observed["deployable"] else ("UNAUTHORIZED_SEMANTIC_ACCEPTANCE" if violation else primary_for(expect, facts)),
        "violation": violation,
        "semantic": observed["semantic"],
        "codes": observed["codes"],
        "reasons": observed["reasons"],
        "operationalIr": observed["ir"] is not None,
        "derivationMatched": observed["derivationMatched"],
        "coverageDisposition": observed["coverageDisposition"],
        "deployable": observed["deployable"],
        "surface": facts["surface"],
        "historical": facts["historical"],
        "sequence": facts["sequence"],
        "positive": expect in ("positive_deploy", "positive_semantic"),
    }
    return record, observed, policy, document, extra


def stamp(facts, seed, number):
    body = dict(facts)
    body["seed"] = seed
    interesting = [f"{key}={body[key]}" for key in (
        "surface", "actor", "resource", "action", "purpose", "scope", "authority", "authorization_ref",
        "delegation", "policy_validity", "approval", "binding", "role", "historical", "target_mutation",
        "cross_surface", "sequence", "prohibition", "condition",
    ) if body.get(key) not in (None, "exact", "absent", "none", "valid", "satisfied", False, "filesystem")]
    slug = "-".join(interesting) or "positive"
    body["caseId"] = f"{seed}-{number:04d}-{slug}"
    return body


def pairwise(seed):
    keys = list(DIMENSIONS)
    emitted = []
    number = 1
    for index, left in enumerate(keys):
        for right in keys[index + 1:]:
            for left_value in DIMENSIONS[left]:
                for right_value in DIMENSIONS[right]:
                    facts = defaults()
                    facts[left] = left_value
                    facts[right] = right_value
                    emitted.append(stamp(facts, seed, number))
                    number += 1
    return emitted


def named(seed, rows):
    emitted = []
    for number, facts in enumerate(rows, start=1):
        body = defaults()
        body.update(facts)
        emitted.append(stamp(body, seed, number))
    return emitted


def catalog():
    batches = {"q13d-seed-0001": pairwise("q13d-seed-0001")}
    batches["q13d-seed-0002"] = named("q13d-seed-0002", [
        {"resource": "substituted", "approval": "expired", "historical": "higher-A"},
        {"actor": "substituted", "delegation": "valid", "historical": "higher-B"},
        {"delegation": "expired", "approval": "valid", "binding": "exact", "historical": "higher-C"},
        {"binding": "ancestor_ir", "target_mutation": "stale-policy", "historical": "higher-D"},
        {"binding": "composition_ir", "historical": "higher-E"},
        {"purpose": "substituted", "approval": "replay", "binding": "stale_ir", "surface": "approval", "approval_required": True, "historical": "higher-F"},
        {"policy_validity": "expired", "historical": "higher-G"},
        {"approval": "foreign", "surface": "approval", "approval_required": True, "historical": "higher-H"},
        {"surface": "model", "historical": "higher-I"},
        {"binding": "glob", "historical": "higher-J"},
        {"surface": "rest", "target_mutation": "rest-host", "historical": "higher-K-rest"},
        {"surface": "tcp", "target_mutation": "tcp-port", "historical": "higher-K-tcp"},
        {"surface": "mcp", "target_mutation": "mcp-tool", "historical": "higher-K-mcp"},
        {"prohibition": True, "approval": "valid", "delegation": "valid", "historical": "higher-L"},
    ])
    batches["q13d-seed-0003"] = named("q13d-seed-0003", [
        {"sequence": "A-valid"},
        {"sequence": "A-expired", "policy_validity": "expired"},
        {"sequence": "A-restored"},
        {"sequence": "B-authorized"},
        {"sequence": "B-resource", "resource": "substituted"},
        {"sequence": "B-restored"},
        {"sequence": "C-authorized"},
        {"sequence": "C-revoked", "delegation": "revoked"},
        {"sequence": "C-old-ir", "delegation": "revoked", "binding": "stale_ir"},
        {"sequence": "C-fresh-delegation", "delegation": "valid"},
        {"sequence": "D-authorized", "target_mutation": "filesystem-secret"},
        {"sequence": "D-contracted", "policy_validity": "revoked"},
        {"sequence": "E-absent", "surface": "approval", "approval_required": True, "approval": "none"},
        {"sequence": "E-valid", "surface": "approval", "approval_required": True, "approval": "valid"},
        {"sequence": "E-purpose", "surface": "approval", "approval_required": True, "approval": "valid", "purpose": "substituted"},
        {"sequence": "E-replay", "surface": "approval", "approval_required": True, "approval": "replay", "purpose": "substituted"},
    ])
    batches["q13d-seed-0004"] = named("q13d-seed-0004", [
        {"historical": "expired-policy", "policy_validity": "expired"},
        {"historical": "expired-delegation", "delegation": "expired"},
        {"historical": "q13b-ancestor", "binding": "ancestor_ir"},
        {"historical": "q13b-glob", "binding": "glob"},
        {"historical": "q13c-forged", "delegation": "forged"},
        {"historical": "q13c-resource", "resource": "substituted"},
        {"historical": "approval-withheld", "surface": "approval", "approval_required": True, "approval": "none"},
    ])
    batches["q13d-seed-0005"] = named("q13d-seed-0005", [
        {"surface": "filesystem", "historical": "positive-filesystem"},
        {"surface": "rest", "historical": "positive-rest"},
        {"surface": "tcp", "historical": "positive-tcp"},
        {"surface": "mcp", "historical": "positive-mcp"},
        {"delegation": "valid", "historical": "positive-delegation"},
        {"surface": "approval", "approval_required": True, "approval": "valid", "historical": "positive-approval"},
        {"sequence": "restore", "historical": "positive-restore"},
        {"surface": "rest", "target_mutation": "rest-host"},
        {"surface": "rest", "target_mutation": "rest-method"},
        {"surface": "tcp", "target_mutation": "tcp-port"},
        {"surface": "mcp", "target_mutation": "mcp-tool"},
        {"target_mutation": "filesystem-secret"},
        {"surface": "model"},
        {"surface": "credential"},
        {"surface": "strict-executable"},
        {"binding": "glob"},
    ])
    batches["q13d-seed-0006"] = named("q13d-seed-0006", [
        {"cross_surface": "filesystem-as-rest", "historical": "cross-filesystem-rest"},
        {"surface": "rest", "resource": "substituted", "historical": "cross-rest-resource"},
        {"surface": "tcp", "actor": "substituted", "historical": "cross-tcp-actor"},
        {"surface": "mcp", "purpose": "substituted", "historical": "cross-mcp-purpose"},
        {"role": "label", "historical": "role-label"},
        {"role": "label", "resource": "substituted", "historical": "role-does-not-grant"},
        {"prohibition": True, "approval": "valid"},
        {"prohibition": True, "delegation": "valid"},
        {"authority": "foreign"},
        {"delegation": "foreign"},
        {"approval": "foreign", "surface": "approval", "approval_required": True},
        {"surface": "credential", "approval": "valid"},
        {"binding": "composition_ir"},
        {"condition": "false"},
        {"policy_validity": "not-yet-valid"},
        {"policy_validity": "superseded"},
        {"authorization_ref": "revoked"},
        {"scope": "exact"},
        {"scope": "substituted"},
    ])
    return batches


def main():
    if (OUT / "results.json").exists():
        print("refusing to overwrite " + RUN_ID)
        return 3
    batches = catalog()
    rows = []
    failure = None
    for seed in SEEDS:
        for facts in batches[seed]:
            record, observed, policy, document, extra = evaluate(facts)
            rows.append(record)
            if record["violation"]:
                failure = {"record": record, "facts": facts, "policy": policy, "document": document, "extra": extra, "observed": {key: value for key, value in observed.items() if key not in ("policy", "compiled", "ir")}}
                break
        if failure:
            break
    OUT.mkdir(parents=True, exist_ok=True)
    counts = {}
    for row in rows:
        counts[row["primary"]] = counts.get(row["primary"], 0) + 1
    decisions = {}
    for row in rows:
        decisions[row["semantic"]] = decisions.get(row["semantic"], 0) + 1
    payload = {
        "run": RUN_ID,
        "generator": GENERATOR,
        "seeds": SEEDS,
        "generatedCases": len(rows),
        "completed": failure is None,
        "runtimeOperationalOpportunities": 0,
        "unauthorizedOperationalEffects": 0,
        "runtimeUOER": None,
        "unauthorizedDeployableEmissions": sum(1 for row in rows if row["primary"] == "UNAUTHORIZED_DEPLOYABLE_AUTHORITY"),
        "aggregateGeneratedExposure": len(rows),
        "primaryCounts": counts,
        "semanticCounts": decisions,
        "deployablePolicies": sum(1 for row in rows if row["deployable"]),
        "operationalIrs": sum(1 for row in rows if row["operationalIr"]),
        "rows": rows,
    }
    (OUT / "results.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (OUT / "campaign.json").write_text(json.dumps({
        "baseline": "6435895898dd089ad545941fa226eb1c0a6860a9",
        "generator": GENERATOR,
        "run": RUN_ID,
        "seeds": SEEDS,
        "pinnedOpenShell": "v0.1.2",
        "pinnedCommit": "6648bd0c290efbc41ba131ee9831ee45cd431f94",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "generatorSourceHash": file_digest(Path(__file__)),
        "manifestHash": file_digest(REFERENCE / "targets" / "openshell" / "manifest.json"),
        "profileHash": file_digest(REFERENCE / "targets" / "openshell" / "execution-profile.json"),
        "runtimeExecuted": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    if failure:
        bundle = OUT / "failures"
        bundle.mkdir(exist_ok=True)
        (bundle / "record.json").write_text(json.dumps(failure["record"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (bundle / "facts.json").write_text(json.dumps(failure["facts"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if failure["policy"] is not None:
            (bundle / "policy.json").write_text(json.dumps(failure["policy"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if failure["document"] is not None:
            (bundle / "exchange.json").write_text(json.dumps(failure["document"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (bundle / "observed.json").write_text(json.dumps(failure["observed"], indent=2, default=str) + "\n", encoding="utf-8", newline="\n")
        (OUT / "report.md").write_text("# Q13D " + RUN_ID + "\n\nFAIL at " + failure["record"]["caseId"] + ".\n", encoding="utf-8", newline="\n")
        print("FAIL " + failure["record"]["caseId"] + " " + failure["record"]["primary"])
        return 1
    (OUT / "report.md").write_text("# Q13D " + RUN_ID + "\n\nCompleted " + str(len(rows)) + " generated cases without an oracle violation.\n", encoding="utf-8", newline="\n")
    print("completed " + str(len(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
