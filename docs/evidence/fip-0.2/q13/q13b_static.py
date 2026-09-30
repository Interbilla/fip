#!/usr/bin/env python3
"""Q13B static enforcement adversary.

The run stops at the first deployable target policy whose authority exceeds
the evaluated FIP grant plus accepted substrate. Later attacks are not executed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
Q13B = Path(__file__).resolve().parent / "q13b-static-enforcement"
RUN_ID = "q13b-run-3"
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project  # noqa: E402

BASELINE = "6435895898dd089ad545941fa226eb1c0a6860a9"
OPENSHELL_COMMIT = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
GENERATOR = "q13b-2"
SEED = "q13b-ordered-0"


def _load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _adapter():
    import importlib.util

    path = ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "adapter.py"
    spec = importlib.util.spec_from_file_location("openshell_adapter_q13b", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(payload):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


ADAPTER = _adapter()
MANIFEST = _load("reference/fip-0.2/targets/openshell/manifest.json")
PROFILE = _load("reference/fip-0.2/targets/openshell/execution-profile.json")


def single_read():
    document = _load("examples/fip-0.2/openshell-filesystem-read-write.json")
    document["policyId"] = "pol-q13b-read"
    document["enforcementRequirements"][0]["groupId"] = "read-only"
    document["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
    document["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
    document["authorizations"][0]["requirementIds"] = ["req-read"]
    return document


def realize(document):
    authority = assess(document)
    projected = project(document)
    ir = projected.get("operationalIr")
    result = {
        "semantic": authority["authorityDecision"],
        "codes": list(authority.get("codes") or []),
        "reasons": list(projected.get("reasons") or []),
        "ir": ir,
        "coverage": None,
        "compiled": None,
        "policy": None,
        "compilation": "NOT_COMPILED",
        "deployable": False,
    }
    if ir is None:
        return result
    coverage = assess_coverage(ir, MANIFEST, PROFILE, document=document)
    compiled = ADAPTER.compile_policy(ir, coverage, MANIFEST, PROFILE, document=document)
    result.update({
        "coverage": coverage,
        "compiled": compiled,
        "policy": compiled.get("generatedPolicy"),
        "compilation": compiled.get("compilationDisposition"),
        "deployable": compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL",
    })
    return result


def _paths(policy):
    filesystem = (policy or {}).get("filesystem_policy") or {}
    reads = list(filesystem.get("read_only") or [])
    writes = list(filesystem.get("read_write") or [])
    return reads, writes


def _substrate_paths(compiled):
    reads, writes = set(), set()
    for item in (compiled or {}).get("substrateMappings") or []:
        path = item.get("path")
        if not path:
            continue
        if item.get("operation") == "write":
            writes.add(path)
        else:
            reads.add(path)
    return reads, writes


def _grant_paths(compiled):
    reads, writes = set(), set()
    for item in (compiled or {}).get("ruleMappings") or []:
        if item.get("source") != "fip-grant" or not item.get("path"):
            continue
        if item.get("operation") == "write":
            writes.add(item["path"])
        elif item.get("operation") == "read":
            reads.add(item["path"])
    return reads, writes


def filesystem_excess(compiled, allowed_reads, allowed_writes):
    if not compiled or not compiled.get("generatedPolicy"):
        return []
    reads, writes = _paths(compiled["generatedPolicy"])
    substrate_reads, substrate_writes = _substrate_paths(compiled)
    excess = []
    for path in reads:
        if path not in allowed_reads and path not in substrate_reads:
            excess.append("read:" + path)
    for path in writes:
        if path not in allowed_writes and path not in substrate_writes:
            excess.append("write:" + path)
    return excess


def network_excess(policy, allowed):
    """allowed is a list of dicts with host, port, and optional method, path, protocol, tool."""
    if not isinstance(policy, dict):
        return []
    excess = []
    rules = policy.get("network_policies") or {}
    if not isinstance(rules, dict):
        return ["network-rules-not-a-map"]
    for name, rule in rules.items():
        if str(name).startswith("_provider_"):
            excess.append("provider-rule:" + str(name))
        for endpoint in (rule or {}).get("endpoints") or []:
            if not isinstance(endpoint, dict):
                excess.append("endpoint-malformed")
                continue
            matched = False
            for grant in allowed:
                if endpoint.get("host") != grant.get("host") or endpoint.get("port") != grant.get("port"):
                    continue
                if "protocol" in grant and endpoint.get("protocol") != grant.get("protocol"):
                    continue
                allow = ((endpoint.get("rules") or [{}])[0].get("allow") or {}) if endpoint.get("rules") else {}
                if "method" in grant and allow.get("method") != grant.get("method"):
                    continue
                if "path" in grant and allow.get("path") != grant.get("path"):
                    continue
                if "tool" in grant and allow.get("tool") != grant.get("tool"):
                    continue
                matched = True
            if not matched:
                excess.append("endpoint:%s:%s:%s" % (endpoint.get("host"), endpoint.get("port"), endpoint.get("protocol")))
    return excess


def _case(case_id, attack_class, surface, point, outcome, note, unauthorized=False, caught_by=None, limitation=None):
    if unauthorized:
        experimental = "FAIL"
    elif limitation:
        experimental = limitation
    else:
        experimental = "PASS"
    return {
        "id": case_id,
        "class": attack_class,
        "surface": surface,
        "point": point,
        "semantic": outcome.get("semantic"),
        "compilation": outcome.get("compilation"),
        "deployable": outcome.get("deployable"),
        "runtime": "UNOBSERVED",
        "caughtBy": caught_by,
        "unauthorizedEmission": unauthorized,
        "experimental": experimental,
        "note": note,
        "diagnostics": list((outcome.get("compiled") or {}).get("diagnostics") or []),
        "codes": list(outcome.get("codes") or []),
    }


def _bundle(document, outcome, mutated_ir=None):
    consumed = mutated_ir if mutated_ir is not None else outcome.get("ir")
    matched = None
    if consumed is not None:
        from fip02 import verify_derivation

        matched = verify_derivation(consumed, document)["matched"]
    return {
        "document": document,
        "originalIr": outcome.get("ir"),
        "mutatedIr": consumed,
        "coverage": outcome.get("coverage"),
        "policy": outcome.get("policy"),
        "derivationMatched": matched,
        "compiledDisposition": outcome.get("compilation"),
        "diagnostics": list((outcome.get("compiled") or {}).get("diagnostics") or []),
    }


def _expect_closed(case_id, attack_class, surface, point, document, note):
    outcome = realize(document)
    unauthorized = outcome["deployable"]
    caught = "none"
    if outcome["semantic"] != "AUTHORIZED":
        caught = "semantic"
    elif outcome["ir"] is None:
        caught = "projection"
    elif outcome["coverage"] and "filesystem_locator_not_exact" in (outcome["coverage"].get("diagnostics") or []):
        caught = "representability"
    elif outcome["coverage"] and outcome["coverage"].get("compilationDisposition") != "FULL":
        caught = "coverage"
    elif not outcome["deployable"]:
        caught = "adapter"
    return _case(case_id, attack_class, surface, point, outcome, note, unauthorized, caught), _bundle(document, outcome)


def _positive_filesystem():
    document = single_read()
    outcome = realize(document)
    excess = filesystem_excess(outcome["compiled"], {"/mission/input"}, set())
    grants = (outcome["coverage"] or {}).get("coverage", {}).get("fipGrants") or []
    substrate_reads, _writes = _substrate_paths(outcome["compiled"])
    leaked = [item for item in grants if item in substrate_reads or item in ("/usr", "/tmp")]
    unauthorized = (not outcome["deployable"]) or bool(excess) or bool(leaked)
    note = "Exact read /mission/input compiles FULL. Substrate paths stay out of fipGrants."
    if excess:
        note = "Positive filesystem control emitted paths outside the grant: %s" % ",".join(excess)
    return _case(
        "filesystem-exact-read",
        "positive-control",
        "filesystem",
        "baseline",
        outcome,
        note,
        unauthorized,
        "adapter" if outcome["deployable"] and not excess else "none",
    ), outcome, document


def _policy_mutation(outcome):
    policy = copy.deepcopy(outcome["policy"])
    policy["filesystem_policy"]["read_only"] = list(policy["filesystem_policy"]["read_only"]) + ["/mission/sibling"]
    grants = [
        (item["operation"], item["path"])
        for item in outcome["compiled"]["ruleMappings"]
        if item.get("source") == "fip-grant"
    ]
    substrate = [
        {"operation": item.get("operation"), "path": item.get("path")}
        for item in outcome["compiled"]["substrateMappings"]
        if item.get("path")
    ]
    reasons = ADAPTER.verify_policy(policy, grants, substrate)
    detected = bool(reasons)
    unauthorized = not detected
    synthetic = {
        "semantic": outcome["semantic"],
        "compilation": "FULL" if not detected else "REJECTED",
        "deployable": not detected,
        "compiled": {"diagnostics": reasons},
        "codes": [],
    }
    return _case(
        "filesystem-policy-add-path",
        "filesystem-widening",
        "filesystem",
        "policy",
        synthetic,
        "Adding /mission/sibling after compile must fail verify_policy. Reasons: %s" % ",".join(reasons),
        unauthorized,
        "verifier" if detected else "none",
    )


def _ir_ancestor(document, outcome):
    mutated = copy.deepcopy(outcome["ir"])
    for binding in mutated.get("bindings") or []:
        locator = binding.get("locator") or {}
        if locator.get("path") == "/mission/input":
            locator["path"] = "/mission"
            binding["locator"] = locator
    coverage = assess_coverage(mutated, MANIFEST, PROFILE, document=document)
    compiled = ADAPTER.compile_policy(mutated, coverage, MANIFEST, PROFILE, document=document)
    deployable = compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL"
    excess = filesystem_excess(compiled, {"/mission/input"}, set()) if deployable else []
    unauthorized = deployable
    synthetic = {
        "semantic": "AUTHORIZED",
        "compilation": compiled.get("compilationDisposition"),
        "deployable": deployable,
        "compiled": compiled,
        "codes": [],
    }
    case = _case(
        "filesystem-ir-ancestor-after-decision",
        "semantic-to-binding",
        "filesystem",
        "ir",
        synthetic,
        "The evaluated grant is read /mission/input. The IR locator was changed to /mission before coverage and compilation. "
        "Excess paths: %s." % (",".join(excess) or "none"),
        unauthorized,
        "none" if unauthorized else "derivation",
    )
    bundle = {
        "document": document,
        "originalIr": outcome["ir"],
        "mutatedIr": mutated,
        "coverage": coverage,
        "policy": compiled.get("generatedPolicy"),
        "compiledDisposition": compiled.get("compilationDisposition"),
        "deployable": deployable,
        "diagnostics": compiled.get("diagnostics"),
        "excess": excess,
    }
    return case, bundle


def _slices():
    import importlib.util

    path = ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "network_slices.py"
    spec = importlib.util.spec_from_file_location("openshell_slices_q13b", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SLICES = _slices()


def _ir_attack(case_id, attack_class, surface, document, note, mutate):
    outcome = realize(document)
    mutated = copy.deepcopy(outcome["ir"])
    mutate(mutated)
    coverage = assess_coverage(mutated, MANIFEST, PROFILE, document=document)
    compiled = ADAPTER.compile_policy(mutated, coverage, MANIFEST, PROFILE, document=document)
    deployable = compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL"
    synthetic = {
        "semantic": outcome["semantic"],
        "compilation": compiled.get("compilationDisposition"),
        "deployable": deployable,
        "compiled": compiled,
        "codes": list((coverage or {}).get("codes") or []),
    }
    return _case(
        case_id, attack_class, surface, "ir", synthetic, note, deployable,
        "none" if deployable else "derivation",
    )


def _policy_attack(case_id, attack_class, surface, outcome, note, mutate, verify):
    policy = copy.deepcopy(outcome["policy"])
    mutate(policy)
    reasons = verify(policy, outcome)
    detected = bool(reasons)
    synthetic = {
        "semantic": outcome["semantic"],
        "compilation": "REJECTED" if detected else "FULL",
        "deployable": not detected,
        "compiled": {"diagnostics": reasons},
        "codes": [],
    }
    return _case(
        case_id, attack_class, surface, "policy", synthetic, note + " Reasons: %s" % ",".join(reasons),
        not detected, "verifier" if detected else "none",
    )


def catalog():
    """Ordered attacks. The runner stops after the first unauthorized emission."""
    items = []

    case, outcome, document = _positive_filesystem()
    items.append((case, None if not case["unauthorizedEmission"] else {"document": document, "ir": outcome["ir"], "policy": outcome["policy"], "coverage": outcome["coverage"]}))

    rest = realize(_load("examples/fip-0.2/openshell-rest-target-restricted.json"))
    rest_excess = network_excess(rest["policy"], [{
        "host": "weather.example.com", "port": 443, "protocol": "rest", "method": "GET", "path": "/weather",
    }]) if rest["deployable"] else ["not-deployable"]
    items.append((_case(
        "rest-exact-get",
        "positive-control",
        "rest",
        "baseline",
        rest,
        "M5 target-restricted GET /weather remains FULL. Query enforcement is not claimed by this grant.",
        bool(rest_excess) and rest["deployable"],
        "adapter" if rest["deployable"] and not rest_excess else "none",
    ), None))

    tcp = realize(_load("examples/fip-0.2/openshell-tcp-connect.json"))
    tcp_excess = network_excess(tcp["policy"], [{"host": "example.com", "port": 443, "protocol": "tcp"}]) if tcp["deployable"] else ["not-deployable"]
    items.append((_case(
        "tcp-exact-connect",
        "positive-control",
        "tcp",
        "baseline",
        tcp,
        "Exact host and port compile. Runtime remains UNOBSERVED. Classification stays SUPPORTED_UNOBSERVED.",
        bool(tcp_excess) and tcp["deployable"],
        "adapter" if tcp["deployable"] and not tcp_excess else "none",
    ), None))

    mcp = realize(_load("examples/fip-0.2/openshell-mcp-tool.json"))
    mcp_excess = network_excess(mcp["policy"], [{
        "host": "mcp.example.com", "port": 443, "protocol": "mcp", "method": "tools/call", "tool": "list_issues",
    }]) if mcp["deployable"] else ["not-deployable"]
    items.append((_case(
        "mcp-exact-tool",
        "positive-control",
        "mcp",
        "baseline",
        mcp,
        "Exact tools/call list_issues compiles. Runtime remains UNOBSERVED. Classification stays SUPPORTED_UNOBSERVED.",
        bool(mcp_excess) and mcp["deployable"],
        "adapter" if mcp["deployable"] and not mcp_excess else "none",
    ), None))

    queries = []
    for name, loader in (
        ("process-exact-executable", lambda: _load("examples/fip-0.2/openshell-process-execute.json")),
        ("credential-use", lambda: _load("examples/fip-0.2/proxy-mediated-credential.json")),
        ("model-exact-identity", lambda: _load("examples/fip-0.2/model-inference.json")),
        ("strict-executable-rest", lambda: _load("examples/fip-0.2/openshell-rest-get.json")),
    ):
        queries.append((name, loader))
    notes = {
        "process-exact-executable": "Kind process stays unenforced. No descendant or generic process grant is compiled.",
        "credential-use": "Credential use stays rejected. Provider attachment is not emitted as credential authority.",
        "model-exact-identity": "Exact model identity stays rejected. Provider access is not emitted as model authority.",
        "strict-executable-rest": "An executable ExecutionBinding stays non-deployable.",
    }
    classes = {
        "process-exact-executable": "process-executable",
        "credential-use": "credential",
        "model-exact-identity": "inference-model",
        "strict-executable-rest": "coverage",
    }
    surfaces = {
        "process-exact-executable": "process",
        "credential-use": "credential",
        "model-exact-identity": "inference",
        "strict-executable-rest": "rest",
    }
    for name, loader in queries:
        case, _outcome = _expect_closed(name, classes[name], surfaces[name], "semantic", loader(), notes[name])
        items.append((case, None))

    expired = single_read()
    expired["validity"] = {"state": "expired"}
    case, _outcome = _expect_closed(
        "expired-policy-not-compiled",
        "lifetime",
        "filesystem",
        "semantic",
        expired,
        "A non-valid AuthorityPolicy Validity produces no deployable target policy.",
    )
    items.append((case, None))

    relative = single_read()
    relative["executionBindings"][0]["locator"]["path"] = "mission/input"
    case, _outcome = _expect_closed(
        "filesystem-relative-path",
        "filesystem-widening",
        "filesystem",
        "semantic",
        relative,
        "A relative path is not an exact filesystem grant and must not compile FULL.",
    )
    items.append((case, None))

    dotted = single_read()
    dotted["executionBindings"][0]["locator"]["path"] = "/mission/input/../secret"
    case, _outcome = _expect_closed(
        "filesystem-dotdot-path",
        "filesystem-widening",
        "filesystem",
        "semantic",
        dotted,
        "A dotdot path is not an exact filesystem grant and must not compile FULL.",
    )
    items.append((case, None))

    delete_op = single_read()
    delete_op["executionBindings"][0]["operation"] = "delete"
    case, _outcome = _expect_closed(
        "filesystem-read-to-delete",
        "filesystem-widening",
        "filesystem",
        "semantic",
        delete_op,
        "Delete is not compiled as a read or write grant.",
    )
    items.append((case, None))

    query = _load("examples/fip-0.2/openshell-rest-target-restricted.json")
    query["executionBindings"][0]["locator"]["uri"] = "https://weather.example.com/weather?x=1"
    case, _outcome = _expect_closed(
        "rest-query-not-enforced",
        "rest-widening",
        "rest",
        "semantic",
        query,
        "A query-bearing URI is rejected. The compiler does not drop the query and stamp FULL.",
    )
    items.append((case, None))

    items.append((_policy_mutation(outcome), None))
    items.append(_ir_ancestor(document, outcome))

    files = _load("examples/fip-0.2/openshell-filesystem-read-write.json")
    rest_doc = _load("examples/fip-0.2/openshell-rest-target-restricted.json")
    tcp_doc = _load("examples/fip-0.2/openshell-tcp-connect.json")
    mcp_doc = _load("examples/fip-0.2/openshell-mcp-tool.json")

    items.append((_ir_attack(
        "filesystem-ir-operation-write", "semantic-to-binding", "filesystem", document,
        "Consumed read binding operation changed to write.",
        lambda ir: ir["bindings"].__setitem__(0, {**ir["bindings"][0], "operation": "write"}),
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-requirement-deleted", "semantic-to-binding", "filesystem", files,
        "One consumed requirement was deleted after projection.",
        lambda ir: ir.__setitem__("requirements", ir["requirements"][:1]),
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-allof-to-anyof", "composition", "filesystem", files,
        "Consumed composition changed from allOf to anyOf.",
        lambda ir: [item.__setitem__("composition", "anyOf") for item in ir["requirements"] + ir["groups"]],
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-lifetime-revocable", "lifetime", "filesystem", document,
        "Consumed lifetime changed from establishment-bound to revocable.",
        lambda ir: ir["bindings"][0].__setitem__("lifetime", "revocable"),
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-resource-substituted", "semantic-to-binding", "filesystem", document,
        "Consumed binding resourceId was substituted.",
        lambda ir: ir["bindings"][0].__setitem__("resourceId", "mission:InspectionOutput"),
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-action-substituted", "semantic-to-binding", "filesystem", document,
        "Consumed binding actionId was substituted.",
        lambda ir: ir["bindings"][0].__setitem__("actionId", "WriteInspectionOutput"),
    ), None))
    items.append((_ir_attack(
        "filesystem-ir-substrate-in-grants", "substrate-laundering", "filesystem", document,
        "A substrate path was inserted into coverage.fipGrants.",
        lambda ir: ir["coverage"]["fipGrants"].append("/tmp"),
    ), None))
    items.append((_ir_attack(
        "rest-ir-host-widened", "rest-widening", "rest", rest_doc,
        "Consumed REST host changed after projection.",
        lambda ir: ir["bindings"][0]["locator"].__setitem__("host", "evil.example.com"),
    ), None))
    items.append((_ir_attack(
        "tcp-ir-port-widened", "tcp-widening", "tcp", tcp_doc,
        "Consumed TCP port changed after projection.",
        lambda ir: ir["bindings"][0]["locator"].__setitem__("port", 22),
    ), None))
    items.append((_ir_attack(
        "mcp-ir-tool-widened", "mcp", "mcp", mcp_doc,
        "Consumed MCP tool name changed after projection.",
        lambda ir: ir["bindings"][0]["protocol"]["mcp"].__setitem__("tool", "shell"),
    ), None))

    for case_id, path, note in (
        ("filesystem-glob-path", "/mission/*", "A star locator is pattern syntax and is not an exact filesystem grant."),
        ("filesystem-question-path", "/mission/?", "A question-mark locator is pattern syntax and is not an exact filesystem grant."),
        ("filesystem-bracket-path", "/mission/[abc]", "A bracket locator is pattern syntax and is not an exact filesystem grant."),
        ("filesystem-range-path", "/mission/[a-z]", "A character-range locator is pattern syntax and is not an exact filesystem grant."),
    ):
        patterned = single_read()
        patterned["executionBindings"][0]["locator"]["path"] = path
        items.append(_expect_closed(
            case_id, "representability", "filesystem", "semantic", patterned, note,
        ))
    starred = _load("examples/fip-0.2/openshell-rest-target-restricted.json")
    starred["executionBindings"][0]["protocol"]["http"]["method"] = "*"
    case, _outcome = _expect_closed(
        "rest-method-star", "rest-widening", "rest", "semantic", starred,
        "A wildcard HTTP method is not compiled FULL.",
    )
    items.append((case, None))
    any_host = copy.deepcopy(tcp_doc)
    any_host["executionBindings"][0]["locator"]["host"] = "*"
    case, _outcome = _expect_closed(
        "tcp-any-host", "tcp-widening", "tcp", "semantic", any_host,
        "A wildcard TCP host is not compiled FULL.",
    )
    items.append((case, None))

    policy = _load("examples/fip-0.2/prohibition.json")
    exchange = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-ReadInspectionInput",
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": policy["traceId"],
        "actor": {"id": "agent-field"},
        "resource": {"id": "mission:InspectionInput"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"id": "az-reads", "validity": "valid"},
        "provenance": policy["provenance"],
    }
    prohibited = project(exchange, policy=policy)["operationalIr"]
    dropped = copy.deepcopy(prohibited)
    dropped["prohibitions"] = []
    prohibited_coverage = assess_coverage(dropped, MANIFEST, PROFILE, document=exchange, policy=policy)
    prohibited_compiled = ADAPTER.compile_policy(
        dropped, prohibited_coverage, MANIFEST, PROFILE, document=exchange, policy=policy
    )
    prohibited_deployable = (
        prohibited_compiled.get("deployable") is True
        and prohibited_compiled.get("compilationDisposition") == "FULL"
    )
    items.append((_case(
        "prohibition-dropped-from-ir", "prohibition", "filesystem", "ir",
        {
            "semantic": "AUTHORIZED",
            "compilation": prohibited_compiled.get("compilationDisposition"),
            "deployable": prohibited_deployable,
            "compiled": prohibited_compiled,
            "codes": list(prohibited_coverage.get("codes") or []),
        },
        "A consumed prohibition was removed after projection.",
        prohibited_deployable,
        "none" if prohibited_deployable else "derivation",
    ), None))

    approval = _load("examples/fip-0.2/human-approval.json")
    case, _outcome = _expect_closed(
        "approval-without-decision", "approval", "filesystem", "semantic", approval,
        "Require-approval without a completed approval has no operational IR.",
    )
    items.append((case, None))
    supplied = project(single_read())["operationalIr"]
    coverage = assess_coverage(supplied, MANIFEST, PROFILE, document=approval)
    compiled = ADAPTER.compile_policy(supplied, coverage, MANIFEST, PROFILE, document=approval)
    deployable = compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL"
    items.append((_case(
        "approval-supplied-ir-without-projection", "approval", "filesystem", "ir",
        {
            "semantic": "REVIEW",
            "compilation": compiled.get("compilationDisposition"),
            "deployable": deployable,
            "compiled": compiled,
            "codes": list(coverage.get("codes") or []),
        },
        "A supplied IR cannot revive a decision that currently has no operational projection.",
        deployable,
        "none" if deployable else "derivation",
    ), None))

    not_yet = single_read()
    not_yet["validity"] = {"state": "not-yet-valid"}
    case, _outcome = _expect_closed(
        "lifetime-not-yet-valid", "lifetime", "filesystem", "semantic", not_yet,
        "A not-yet-valid AuthorityPolicy produces no deployable policy.",
    )
    items.append((case, None))

    credential = _load("examples/fip-0.2/proxy-mediated-credential.json")
    credential_outcome = realize(credential)
    stamped = copy.deepcopy(credential_outcome["coverage"] or {"compilationDisposition": "REJECTED", "deployable": False})
    stamped["authorityDecision"] = "AUTHORIZED"
    stamped["compilationDisposition"] = "FULL"
    stamped["deployable"] = True
    forced = ADAPTER.compile_policy(credential_outcome["ir"], stamped, MANIFEST, PROFILE, document=credential)
    forced_deployable = forced.get("deployable") is True and forced.get("compilationDisposition") == "FULL"
    items.append((_case(
        "coverage-stamped-full-credential", "coverage", "credential", "coverage",
        {
            "semantic": credential_outcome["semantic"],
            "compilation": forced.get("compilationDisposition"),
            "deployable": forced_deployable,
            "compiled": forced,
            "codes": [],
        },
        "Stamping FULL on a credential assessment does not emit a deployable policy.",
        forced_deployable,
        "none" if forced_deployable else "adapter",
    ), None))

    manifest = copy.deepcopy(MANIFEST)
    manifest["adapterId"] = "other-adapter"
    alien = assess_coverage(project(rest_doc)["operationalIr"], manifest, PROFILE, document=rest_doc)
    alien_compiled = ADAPTER.compile_policy(project(rest_doc)["operationalIr"], alien, manifest, PROFILE, document=rest_doc)
    alien_deployable = alien_compiled.get("deployable") is True and alien_compiled.get("compilationDisposition") == "FULL"
    items.append((_case(
        "capability-manifest-identity-swap", "capability-manifest", "rest", "manifest",
        {
            "semantic": "AUTHORIZED",
            "compilation": alien_compiled.get("compilationDisposition"),
            "deployable": alien_deployable,
            "compiled": alien_compiled,
            "codes": list(alien.get("codes") or []),
        },
        "A substituted capability manifest does not make the REST grant deployable.",
        alien_deployable,
        "none" if alien_deployable else "adapter",
    ), None))

    grants = (outcome["coverage"] or {}).get("coverage", {}).get("fipGrants") or []
    leaked = [item for item in grants if item in ("/tmp", "/usr", "/dev/null")]
    items.append((_case(
        "substrate-not-in-fip-grants", "substrate-laundering", "filesystem", "baseline",
        outcome,
        "Accepted substrate paths are absent from fipGrants: %s" % ",".join(leaked),
        bool(leaked),
        "none" if leaked else "coverage",
    ), None))

    def _rest_verify(policy, compiled_outcome):
        return ADAPTER.verify_effective_policy(
            policy,
            compiled_outcome["compiled"]["networkGrants"],
            compiled_outcome["compiled"]["extractedAuthority"]["substrate"],
            compiled_outcome["compiled"]["binaryRestrictions"],
        )

    items.append((_policy_attack(
        "rest-policy-host-widened", "target-policy-mutation", "rest", rest,
        "REST host changed after compilation.",
        lambda policy: policy["network_policies"]["req-weather-api"]["endpoints"][0].__setitem__("host", "*.example.com"),
        _rest_verify,
    ), None))
    items.append((_policy_attack(
        "rest-policy-downgraded-to-tcp", "cross-surface", "rest", rest,
        "A REST rule was rewritten as unrestricted TCP.",
        lambda policy: policy["network_policies"]["req-weather-api"]["endpoints"][0].__setitem__("protocol", "tcp"),
        _rest_verify,
    ), None))

    def _tcp_verify(policy, compiled_outcome):
        grant = {"host": "example.com", "port": 443}
        return SLICES.verify_tcp_policy(
            policy, grant, compiled_outcome["compiled"]["substrateMappings"], "/usr/bin/curl"
        )

    items.append((_policy_attack(
        "tcp-policy-port-widened", "target-policy-mutation", "tcp", tcp,
        "TCP port changed after compilation.",
        lambda policy: policy["network_policies"]["req-example-connect"]["endpoints"][0].__setitem__("port", 22),
        _tcp_verify,
    ), None))

    def _mcp_verify(policy, compiled_outcome):
        grant = {"host": "mcp.example.com", "port": 443, "method": "tools/call", "tool": "list_issues"}
        return SLICES.verify_mcp_policy(
            policy, grant, compiled_outcome["compiled"]["substrateMappings"], "/usr/bin/curl"
        )

    items.append((_policy_attack(
        "mcp-policy-tool-widened", "target-policy-mutation", "mcp", mcp,
        "MCP tool changed after compilation.",
        lambda policy: policy["network_policies"]["req-list-issues"]["endpoints"][0]["rules"][0]["allow"].__setitem__("tool", "shell"),
        _mcp_verify,
    ), None))
    items.append((_policy_attack(
        "mcp-policy-downgraded-to-tcp", "cross-surface", "mcp", mcp,
        "An MCP rule was rewritten as unrestricted TCP.",
        lambda policy: policy["network_policies"]["req-list-issues"]["endpoints"][0].__setitem__("protocol", "tcp"),
        _mcp_verify,
    ), None))
    return items


def _counts(cases):
    by_class = {}
    for item in cases:
        bucket = by_class.setdefault(item["class"], {"attempts": 0, "unauthorized": 0, "pass": 0, "fail": 0})
        bucket["attempts"] += 1
        if item["unauthorizedEmission"]:
            bucket["unauthorized"] += 1
        if item["experimental"] == "PASS":
            bucket["pass"] += 1
        if item["experimental"] == "FAIL":
            bucket["fail"] += 1
    return by_class


def _report(cases, stopped, gate):
    lines = [
        "# Q13B static enforcement",
        "",
        "Run id: `%s`" % RUN_ID,
        "",
        "Baseline commit: `%s`" % BASELINE,
        "",
        "OpenShell pin: v0.1.2 `%s`" % OPENSHELL_COMMIT,
        "",
        "Generator: `%s`. Seed: `%s`." % (GENERATOR, SEED),
        "",
        "Gate: **%s**" % gate,
        "",
        "Executed cases: %s. Unauthorized deployable emissions: %s." % (
            len(cases),
            sum(1 for item in cases if item["unauthorizedEmission"]),
        ),
        "",
        "Runtime was not started. Runtime UOER denominator is 0.",
        "",
    ]
    if stopped:
        lines.append("The run stopped at `%s`. Later attack classes were not executed." % stopped)
        lines.append("")
    lines.extend(["| Case | Class | Point | Semantic | Compilation | Deployable | Result |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for item in cases:
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            item["id"], item["class"], item["point"], item["semantic"], item["compilation"], item["deployable"], item["experimental"],
        ))
    lines.extend(["", "## Notes", ""])
    for item in cases:
        lines.append("- `%s`: %s Caught by `%s`." % (item["id"], item["note"], item["caughtBy"]))
    lines.append("")
    return "\n".join(lines)


def main():
    run_dir = Q13B / RUN_ID
    if (run_dir / "results.json").exists():
        print("refusing to overwrite %s" % RUN_ID)
        return 3
    cases = []
    stopped = None
    failure_bundle = None
    for case, bundle in catalog():
        cases.append(case)
        if case["unauthorizedEmission"]:
            stopped = case["id"]
            failure_bundle = bundle
            break
    unauthorized = sum(1 for item in cases if item["unauthorizedEmission"])
    gate = "FAIL" if unauthorized else "PASS"
    payload = {
        "runId": RUN_ID,
        "startedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "baselineCommit": BASELINE,
        "prospectiveSource": "uncommitted working tree including derivation verification and exact filesystem locator rejection",
        "openshellVersion": "0.1.2",
        "openshellCommit": OPENSHELL_COMMIT,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "generator": GENERATOR,
        "seed": SEED,
        "runtimeExecuted": False,
        "gate": gate,
        "stoppedAt": stopped,
        "countsByClass": _counts(cases),
        "cases": cases,
    }
    _write(run_dir / "results.json", json.dumps(payload, indent=2) + "\n")
    _write(run_dir / "attack-matrix.json", json.dumps({
        "generator": GENERATOR,
        "seed": SEED,
        "stoppedAt": stopped,
        "cases": [{key: item[key] for key in ("id", "class", "surface", "point", "experimental", "unauthorizedEmission", "caughtBy")} for item in cases],
    }, indent=2) + "\n")
    _write(run_dir / "report.md", _report(cases, stopped, gate))
    if failure_bundle:
        for name, value in (
            ("inputs/source.json", failure_bundle.get("document")),
            ("ir/original.json", failure_bundle.get("originalIr")),
            ("ir/mutated.json", failure_bundle.get("mutatedIr")),
            ("coverage/assessment.json", failure_bundle.get("coverage")),
            ("policies/generated.json", failure_bundle.get("policy")),
            ("derivation.json", {"matched": failure_bundle.get("derivationMatched")}),
        ):
            _write(run_dir / name, json.dumps(value, indent=2) + "\n")
        _write(run_dir / "inputs/minimized-mutation.json", json.dumps({
            "stoppedAt": stopped,
            "derivationMatched": failure_bundle.get("derivationMatched"),
            "compilationDisposition": failure_bundle.get("compiledDisposition"),
            "diagnostics": failure_bundle.get("diagnostics"),
        }, indent=2) + "\n")
        hashes = {
            name: _sha256(json.loads((run_dir / name).read_text(encoding="utf-8")))
            for name in (
                "inputs/source.json",
                "inputs/minimized-mutation.json",
                "ir/original.json",
                "ir/mutated.json",
                "coverage/assessment.json",
                "policies/generated.json",
                "derivation.json",
            )
        }
        _write(run_dir / "hashes.json", json.dumps(hashes, indent=2) + "\n")
    print(json.dumps({"gate": gate, "stoppedAt": stopped, "cases": len(cases), "unauthorized": unauthorized}, indent=2))
    return 2 if gate == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
