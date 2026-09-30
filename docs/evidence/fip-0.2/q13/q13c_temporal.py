"""Q13C runtime authority evolution adversary.

Each case is a fresh evaluation of the current sources. The runner stops at
the first case that accepts authority the current facts do not support, or
that emits a deployable policy for a non-authorized decision. It does not
start a sandbox and does not record a runtime effect that was not executed.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
REFERENCE = ROOT / "reference" / "fip-0.2"
sys.path.insert(0, str(REFERENCE))

from fip02 import assess, assess_coverage, project, verify_derivation  # noqa: E402

RUN_ID = "q13c-run-4"
GENERATOR = "q13c-4"
OUT = ROOT / "docs" / "evidence" / "fip-0.2" / "q13" / "q13c-runtime-authority" / RUN_ID
EXAMPLE = ROOT / "examples" / "fip-0.2" / "openshell-filesystem-read-write.json"
APPROVAL = ROOT / "examples" / "fip-0.2" / "human-approval.json"
APPROVAL_DECISION = ROOT / "examples" / "fip-0.2" / "human-approval-decision.json"

_spec = importlib.util.spec_from_file_location(
    "openshell_adapter", REFERENCE / "targets" / "openshell" / "adapter.py"
)
ADAPTER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ADAPTER)
MANIFEST = json.loads((REFERENCE / "targets" / "openshell" / "manifest.json").read_text(encoding="utf-8"))
PROFILE = json.loads((REFERENCE / "targets" / "openshell" / "execution-profile.json").read_text(encoding="utf-8"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def base_policy():
    policy = load(EXAMPLE)
    policy["enforcementRequirements"] = [
        requirement for requirement in policy["enforcementRequirements"] if requirement["requirementId"] == "req-read"
    ]
    policy["enforcementRequirements"][0]["groupId"] = "read-only"
    policy["authorizations"][0]["actionIds"] = ["ReadInspectionInput"]
    policy["authorizations"][0]["resourceIds"] = ["mission:InspectionInput"]
    policy["authorizations"][0]["requirementIds"] = ["req-read"]
    policy["authorizations"][0]["purpose"] = "FieldInspection"
    policy["authorizations"][0]["actorId"] = "agent-field"
    return policy


def request_exchange(policy, **overrides):
    body = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-read",
        "exchangeType": "Request",
        "policyId": policy["policyId"],
        "traceId": "trace-q13c",
        "actor": {"id": "agent-field", "identity": "id-agent-field"},
        "resource": {"id": "mission:InspectionInput"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"authorizationId": "az-openshell-files", "validity": {"state": "valid"}},
        "provenance": copy.deepcopy(policy["provenance"]),
    }
    body.update(overrides)
    return body


def delegation_exchange(policy, state="valid", can_delegate=True, kind="delegable"):
    return {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "ex-delegate",
        "exchangeType": "Delegation",
        "policyId": policy["policyId"],
        "traceId": "trace-q13c-delegation",
        "actor": {"id": "agent-field", "identity": "id-agent-field"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": kind},
        "authorization": {"authorizationId": "az-openshell-files", "validity": {"state": "valid"}},
        "delegation": {"authorityId": "auth-mission-control", "canDelegate": can_delegate},
        "validity": {"state": state},
        "provenance": copy.deepcopy(policy["provenance"]),
    }


def with_window(policy, state):
    cloned = copy.deepcopy(policy)
    cloned["validities"] = [{"validityId": "val-emergency", "state": state}]
    cloned["authorizations"][0]["conditions"] = [
        {"conditionId": "cond-emergency", "type": "validity-window", "validityId": "val-emergency"}
    ]
    return cloned


def with_scope(policy):
    cloned = copy.deepcopy(policy)
    cloned["scopes"] = [{"scopeId": "scope-mission", "dimension": "mission", "value": "inspection"}]
    cloned["authorizations"][0]["conditions"] = [
        {"conditionId": "cond-scope", "type": "scope-match", "scopeId": "scope-mission"}
    ]
    return cloned


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
        "compilation": "NOT_COMPILED",
        "deployable": False,
        "coverageDisposition": None,
        "policy": None,
    }
    if ir is None:
        return result
    source = document
    verdict = verify_derivation(ir, source, policy=policy, approvals=approvals)
    coverage = assess_coverage(
        ir, MANIFEST, PROFILE, document=source, policy=policy, approvals=approvals
    )
    compiled = ADAPTER.compile_policy(
        ir, coverage, MANIFEST, PROFILE, document=source, policy=policy, approvals=approvals
    )
    result.update({
        "derivationMatched": verdict["matched"] is True,
        "coverageDisposition": (coverage.get("coverage") or {}).get("compilationDisposition"),
        "compilation": compiled.get("compilationDisposition"),
        "deployable": compiled.get("deployable") is True and compiled.get("compilationDisposition") == "FULL",
        "policy": compiled.get("generatedPolicy"),
        "diagnostics": list(compiled.get("diagnostics") or []),
    })
    return result


CASES = []


def add(case):
    CASES.append(case)
    return case


def substrate_rows():
    rows = []
    for item in PROFILE.get("acceptedExecutionSubstrate") or []:
        path = (item.get("locator") or {}).get("path")
        if isinstance(path, str) and path:
            rows.append({"operation": item.get("operation"), "path": path})
    return rows


def ir_grants(ir):
    pairs = []
    for binding in (ir or {}).get("bindings") or []:
        if binding.get("kind") != "filesystem":
            continue
        path = (binding.get("locator") or {}).get("path")
        operation = binding.get("operation")
        if isinstance(path, str) and path and operation in ("read", "write"):
            pairs.append((operation, path))
    return pairs


def summarize(case, observed):
    return {
        "id": case["id"],
        "attack": case.get("attack"),
        "eventType": case["eventType"],
        "transition": case.get("transition"),
        "semantic": observed["semantic"],
        "codes": observed["codes"],
        "reasons": observed["reasons"],
        "operationalIr": observed["ir"] is not None,
        "derivationMatched": observed["derivationMatched"],
        "compilation": observed["compilation"],
        "deployable": observed["deployable"],
        "classification": case.get("classification"),
        "sourceDigest": digest(case["source"]),
    }


def executable_authority(observed):
    """An outstanding approval is not executable authority.

    The evaluator reports AUTHORIZED with approval_required, and projection
    emits no operational IR. That state matches a missing approval. It is
    not acceptance of a supplied decision.
    """
    if observed["ir"] is not None or observed["deployable"]:
        return True
    return observed["semantic"] == "AUTHORIZED" and "approval_required" not in (observed["codes"] or [])


def classify_closed(observed, classification):
    if executable_authority(observed):
        return "SEMANTIC_AUTHORITY_ACCEPTED", True
    return classification, False


def main():
    if (OUT / "results.json").exists():
        print("refusing to overwrite " + RUN_ID)
        return 3
    OUT.mkdir(parents=True, exist_ok=True)
    policy = base_policy()
    current = realize(request_exchange(policy), policy=policy)
    if current["semantic"] != "AUTHORIZED" or not current["deployable"]:
        print("baseline control did not authorize an exact read")
        return 2
    installed = current["policy"]
    installed_ir = current["ir"]
    order = 0
    rows = []
    failure = None

    def run(case, observed, source, extra=None):
        nonlocal order, failure
        order += 1
        record = summarize(case, observed)
        record["order"] = order
        record["observedAt"] = datetime.now(timezone.utc).isoformat()
        companion = None
        if extra:
            companion = extra.pop("companionPolicy", None)
            record.update(extra)
        rows.append(record)
        if record.get("gateFailure") or case.get("gateFailure"):
            failure = {
                "record": record,
                "source": source,
                "observed": _public(observed),
                "companionPolicy": companion,
                "before": {
                    "semantic": "AUTHORIZED",
                    "operationalIr": installed_ir is not None,
                    "policyDigest": digest(policy),
                },
            }
            return True
        return False

    def closed(case_id, attack, event, source, policy_arg=None, approvals=None, transition=None, classification="SEMANTICALLY_PREVENTED"):
        observed = realize(source, policy=policy_arg, approvals=approvals)
        classification, failed = classify_closed(observed, classification)
        case = {
            "id": case_id,
            "attack": attack,
            "eventType": event,
            "transition": transition,
            "classification": classification,
            "source": source,
            "gateFailure": failed,
        }
        extra = {"gateFailure": failed}
        if failed:
            extra["failure"] = "current facts do not authorize this interaction, but the decision or projection did"
            extra["companionPolicy"] = policy_arg
        return run(case, observed, source, extra)

    # T0
    bare = copy.deepcopy(policy)
    bare["authorizations"] = []
    if closed("T0", None, "semantic-authority-update", request_exchange(bare), policy_arg=bare, transition="T0"):
        return finish(rows, failure, installed, installed_ir)
    # T1
    opened = realize(request_exchange(policy), policy=policy)
    if opened["semantic"] != "AUTHORIZED":
        return finish(rows, _force("T1", "semantic expansion did not authorize", opened, policy), installed, installed_ir, pending=run)
    run({
        "id": "T1", "attack": None, "eventType": "semantic-authority-update", "transition": "T1",
        "classification": "SEMANTICALLY_PREVENTED", "source": policy,
    }, opened, policy, {"classification": "positive-authorized", "gateFailure": False})
    # T2
    if not (opened["derivationMatched"] and opened["deployable"]):
        return finish(rows, _force("T2", "exact interaction did not derive and deploy", opened, policy), installed, installed_ir)
    run({
        "id": "T2", "attack": None, "eventType": "interaction-decision", "transition": "T2",
        "classification": "positive-authorized", "source": policy,
    }, opened, policy, {"gateFailure": False, "coverage": opened["coverageDisposition"]})
    # T3 purpose substituted
    if closed("T3", "J", "interaction-decision", request_exchange(policy, purpose="OtherPurpose"), policy, transition="T3"):
        return finish(rows, failure, installed, installed_ir)
    # T4 restored
    restored = realize(request_exchange(policy), policy=policy)
    if restored["semantic"] != "AUTHORIZED" or not restored["deployable"]:
        return finish(rows, _force("T4", "restored purpose did not authorize", restored, policy), installed, installed_ir)
    run({
        "id": "T4", "attack": None, "eventType": "semantic-authority-update", "transition": "T4",
        "classification": "positive-authorized", "source": policy,
    }, restored, policy, {"gateFailure": False})
    # T5 expired delegation
    expired = delegation_exchange(policy, state="expired", can_delegate=True, kind="delegable")
    policy_delegable = copy.deepcopy(policy)
    policy_delegable["authorities"][0]["kind"] = "delegable"
    if closed("T5", "D", "semantic-authority-update", expired, policy_delegable, transition="T5"):
        return finish(rows, failure, installed, installed_ir)
    # T6 is authorized only after the delegation predicate permits it.
    # The same delegable authority with canDelegate false must already be denied.
    refused = delegation_exchange(policy, state="valid", can_delegate=False, kind="delegable")
    refused_observed = realize(refused, policy=policy_delegable)
    if refused_observed["semantic"] == "AUTHORIZED" or refused_observed["ir"] is not None:
        return finish(rows, _force("T6", "delegation predicate was not applied", refused_observed, refused), installed, installed_ir)
    fresh = delegation_exchange(policy, state="valid", can_delegate=True, kind="delegable")
    delegated = realize(fresh, policy=policy_delegable)
    if delegated["semantic"] != "AUTHORIZED" or delegated["ir"] is None:
        return finish(rows, _force("T6", "bounded delegation was not authorized", delegated, fresh), installed, installed_ir)
    run({
        "id": "T6", "attack": None, "eventType": "semantic-authority-update", "transition": "T6",
        "classification": "positive-authorized", "source": fresh,
    }, delegated, fresh, {
        "gateFailure": False,
        "delegationPredicate": "canDelegate true authorized; canDelegate false denied before the action grant",
        "refusedDecision": refused_observed["semantic"],
        "refusedCodes": refused_observed["codes"],
    })
    # T7 condition ends
    ended = with_window(policy, "expired")
    if closed("T7", "A", "semantic-authority-update", request_exchange(ended), ended, transition="T7"):
        return finish(rows, failure, installed, installed_ir)

    attacks = [
        ("A-stale-emergency", "A", "semantic-authority-update", request_exchange(ended, emergency=True), ended, None),
        ("B-stale-context", "B", "interaction-decision", request_exchange(policy, purpose="StalePurpose", contextSnapshot="v17"), policy, None),
        ("C-stale-state-label", "C", "interaction-decision", request_exchange(ended, authorityState="v17"), ended, None),
        ("E-revoked-delegation", "E", "semantic-authority-update", delegation_exchange(policy, state="revoked", can_delegate=True, kind="delegable"), policy_delegable, None),
        ("F-forged-delegation", "F", "interaction-decision", delegation_exchange(policy, state="valid", can_delegate=False, kind="direct"), policy, None),
    ]
    for case_id, attack, event, source, policy_arg, approvals in attacks:
        if closed(case_id, attack, event, source, policy_arg, approvals):
            return finish(rows, failure, installed, installed_ir)

    approval_policy = load(APPROVAL)
    approval = load(APPROVAL_DECISION)
    before = realize(approval_policy)
    if before["semantic"] == "AUTHORIZED" and before["ir"] is not None:
        return finish(rows, _force("approval-before", "approval was executable before a decision", before, approval_policy), installed, installed_ir)
    run({
        "id": "approval-before", "attack": "G", "eventType": "interaction-decision",
        "classification": "SEMANTICALLY_PREVENTED", "source": approval_policy,
    }, before, approval_policy, {"gateFailure": False})
    after = realize(approval_policy, approvals=[approval])
    if after["semantic"] != "AUTHORIZED":
        return finish(rows, _force("approval-after", "current approval did not authorize", after, approval_policy), installed, installed_ir)
    run({
        "id": "approval-after", "attack": "G", "eventType": "semantic-authority-update",
        "classification": "positive-authorized", "source": approval,
    }, after, approval_policy, {"gateFailure": False, "deployableNote": "delete is not an OpenShell filesystem compile target"})

    replay_purpose = request_exchange(approval_policy, purpose="OtherPurpose", action="DeleteInspectionOutput", resource={"id": "mission:InspectionOutput"})
    if closed("G-replay-purpose", "G", "interaction-decision", replay_purpose, approval_policy, [approval]):
        return finish(rows, failure, installed, installed_ir)
    expired_approval = copy.deepcopy(approval)
    expired_approval["decision"]["validity"] = {"state": "expired"}
    expired_observed = realize(approval_policy, approvals=[expired_approval])
    classification, failed = classify_closed(expired_observed, "SEMANTICALLY_PREVENTED")
    if run({
        "id": "G-expired-approval", "attack": "G", "eventType": "semantic-authority-update",
        "classification": classification, "source": expired_approval, "gateFailure": failed,
    }, expired_observed, expired_approval, {"gateFailure": failed}):
        return finish(rows, failure, installed, installed_ir)

    scoped = with_scope(policy)
    matched_scope = request_exchange(scoped, scope=[{"dimension": "mission", "value": "inspection"}])
    scope_ok = realize(matched_scope, policy=scoped)
    if scope_ok["semantic"] != "AUTHORIZED":
        return finish(rows, _force("K-scope-match", "matching scope was denied", scope_ok, scoped), installed, installed_ir)
    run({
        "id": "K-scope-match", "attack": "K", "eventType": "interaction-decision",
        "classification": "positive-authorized", "source": matched_scope,
    }, scope_ok, scoped, {"gateFailure": False})
    if closed("K-scope-substitution", "K", "interaction-decision", request_exchange(scoped, scope=[{"dimension": "mission", "value": "other"}]), scoped):
        return finish(rows, failure, installed, installed_ir)
    if closed("L-resource-substitution", "L", "interaction-decision", request_exchange(policy, resource={"id": "mission:Other"}), policy):
        return finish(rows, failure, installed, installed_ir)
    if closed("M-actor-substitution", "M", "interaction-decision", request_exchange(policy, actor={"id": "other-agent", "identity": "id-other"}), policy):
        return finish(rows, failure, installed, installed_ir)

    role_exchange = request_exchange(policy, role="unrelated-role")
    role_observed = realize(role_exchange, policy=policy)
    role_changed_grant = role_observed["ir"] != installed_ir and role_observed["semantic"] == "AUTHORIZED"
    run({
        "id": "N-role-substitution", "attack": "N", "eventType": "interaction-decision",
        "classification": "SEMANTICALLY_PREVENTED" if not role_changed_grant else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": role_exchange, "gateFailure": role_changed_grant,
    }, role_observed, role_exchange, {
        "gateFailure": role_changed_grant,
        "note": "role is not a consistency field on this authorization; the authorized action is unchanged" if not role_changed_grant else "role substitution changed the grant",
    })
    if role_changed_grant:
        return finish(rows, failure, installed, installed_ir)

    replaced = copy.deepcopy(policy)
    replaced["executionBindings"][0]["locator"] = {"path": "/mission/archive"}
    fresh_binding = realize(request_exchange(replaced), policy=replaced)
    stale_binding = verify_derivation(installed_ir, request_exchange(replaced), policy=replaced)
    binding_failed = stale_binding["matched"] is True
    run({
        "id": "O-binding-substitution", "attack": "O", "eventType": "semantic-authority-update",
        "classification": "DERIVATION_REJECTED" if not binding_failed else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": replaced, "gateFailure": binding_failed,
    }, fresh_binding, replaced, {"gateFailure": binding_failed, "staleDerivationMatched": stale_binding["matched"]})
    if binding_failed:
        return finish(rows, failure, installed, installed_ir)

    foreign_decision = copy.deepcopy(approval)
    foreign_decision["policyId"] = "pol-foreign"
    foreign_decision["decision"]["requirementId"] = "req-foreign"
    foreign_observed = realize(approval_policy, approvals=[foreign_decision])
    classification, failed = classify_closed(foreign_observed, "SEMANTICALLY_PREVENTED")
    if run({
        "id": "Q-foreign-decision", "attack": "Q", "eventType": "interaction-decision",
        "classification": classification, "source": foreign_decision, "gateFailure": failed,
    }, foreign_observed, foreign_decision, {"gateFailure": failed}):
        return finish(rows, failure, installed, installed_ir)

    foreign_context = request_exchange(ended, foreignEmergencyEvidence={"enterprise": "other", "state": "active"})
    if closed("R-foreign-emergency", "R", "interaction-decision", foreign_context, ended):
        return finish(rows, failure, installed, installed_ir)

    prover = request_exchange(policy, purpose="OtherPurpose", proverResult="PASS", openshellApproval="approved")
    if closed("S-T-approval-and-prover", "S", "technical-policy-update", prover, policy):
        return finish(rows, failure, installed, installed_ir)

    contracted = copy.deepcopy(policy)
    contracted["validity"] = {"state": "expired"}
    contracted_observed = realize(request_exchange(contracted), policy=contracted)
    classification, failed = classify_closed(contracted_observed, "SEMANTICALLY_PREVENTED")
    if run({
        "id": "U-contraction", "attack": "U", "eventType": "semantic-authority-update",
        "classification": classification, "source": contracted, "gateFailure": failed,
    }, contracted_observed, contracted, {"gateFailure": failed}):
        return finish(rows, failure, installed, installed_ir)
    stale_reasons = ADAPTER.verify_policy(installed, [], substrate_rows())
    stale_detected = bool(stale_reasons)
    run({
        "id": "U-stale-target-policy", "attack": "U", "eventType": "technical-policy-update",
        "classification": "TARGET_STALE_DETECTED" if stale_detected else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": contracted, "gateFailure": not stale_detected,
    }, contracted_observed, contracted, {
        "gateFailure": not stale_detected,
        "staleReasons": stale_reasons,
        "retracted": False,
        "targetLifetime": "REQUIRES_CONTEXT_RESTART",
    })
    if not stale_detected:
        return finish(rows, failure, installed, installed_ir)

    reloaded = verify_derivation(installed_ir, request_exchange(contracted), policy=contracted)
    run({
        "id": "V-older-verified-policy", "attack": "V", "eventType": "technical-policy-update",
        "classification": "DERIVATION_REJECTED" if reloaded["matched"] is False else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": contracted, "gateFailure": reloaded["matched"] is True,
    }, contracted_observed, contracted, {"gateFailure": reloaded["matched"] is True, "staleDerivationMatched": reloaded["matched"]})
    if reloaded["matched"] is True:
        return finish(rows, failure, installed, installed_ir)

    foreign_ir = verify_derivation(installed_ir, approval_policy)
    run({
        "id": "foreign-ir", "attack": "Q", "eventType": "interaction-decision",
        "classification": "DERIVATION_REJECTED" if foreign_ir["matched"] is False else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": approval_policy, "gateFailure": foreign_ir["matched"] is True,
    }, realize(approval_policy, approvals=[approval]), approval_policy, {
        "gateFailure": foreign_ir["matched"] is True,
        "staleDerivationMatched": foreign_ir["matched"],
    })
    if foreign_ir["matched"] is True:
        return finish(rows, failure, installed, installed_ir)

    mediated = realize(request_exchange(contracted), policy=contracted)
    run({
        "id": "mediated-federation", "attack": "M-federation", "eventType": "semantic-authority-update",
        "classification": "SEMANTICALLY_PREVENTED" if mediated["semantic"] != "AUTHORIZED" else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": contracted, "gateFailure": mediated["semantic"] == "AUTHORIZED",
    }, mediated, contracted, {
        "gateFailure": mediated["semantic"] == "AUTHORIZED",
        "outerGatewayTechnicallyOpen": True,
        "outerGatewayIsNotFipAuthority": True,
        "runtimeEffect": "UNOBSERVED",
    })

    foreign_delegation = delegation_exchange(policy, state="valid", can_delegate=True, kind="delegable")
    foreign_delegation["policyId"] = "pol-foreign"
    foreign_delegation_observed = realize(foreign_delegation, policy=policy_delegable)
    foreign_failed = foreign_delegation_observed["semantic"] == "AUTHORIZED" or foreign_delegation_observed["ir"] is not None
    if run({
        "id": "foreign-delegation", "attack": "Q", "eventType": "interaction-decision",
        "classification": "SEMANTICALLY_PREVENTED" if not foreign_failed else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": foreign_delegation, "gateFailure": foreign_failed,
    }, foreign_delegation_observed, foreign_delegation, {"gateFailure": foreign_failed}):
        return finish(rows, failure, installed, installed_ir)

    replay_after_expiry = delegation_exchange(policy, state="expired", can_delegate=True, kind="delegable")
    if closed("I-decision-after-delegation-expiry", "I", "interaction-decision", replay_after_expiry, policy_delegable, [approval]):
        return finish(rows, failure, installed, installed_ir)

    widened = copy.deepcopy(installed)
    widened["filesystem_policy"]["read_only"] = list(widened["filesystem_policy"]["read_only"]) + ["/mission/secret"]
    widened_reasons = ADAPTER.verify_policy(widened, ir_grants(installed_ir), substrate_rows())
    widened_detected = bool(widened_reasons)
    run({
        "id": "toctou-target-expanded", "attack": "TOCTOU-C", "eventType": "technical-policy-update",
        "classification": "TARGET_STALE_DETECTED" if widened_detected else "SEMANTIC_AUTHORITY_ACCEPTED",
        "source": contracted, "gateFailure": not widened_detected,
    }, contracted_observed, contracted, {"gateFailure": not widened_detected, "staleReasons": widened_reasons})
    if not widened_detected:
        return finish(rows, failure, installed, installed_ir)

    for case_id, note, classification in (
        ("toctou-mid-operation", "delegation expiry during an operation is a fresh denial; no live operation was running", "UNOBSERVED"),
        ("long-running-action", "no action was started under authority and left running after revocation", "UNOBSERVED"),
        ("session-persistence", "no TCP or service session was established; filesystem policy replacement requires context restart", "TARGET_LIMITED"),
        ("credential-persistence", "no provider credential was used; independent credential-use authority stays outside this run", "TARGET_LIMITED"),
        ("alternate-route", "outer connectivity was not executed; the semantic gateway denial is the mediated-federation row", "UNOBSERVED"),
    ):
        run({
            "id": case_id, "attack": case_id, "eventType": "technical-policy-update",
            "classification": classification, "source": contracted, "gateFailure": False,
        }, contracted_observed, contracted, {"gateFailure": False, "note": note, "runtimeEffect": "UNOBSERVED"})

    return finish(rows, None, installed, installed_ir)


def _public(observed):
    return {key: value for key, value in observed.items() if key != "policy"}


def _force(case_id, message, observed, source):
    return {
        "record": {"id": case_id, "gateFailure": True, "failure": message, "semantic": observed["semantic"]},
        "source": source,
        "observed": _public(observed),
    }


def finish(rows, failure, installed, installed_ir, pending=None):
    del pending
    payload = {
        "run": RUN_ID,
        "generator": GENERATOR,
        "runtimeExecuted": False,
        "runtimeOperationalOpportunities": 0,
        "unauthorizedOperationalEffects": 0,
        "runtimeUOER": None,
        "targetLifetime": {
            "filesystem": "REQUIRES_CONTEXT_RESTART",
            "network_policies": "LIVE_UPDATE_SUPPORTED",
            "basis": "pinned OpenShell v0.1.2 policy update semantics; this run did not update a live sandbox",
        },
        "rows": rows,
        "gateFailure": failure is not None,
    }
    (OUT / "results.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (OUT / "transition-sequence.json").write_text(
        json.dumps([{key: row[key] for key in ("order", "id", "transition", "attack", "eventType", "semantic", "deployable", "classification", "gateFailure") if key in row} for row in rows], indent=2) + "\n",
        encoding="utf-8", newline="\n",
    )
    if failure:
        bundle = OUT / "failure"
        bundle.mkdir(exist_ok=True)
        (bundle / "record.json").write_text(json.dumps(failure["record"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (bundle / "source.json").write_text(json.dumps(failure["source"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (bundle / "observed.json").write_text(json.dumps(failure["observed"], indent=2, default=str) + "\n", encoding="utf-8", newline="\n")
        if installed is not None:
            (bundle / "prior-target-policy.json").write_text(json.dumps(installed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if installed_ir is not None:
            (bundle / "prior-ir.json").write_text(json.dumps(installed_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if failure.get("before") is not None:
            (bundle / "before.json").write_text(json.dumps(failure["before"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if failure.get("companionPolicy") is not None:
            (bundle / "companion-policy.json").write_text(json.dumps(failure["companionPolicy"], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        lines = ["# Q13C " + RUN_ID, "", "FAIL. The first gate failure is preserved. No later case was executed.", ""]
        lines.append("Case: " + str(failure["record"].get("id")))
        lines.append("")
        lines.append(failure["record"].get("failure") or "gate failure")
        (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        print("FAIL " + str(failure["record"].get("id")))
        return 1
    (OUT / "report.md").write_text("# Q13C " + RUN_ID + "\n\nCompleted the executed case list without a gate failure.\n", encoding="utf-8", newline="\n")
    print("completed " + str(len(rows)) + " cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
