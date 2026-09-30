"""Derivation check for a consumed Enforcement IR.

The check recomputes Eval and Project from the current sources and compares
security-relevant content. A hash stored on the IR is not an authority anchor.
This module does not interpret authorization rules of its own.
"""

from __future__ import annotations

import json

from .project import project

_REQUIREMENT_FIELDS = (
    "requirementId",
    "effect",
    "bindingIds",
    "constraints",
    "conditions",
    "composition",
    "groupId",
    "lifetime",
    "audit",
    "bindingPattern",
    "authorizationId",
    "authorityId",
    "prohibitionIds",
    "approverIds",
)

_BINDING_FIELDS = (
    "bindingId",
    "resourceId",
    "actionId",
    "kind",
    "operation",
    "locator",
    "protocol",
    "disclosure",
    "lifetime",
)

_PROHIBITION_FIELDS = (
    "prohibitionId",
    "actionIds",
    "resourceIds",
    "bindingIds",
    "requirementIds",
    "bindingPattern",
)

_APPROVAL_FIELDS = (
    "satisfied",
    "requirementId",
    "exchangeId",
    "decisionId",
    "actorId",
    "effect",
    "provenance",
)


def verify_derivation(supplied_ir, document=None, policy=None, approvals=None):
    """Return whether supplied_ir matches a fresh projection of the sources.

    document is an AuthorityPolicy, or an Exchange when policy is the companion.
    A missing source cannot demonstrate derivation.
    """
    if document is None and policy is None:
        return _verdict(False, "derivation_sources_absent", None, None)
    if isinstance(document, dict) and document.get("document") == "Exchange":
        projected = project(document, policy=policy, approvals=approvals)
    else:
        projected = project(document if document is not None else policy, approvals=approvals)
    regenerated = projected.get("operationalIr")
    if regenerated is None:
        return _verdict(False, "no_operational_projection", projected.get("authorityDecision"), None)
    if not isinstance(supplied_ir, dict):
        return _verdict(False, "supplied_ir_missing", projected.get("authorityDecision"), regenerated)
    matched = _canonical(_security(supplied_ir)) == _canonical(_security(regenerated))
    return _verdict(
        matched,
        None if matched else "security_content_mismatch",
        projected.get("authorityDecision"),
        regenerated,
    )


def _verdict(matched, reason, authority_decision, regenerated):
    return {
        "matched": matched,
        "reason": reason,
        "authorityDecision": authority_decision,
        "operationalIr": regenerated,
    }


def _security(ir):
    coverage = ir.get("coverage") if isinstance(ir.get("coverage"), dict) else {}
    approvals = ir.get("approvals") or []
    return {
        "authorityDecision": ir.get("authorityDecision"),
        "policyId": ir.get("policyId"),
        "exchangeId": ir.get("exchangeId"),
        "authorizationIds": _id_list(ir.get("authorizationIds")),
        "authorityIds": _id_list(ir.get("authorityIds")),
        "requirements": [
            _pick(item, _REQUIREMENT_FIELDS)
            for item in sorted(ir.get("requirements") or [], key=lambda item: str(item.get("requirementId")))
        ],
        "groups": [
            _group(item)
            for item in sorted(ir.get("groups") or [], key=lambda item: str(item.get("groupId")))
        ],
        "prohibitions": [
            _pick(item, _PROHIBITION_FIELDS)
            for item in sorted(ir.get("prohibitions") or [], key=lambda item: str(item.get("prohibitionId")))
        ],
        "bindings": [
            _pick(item, _BINDING_FIELDS)
            for item in sorted(ir.get("bindings") or [], key=lambda item: str(item.get("bindingId")))
        ],
        "approvals": [
            _approval(item)
            for item in sorted(approvals, key=lambda item: str(item.get("requirementId")))
        ],
        "fipGrants": _id_list(coverage.get("fipGrants")),
    }


def _pick(item, fields):
    source = item if isinstance(item, dict) else {}
    picked = {}
    for field in fields:
        if field not in source:
            continue
        value = source[field]
        if isinstance(value, list) and value and not isinstance(value[0], (dict, list)):
            picked[field] = sorted(value, key=str)
        else:
            picked[field] = value
    return picked


def _group(item):
    source = item if isinstance(item, dict) else {}
    return {
        "groupId": source.get("groupId"),
        "composition": source.get("composition"),
        "requirementIds": _id_list(source.get("requirementIds")),
    }


def _approval(item):
    picked = _pick(item, _APPROVAL_FIELDS)
    provenance = picked.get("provenance")
    if isinstance(provenance, dict):
        picked["provenance"] = {
            key: value for key, value in provenance.items() if key != "traceId"
        }
    return picked


def _id_list(value):
    if not isinstance(value, list):
        return []
    return sorted((item for item in value if not isinstance(item, (dict, list))), key=str)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
