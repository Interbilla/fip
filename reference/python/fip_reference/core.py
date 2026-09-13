"""Foundational UDG RC 0.1 standalone Python reference adapter.

Serialized-boundary only. No BILLA, CAMEO, Explorer, or Interbilla imports.
Not a production system. REFERENCE CANDIDATE. NOT A PUBLISHED STANDARD.
"""

from __future__ import annotations

import copy
import json
from typing import Any

VERSION = "0.1"
STATUS = "REFERENCE CANDIDATE"
PUBLICATION = "NOT A PUBLISHED STANDARD"
CANONICAL = "NOT CANONICAL EXTERNAL VOCABULARY"

FOUNDATIONAL_PRIMITIVES = [
    "Actor",
    "Resource",
    "Role",
    "Identity",
    "Credential",
    "Request",
    "Response",
    "Action",
    "Assertion",
    "Recommendation",
    "Instruction",
    "Delegation",
    "Decision",
    "Purpose",
    "Condition",
    "Constraint",
    "Authority",
    "Authorization",
    "Permission",
    "Prohibition",
    "Obligation",
    "Policy",
    "Evidence",
    "Provenance",
    "Validity",
    "Scope",
]

RELATIONS = [
    "requests",
    "respondsTo",
    "usesResource",
    "hasPurpose",
    "hasIdentity",
    "presentsCredential",
    "hasRole",
    "ownedBy",
    "controlledBy",
    "actsUnderAuthority",
    "authorizedBy",
    "governedBy",
    "permits",
    "prohibits",
    "obligates",
    "constrainedBy",
    "appliesWithin",
    "validDuring",
    "delegatesTo",
    "delegatesAuthority",
    "hasEvidence",
    "derivedFrom",
    "assertedBy",
    "decidedBy",
]

SEMANTIC_ACTS = (
    "Assertion",
    "Recommendation",
    "Request",
    "Response",
    "Instruction",
    "Delegation",
    "Authorization",
    "Decision",
)
CONSEQUENTIAL_ACTS = ("Request", "Instruction", "Delegation", "Authorization")
NORMATIVE_STATES = ("allowed", "prohibited", "obligated", "unknown")
VALIDITY_STATES = ("valid", "expired", "revoked", "superseded", "not-yet-valid")
SCOPE_DIMENSIONS = ("spatial", "temporal", "jurisdictional")
FIREWALL_DECISIONS = ("PERMITTED", "DENIED", "INCOMPLETE", "ESCALATE")
PROTECTED_GOVERNANCE = (
    "authority",
    "authorization",
    "permission",
    "prohibition",
    "obligation",
    "delegation",
    "provenance",
    "policy",
    "validity",
)
FORBIDDEN_ESCALATIONS = {
    ("Assertion", "Instruction"),
    ("Assertion", "Authorization"),
    ("Assertion", "command"),
    ("Recommendation", "Instruction"),
    ("Recommendation", "Authorization"),
    ("Recommendation", "Delegation"),
    ("Request", "Permission"),
    ("Request", "Authorization"),
    ("Instruction", "Delegation"),
}
REQUIRED_BY_ACT = {
    "Assertion": ["actor", "resource", "provenance"],
    "Recommendation": ["actor", "action"],
    "Request": ["actor", "resource", "action", "purpose"],
    "Response": ["actor", "respondsTo"],
    "Instruction": ["actor", "resource", "action", "authority", "authorization"],
    "Delegation": ["actor", "delegation", "action", "authority"],
    "Authorization": ["actor", "authorization", "authority"],
    "Decision": ["decision", "provenance"],
}

DEFINITION = (
    "A semantic micro-firewall constrains which semantic assertions are "
    "allowed to cross a trust boundary and acquire operational effect."
)
NOT_CLAIM = (
    "This evaluator does not claim that a semantic micro-firewall prevents "
    "all prompt injection."
)


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _validity(exchange: dict[str, Any]) -> str | None:
    auth = exchange.get("authorization") or {}
    validity = exchange.get("validity") or {}
    return auth.get("validity") or validity.get("state")


def _normative(exchange: dict[str, Any]) -> str:
    return str((exchange.get("normative") or {}).get("state") or "unknown")


def _meta() -> dict[str, Any]:
    return {
        "status": STATUS,
        "publication": PUBLICATION,
        "canonical": CANONICAL,
        "version": VERSION,
        "published_objects": 0,
        "canonical_swids": 0,
        "new_foundational_primitives": 0,
        "new_foundational_relations": 0,
    }


def parse(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("exchange_must_be_object")
    return payload


def serialize(exchange: dict[str, Any]) -> str:
    return json.dumps(normalize(exchange), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def normalize(exchange: dict[str, Any]) -> dict[str, Any]:
    row = copy.deepcopy(exchange)
    row.setdefault("status", STATUS)
    row.setdefault("publication", PUBLICATION)
    row.setdefault("canonical", CANONICAL)
    return row


def preserve_extensions(exchange: dict[str, Any]) -> list[dict[str, Any]]:
    return copy.deepcopy(list(exchange.get("extensions") or []))


def validate(exchange: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    act = str(exchange.get("exchangeType") or "")
    if act not in SEMANTIC_ACTS:
        errors.append(f"unknown_exchange_type:{act or 'missing'}")
        return _validation(False, errors, warnings, act, exchange)
    for field in REQUIRED_BY_ACT.get(act, []):
        if field == "delegation" and not _present(exchange.get("delegation")):
            errors.append("missing:delegation")
        elif field == "respondsTo" and not _present(exchange.get("respondsTo")):
            errors.append("missing:respondsTo")
        elif field == "decision" and not _present(
            (exchange.get("decision") or {}).get("value")
            if isinstance(exchange.get("decision"), dict)
            else exchange.get("decision")
        ):
            errors.append("missing:decision")
        elif field not in {"delegation", "respondsTo", "decision"} and not _present(exchange.get(field)):
            errors.append(f"missing:{field}")
    attempted = exchange.get("attemptedEffect")
    if attempted and (act, str(attempted)) in FORBIDDEN_ESCALATIONS:
        errors.append(f"silent_type_change:{act}->{attempted}")
    for scope in exchange.get("scope") or []:
        dim = (scope or {}).get("dimension")
        if dim and dim not in SCOPE_DIMENSIONS:
            errors.append(f"unknown_scope_dimension:{dim}")
    validity = _validity(exchange)
    if validity and validity not in VALIDITY_STATES:
        errors.append(f"unknown_validity:{validity}")
    for ext in exchange.get("extensions") or []:
        claims = ext.get("claims") or {}
        for key in PROTECTED_GOVERNANCE:
            if claims.get(key) or ext.get(f"override_{key}"):
                errors.append(f"extension_overrides_{key}")
        if ext.get("eraseProvenance") or claims.get("erase_provenance"):
            errors.append("extension_suppresses_provenance")
    if act in CONSEQUENTIAL_ACTS and not _present(exchange.get("provenance")):
        warnings.append("consequential_exchange_missing_provenance")
    return _validation(not errors, errors, warnings, act, exchange)


def evaluate(exchange: dict[str, Any]) -> dict[str, Any]:
    validation = validate(exchange)
    act = str(exchange.get("exchangeType") or "")
    attempted = exchange.get("attemptedEffect")
    untrusted: list[str] = []
    missing: list[str] = []
    evaluated = {
        "identity": _present((exchange.get("actor") or {}).get("id") or exchange.get("actor")),
        "role": _present((exchange.get("actor") or {}).get("role")),
        "act": act,
        "resource": _present(exchange.get("resource")),
        "action": _present(exchange.get("action")),
        "purpose": _present(exchange.get("purpose")),
        "authority": _present(exchange.get("authority")),
        "authorization": _present(exchange.get("authorization")),
        "credential": _present(exchange.get("credential")),
        "policy": _present(exchange.get("policy")),
        "scope": bool(exchange.get("scope")),
        "validity": _validity(exchange),
        "delegation": _present(exchange.get("delegation")),
        "provenance": _present(exchange.get("provenance")),
        "evidence": _present(exchange.get("evidence")),
        "normative": _normative(exchange),
    }

    if exchange.get("untrustedFreeText") and not evaluated["authority"]:
        return _decision("DENIED", exchange, validation, evaluated, ["Untrusted natural language does not create authority."], ["free_text_cannot_manufacture_authority"], [], [])
    if exchange.get("authoritySource") == "free_text":
        return _decision("DENIED", exchange, validation, evaluated, ["Natural-language interpretation alone does not create operational authority."], ["authority_source_free_text"], [], [])
    if exchange.get("channel") == "agent-to-memory" and attempted in {"manufacture_authority", "authorization"}:
        return _decision("DENIED", exchange, validation, evaluated, ["An agent cannot manufacture authority by writing to shared memory."], ["memory_cannot_manufacture_authority"], [], [])
    if attempted and (act, str(attempted)) in FORBIDDEN_ESCALATIONS:
        return _decision("DENIED", exchange, validation, evaluated, [f"{act} must not silently become {attempted}."], ["silent_semantic_escalation"], [], [])

    for ext in exchange.get("extensions") or []:
        claims = ext.get("claims") or {}
        ns = ext.get("namespace") or "unknown"
        if not ext.get("recognized", True):
            untrusted.append(ns)
        if claims.get("authority") or claims.get("permission") or claims.get("delegation"):
            return _decision("DENIED", exchange, validation, evaluated, ["Unknown or hostile extension cannot manufacture authority, permission, or delegation."], ["extension_cannot_grant_authority"], [], untrusted)
        if claims.get("override_policy") or ext.get("override_policy"):
            return _decision("DENIED", exchange, validation, evaluated, ["Extension cannot override foundational policy."], ["extension_cannot_override_policy"], [], untrusted)
        if ext.get("eraseProvenance") or claims.get("erase_provenance"):
            return _decision("DENIED", exchange, validation, evaluated, ["Extension cannot suppress foundational provenance."], ["extension_cannot_erase_provenance"], [], untrusted)

    validity = _validity(exchange)
    if validity in {"expired", "revoked", "superseded"}:
        return _decision("DENIED", exchange, validation, evaluated, [f"Authorization/authority is {validity}."], [f"validity_{validity}"], [], untrusted)
    if validity == "not-yet-valid":
        return _decision("DENIED", exchange, validation, evaluated, ["Authorization is not yet valid."], ["validity_not_yet_valid"], [], untrusted)
    if _normative(exchange) == "prohibited":
        return _decision("DENIED", exchange, validation, evaluated, ["Explicit prohibition applies. Absence of permission is not required for this deny."], ["explicit_prohibition"], [], untrusted)

    expected_scope = exchange.get("expectedScope") or []
    if expected_scope and exchange.get("scope"):
        got = {(row.get("dimension"), row.get("value")) for row in exchange.get("scope") or []}
        need = {(row.get("dimension"), row.get("value")) for row in expected_scope}
        if not need.issubset(got):
            return _decision("DENIED", exchange, validation, evaluated, ["Scope does not match the authorized spatial/temporal bound."], ["scope_mismatch"], [], untrusted)
    if exchange.get("expectedPurpose") and exchange.get("purpose") and exchange.get("purpose") != exchange.get("expectedPurpose"):
        return _decision("DENIED", exchange, validation, evaluated, ["Purpose does not match the authorized purpose."], ["purpose_mismatch"], [], untrusted)
    if exchange.get("expectedActor") and (exchange.get("actor") or {}).get("id") not in {exchange.get("expectedActor"), None}:
        if (exchange.get("actor") or {}).get("id") != exchange.get("expectedActor"):
            return _decision("DENIED", exchange, validation, evaluated, ["Identity does not match the authorized actor."], ["identity_mismatch"], [], untrusted)
    if exchange.get("staleReplay"):
        return _decision("DENIED", exchange, validation, evaluated, ["Stale exchange replay is not accepted."], ["stale_replay"], [], untrusted)
    if exchange.get("tamperedAfterBinding"):
        return _decision("DENIED", exchange, validation, evaluated, ["Extension or payload changed after provenance binding."], ["tampered_after_binding"], [], untrusted)
    if exchange.get("conflictingPolicy"):
        return _decision("ESCALATE", exchange, validation, evaluated, ["Applicable policies conflict; human or higher-assurance review is required."], ["conflicting_policy"], [], untrusted)

    if exchange.get("correlatedPrivilegeChain") or (exchange.get("history") or {}).get("privilegeEscalationPath"):
        return _decision("ESCALATE", exchange, validation, evaluated, ["Cross-boundary correlated privilege chain requires review. No new Foundational primitive is required."], ["correlated_privilege_chain"], [], untrusted)

    instruction = exchange.get("instruction") or {}
    trusted = exchange.get("trustedEvidence") or {}
    if exchange.get("evidenceMismatch") or (
        instruction.get("requested_command")
        and trusted.get("observed_command")
        and instruction.get("requested_command") != trusted.get("observed_command")
    ):
        return _decision("ESCALATE", exchange, validation, evaluated, ["Trusted evidence contradicts asserted or requested action. Agent self-report is not ground truth."], ["EVIDENCE_MISMATCH", "PROVENANCE_MISMATCH"], [], untrusted)

    if exchange.get("evidenceSource") == "agent_self_report" and act in CONSEQUENTIAL_ACTS:
        return _decision("ESCALATE", exchange, validation, evaluated, ["Agent-declared assertion is not independently provenanced evidence."], ["assertion_is_not_trusted_evidence"], [], untrusted)

    if exchange.get("purpose") in {"cross-agent-communication", "establish-cross-agent-channel"}:
        if not (exchange.get("authorization") or {}).get("permitsCommunication"):
            return _decision("DENIED", exchange, validation, evaluated, ["Valid package-access credential is not authorization to establish cross-agent communication."], ["package_access_is_not_communication_authorization"], [], untrusted)

    if exchange.get("emergentCoordination") or exchange.get("emergentDelegation"):
        chain = (exchange.get("delegation") or {}).get("authorizedChain")
        if not chain:
            return _decision("DENIED", exchange, validation, evaluated, ["Emergent coordination is not enterprise delegation."], ["coordination_is_not_enterprise_delegation"], [], untrusted)

    if evaluated["credential"] and not evaluated["authorization"] and (
        act in CONSEQUENTIAL_ACTS or _present(exchange.get("action"))
    ):
        return _decision("DENIED", exchange, validation, evaluated, ["A technically valid credential is not authorization."], ["credential_is_not_authorization"], [], untrusted)

    if act == "Delegation":
        delegation = exchange.get("delegation") or {}
        if not delegation.get("canDelegate") and not (exchange.get("authority") or {}).get("kind") == "delegable":
            return _decision("DENIED", exchange, validation, evaluated, ["Delegation requires explicit authority to delegate."], ["delegation_requires_explicit_authority"], [], untrusted)
        if delegation.get("canDelegate") is False:
            return _decision("DENIED", exchange, validation, evaluated, ["Delegation requires explicit authority to delegate."], ["delegation_requires_explicit_authority"], [], untrusted)

    if act in CONSEQUENTIAL_ACTS:
        for field in REQUIRED_BY_ACT.get(act, []):
            if field == "delegation" and not _present(exchange.get("delegation")):
                missing.append("delegation")
            elif field not in {"delegation", "respondsTo", "decision"} and not _present(exchange.get(field)):
                missing.append(field)
        if act in {"Request", "Instruction", "Delegation", "Authorization"} and not evaluated["authority"]:
            missing.append("authority")
        if not evaluated["provenance"]:
            missing.append("provenance")
        missing = list(dict.fromkeys(missing))
        if missing:
            return _decision("INCOMPLETE", exchange, validation, evaluated, ["Missing structured fields: " + ", ".join(missing) + "."], ["incomplete_structured_fields"], missing, untrusted)
        if evaluated["authority"] and not evaluated["policy"]:
            return _decision("ESCALATE", exchange, validation, evaluated, ["Authority is present but policy is not independently established."], ["authority_without_policy"], [], untrusted)
        if act == "Request" and _normative(exchange) == "unknown" and not (exchange.get("authorization") or {}).get("id"):
            return _decision("ESCALATE", exchange, validation, evaluated, ["Permission is not established. Absence of prohibition is not permission."], ["permission_not_established"], [], untrusted)

    if act == "Recommendation":
        return _decision("DENIED", exchange, validation, evaluated, ["A recommendation may be recorded but does not acquire operational effect."], ["recommendation_has_no_operational_effect"], [], untrusted)
    if act == "Assertion":
        return _decision("DENIED", exchange, validation, evaluated, ["An informational assertion is not an operational instruction."], ["assertion_is_not_command"], [], untrusted)

    if untrusted and act in CONSEQUENTIAL_ACTS and not exchange.get("foundationalTrusted", True):
        return _decision("ESCALATE", exchange, validation, evaluated, ["Extension namespace is unrecognized; foundational layer is not independently trusted."], ["unknown_publisher"], [], untrusted)

    if evaluated["authority"] and evaluated["policy"] and evaluated["provenance"] and (validity in {None, "valid"}):
        return _decision("PERMITTED", exchange, validation, evaluated, ["Structured identity, authority, policy, validity, and provenance are consistent."], ["structured_governance_present"], [], untrusted)
    return _decision("ESCALATE", exchange, validation, evaluated, ["Structured fields are present but the boundary remains uncertain."], ["uncertain_boundary"], [], untrusted)


def round_trip(text: str) -> dict[str, Any]:
    first = parse(text)
    serialized = serialize(first)
    second = parse(serialized)
    mutated = serialize(second) != serialized
    return {
        "ok": not mutated,
        "serialized": serialized,
        "semantic_mutation": mutated,
        **_meta(),
    }


def _validation(ok: bool, errors: list[str], warnings: list[str], act: str, exchange: dict[str, Any]) -> dict[str, Any]:
    return {
        "valid": ok,
        "exchangeId": exchange.get("exchangeId"),
        "exchangeType": act,
        "errors": errors,
        "warnings": warnings,
        **_meta(),
    }


def _decision(
    decision: str,
    exchange: dict[str, Any],
    validation: dict[str, Any],
    evaluated: dict[str, Any],
    reasons: list[str],
    codes: list[str],
    missing: list[str],
    untrusted: list[str],
) -> dict[str, Any]:
    if decision not in FIREWALL_DECISIONS:
        raise ValueError(decision)
    authority = exchange.get("authority") or {}
    delegation = exchange.get("delegation") or {}
    return {
        "decision": decision,
        "reasons": reasons,
        "codes": codes,
        "evaluated": evaluated,
        "applicablePolicy": (exchange.get("policy") or {}).get("id"),
        "authorityChain": [item for item in [authority.get("id"), delegation.get("from"), delegation.get("to")] if item],
        "missingSemantics": missing,
        "untrustedExtensions": untrusted,
        "provenance": exchange.get("provenance"),
        "traceId": (exchange.get("provenance") or {}).get("traceId") or exchange.get("exchangeId"),
        "exchangeId": exchange.get("exchangeId"),
        "exchangeType": exchange.get("exchangeType"),
        "validation": validation,
        "llmRequired": False,
        "definition": DEFINITION,
        "notClaim": NOT_CLAIM,
        **_meta(),
    }


def evaluate_json(text: str) -> dict[str, Any]:
    return evaluate(parse(text))
