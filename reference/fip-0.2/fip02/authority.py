"""FIP 0.2 authority evaluation.

The result is an authority decision. This module is not a compiler, so
compilationDisposition is always NOT_COMPILED and deployable is always false.
A later compiler may consume an AUTHORIZED operational document. This module
does not produce that artifact.
"""

from __future__ import annotations

AUTHOR_OUTPUT_FIELDS = (
    "authorityDecision",
    "compilationDisposition",
    "runtimeDisposition",
    "deployable",
)

CONSEQUENTIAL = {"Request", "Instruction", "Delegation", "Authorization"}

REQUIRED_FIELDS = {
    "Assertion": ("actor", "resource", "provenance"),
    "Recommendation": ("actor", "action"),
    "Request": ("actor", "resource", "action", "purpose"),
    "Response": ("actor", "respondsTo"),
    "Instruction": ("actor", "resource", "action", "authority", "authorization"),
    "Delegation": ("actor", "delegation", "action", "authority"),
    "Authorization": ("actor", "authorization", "authority"),
    "Decision": ("decision", "provenance"),
}

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

PROTECTED_EXTENSIONS = {
    "decision",
    "codes",
    "authority",
    "authorization",
    "policy",
    "provenance",
    "validity",
    "normative",
}

VALIDITY_CODES = {
    "expired": "validity_expired",
    "revoked": "validity_revoked",
    "superseded": "validity_superseded",
    "not-yet-valid": "validity_not_yet_valid",
}

SEVERITY = {"DENIED": 0, "REVIEW": 1, "INCOMPLETE": 2, "AUTHORIZED": 3}


def assess(document, policy=None, approvals=None):
    """Evaluate one AuthorityPolicy or Exchange.

    policy is the companion AuthorityPolicy for an operational Exchange.
    approvals is a list of Decision exchanges. A missing companion is not
    inferred.
    """
    if not isinstance(document, dict):
        return _finish("INCOMPLETE", ["unknown_fip_version"], ["document_not_object"])
    stamped = [name for name in AUTHOR_OUTPUT_FIELDS if name in document]
    if stamped or "failClosed" in document:
        return _finish("INCOMPLETE", [], ["author_supplied_output"])
    version = document.get("fipVersion")
    if version != "0.2":
        if version == "0.1":
            return _finish("INCOMPLETE", [], ["version_0_1_requires_lifter"])
        return _finish("INCOMPLETE", ["unknown_fip_version"], [])
    kind = document.get("document")
    if kind == "AuthorityPolicy":
        return _assess_policy(document, approvals or [])
    if kind == "Exchange":
        return _assess_exchange(document, policy, approvals or [])
    return _finish("INCOMPLETE", [], ["unknown_document"])


def _finish(decision, codes, reasons, grants=None, extra=None):
    ordered = []
    for code in list(codes) + ["not_compiled"]:
        if code and code not in ordered:
            ordered.append(code)
    result = {
        "fipVersion": "0.2",
        "authorityDecision": decision,
        "compilationDisposition": "NOT_COMPILED",
        "deployable": False,
        "codes": ordered,
        "reasons": list(reasons),
    }
    if grants is not None:
        result["grants"] = grants
    if extra:
        result.update(extra)
    return result


def _assess_policy(policy, approvals):
    reasons = []
    if policy.get("status") != "ENFORCEMENT CANDIDATE":
        return _finish("INCOMPLETE", [], ["status"])
    mode = policy.get("mode")
    if mode not in ("operational", "semantic-only"):
        return _finish("INCOMPLETE", [], ["mode"])
    if not policy.get("policyId"):
        return _finish("INCOMPLETE", [], ["policyId"])
    if "validity" not in policy:
        return _finish("INCOMPLETE", [], ["validity"])
    validity = _validity_problem(policy.get("validity"))
    if validity:
        return _finish(validity[0], validity[1], ["policy_validity"])
    authorities = _index(policy.get("authorities") or [], "id")
    if authorities is None:
        return _finish("INCOMPLETE", [], ["duplicate_identifier"])
    if not authorities:
        return _finish("INCOMPLETE", ["missing_authority"], [])
    bindings = _index(policy.get("executionBindings") or [], "bindingId")
    requirements = _index(policy.get("enforcementRequirements") or [], "requirementId")
    if bindings is None or requirements is None:
        return _finish("INCOMPLETE", [], ["duplicate_identifier"])
    authorizations = policy.get("authorizations") or []
    obligations = policy.get("obligations") or []
    if not authorizations:
        if obligations:
            return _finish("INCOMPLETE", ["obligation_is_not_authority"], [])
        return _finish("REVIEW", ["absence_is_not_permission"], [])
    grants = []
    for authorization in authorizations:
        grants.extend(
            _authorization_grants(
                policy, authorization, authorities, bindings, requirements, approvals
            )
        )
    if not grants:
        return _finish("REVIEW", ["absence_is_not_permission"], reasons)
    decision = min((item["authorityDecision"] for item in grants), key=lambda item: SEVERITY[item])
    codes = []
    for item in grants:
        for code in item["codes"]:
            if code not in codes and code != "not_compiled":
                codes.append(code)
    if mode == "semantic-only" and decision == "AUTHORIZED" and "semantic_only" not in codes:
        codes.append("semantic_only")
    return _finish(decision, codes, reasons, grants=grants)


def _authorization_grants(policy, authorization, authorities, bindings, requirements, approvals):
    action_ids = list(authorization.get("actionIds") or [])
    if not action_ids:
        return [_grant("*", "REVIEW", ["absence_is_not_permission"])]
    shared_codes = []
    shared_decision = "AUTHORIZED"
    authority = authorities.get(authorization.get("authorityId"))
    if authority is None:
        shared_decision, shared_codes = _worse(shared_decision, shared_codes, "INCOMPLETE", ["missing_authority"])
    else:
        validity = _validity_problem(authority.get("validity", "valid"))
        if validity:
            shared_decision, shared_codes = _worse(shared_decision, shared_codes, validity[0], validity[1])
    validity = _validity_problem(authorization.get("validity", "valid"))
    if validity:
        shared_decision, shared_codes = _worse(shared_decision, shared_codes, validity[0], validity[1])
    mode = policy.get("mode")
    requirement_ids = list(authorization.get("requirementIds") or [])
    if mode == "operational" and not requirement_ids:
        shared_decision, shared_codes = _worse(shared_decision, shared_codes, "INCOMPLETE", [])
    referenced = []
    for requirement_id in requirement_ids:
        requirement = requirements.get(requirement_id)
        if requirement is None:
            shared_decision, shared_codes = _worse(shared_decision, shared_codes, "INCOMPLETE", [])
            continue
        referenced.append(requirement)
        problem = _requirement_problem(policy, requirement, bindings, approvals)
        if problem:
            shared_decision, shared_codes = _worse(shared_decision, shared_codes, problem[0], problem[1])
    if mode == "operational" and referenced and not any(item.get("effect") == "permit" or item.get("effect") == "require-approval" for item in referenced):
        shared_decision, shared_codes = _worse(
            shared_decision, shared_codes, "REVIEW", ["absence_is_not_permission"]
        )
    linked = list(authorization.get("conditions") or [])
    for requirement in referenced:
        found, missing = _conditions_for(policy, requirement)
        if missing:
            shared_decision, shared_codes = _worse(shared_decision, shared_codes, "INCOMPLETE", [])
        linked.extend(found)
    condition_problem = _conditions(policy, linked, None, approvals)
    if condition_problem:
        shared_decision, shared_codes = _worse(
            shared_decision, shared_codes, condition_problem[0], condition_problem[1]
        )
    grants = []
    for action_id in action_ids:
        decision, codes = shared_decision, list(shared_codes)
        if _prohibition_hits(policy, action_id, referenced, bindings):
            code = "prohibition_dominates" if decision == "AUTHORIZED" or requirement_ids else "explicit_prohibition"
            if any(item.get("effect") == "permit" or requirement_ids for item in referenced):
                code = "prohibition_dominates"
            decision, codes = _worse(decision, codes, "DENIED", [code])
        grants.append(_grant(action_id, decision, codes))
    return grants


def _requirement_problem(policy, requirement, bindings, approvals):
    if requirement.get("effect") == "require-approval" and not requirement.get("approverIds"):
        return ("INCOMPLETE", [])
    if "custom" in (
        requirement.get("effect"),
        *((requirement.get("bindingPattern") or {}).get("kinds") or []),
    ):
        return ("INCOMPLETE", [])
    binding_ids = list(requirement.get("bindingIds") or [])
    pattern = requirement.get("bindingPattern")
    if policy.get("mode") == "operational" and requirement.get("effect") in ("permit", "deny", "require-approval"):
        if not binding_ids and not pattern:
            return ("INCOMPLETE", ["missing_execution_binding"])
    for binding_id in binding_ids:
        binding = bindings.get(binding_id)
        if binding is None:
            return ("INCOMPLETE", ["missing_execution_binding"])
        if binding.get("kind") == "custom" or binding.get("operation") == "custom":
            return ("INCOMPLETE", [])
        for constraint in binding.get("constraints") or []:
            if constraint.get("type") == "custom" or constraint.get("type") not in (
                "locator-pattern",
                "operation",
                "protocol-parameter",
            ):
                return ("INCOMPLETE", [])
    if requirement.get("effect") == "require-approval" and not _approval_satisfies(requirement, approvals):
        return ("AUTHORIZED", ["approval_required"])
    return None


def _prohibition_hits(policy, action_id, requirements, bindings):
    for prohibition in policy.get("prohibitions") or []:
        named_actions = prohibition.get("actionIds") or []
        if named_actions:
            if action_id in named_actions:
                return True
            continue
        prohibited_bindings = set(prohibition.get("bindingIds") or [])
        if prohibited_bindings and _used_bindings(requirements, bindings, action_id) & prohibited_bindings:
            return True
        pattern = prohibition.get("bindingPattern") or {}
        except_ids = set(pattern.get("exceptBindingIds") or [])
        if pattern and any(
            _pattern_matches(pattern, binding) and binding.get("bindingId") not in except_ids
            for binding in used_objects(requirements, bindings, action_id)
        ):
            return True
    return False


def used_objects(requirements, bindings, action_id=None):
    found = []
    for requirement in requirements:
        for binding_id in requirement.get("bindingIds") or []:
            binding = bindings.get(binding_id)
            if binding is None:
                continue
            bound_action = binding.get("actionId")
            if action_id and bound_action and bound_action != action_id:
                continue
            found.append(binding)
    return found


def _used_bindings(requirements, bindings, action_id=None):
    return {binding.get("bindingId") for binding in used_objects(requirements, bindings, action_id)}


def _pattern_matches(pattern, binding):
    kinds = pattern.get("kinds") or []
    operations = pattern.get("operations") or []
    if not kinds and not operations:
        return True
    if kinds and binding.get("kind") not in kinds:
        return False
    if operations and binding.get("operation") not in operations:
        return False
    return True


def _approval_satisfies(requirement, approvals):
    approvers = set(requirement.get("approverIds") or [])
    for item in approvals:
        if not isinstance(item, dict) or item.get("exchangeType") != "Decision":
            continue
        decision = item.get("decision") or {}
        actor = item.get("actor") or {}
        actor_id = actor.get("id") if isinstance(actor, dict) else actor
        if (
            decision.get("kind") == "approval"
            and decision.get("value") == "approved"
            and decision.get("requirementId") == requirement.get("requirementId")
            and _state(decision.get("validity")) == "valid"
            and item.get("provenance")
            and actor_id in approvers
        ):
            return True
    return False


def _assess_exchange(exchange, policy, approvals):
    mode = exchange.get("mode")
    act = exchange.get("exchangeType")
    if exchange.get("status") != "ENFORCEMENT CANDIDATE":
        return _finish("INCOMPLETE", [], ["status"])
    if mode not in ("operational", "semantic-only"):
        return _finish("INCOMPLETE", [], ["mode"])
    if act not in REQUIRED_FIELDS:
        return _finish("INCOMPLETE", [], ["exchangeType"])
    codes = []
    reasons = []
    decision = "AUTHORIZED"
    blocked = _blocked_inputs(exchange, act)
    if blocked:
        return _finish(blocked[0], blocked[1], blocked[2])
    missing = [name for name in REQUIRED_FIELDS[act] if exchange.get(name) in (None, "", [], {})]
    if missing:
        return _finish("INCOMPLETE", [], ["missing_fields:" + ",".join(missing)])
    if act in ("Request", "Instruction", "Delegation", "Authorization", "Decision") and "validity" in exchange:
        validity = _validity_problem(exchange.get("validity"))
        if validity:
            return _finish(validity[0], validity[1], [])
    if act in ("Assertion", "Recommendation"):
        return _finish("DENIED", [], ["no_operational_effect"])
    if act == "Response":
        return _finish("REVIEW", ["absence_is_not_permission"], ["no_independent_execution_grant"])
    if act == "Decision":
        return _assess_decision(exchange)
    if act == "Delegation":
        delegation_result = _delegation(exchange, policy)
        if delegation_result["authorityDecision"] != "AUTHORIZED" or mode != "operational":
            return delegation_result
    if mode == "operational" and act in CONSEQUENTIAL:
        if not exchange.get("provenance"):
            return _finish("INCOMPLETE", [], ["provenance"])
        if not exchange.get("authority"):
            return _finish("INCOMPLETE", ["missing_authority"], [])
        if policy is None:
            return _finish("INCOMPLETE", [], ["companion_policy_not_inferred"])
        if policy.get("policyId") != exchange.get("policyId"):
            return _finish("INCOMPLETE", [], ["policy_mismatch"])
        return _exchange_against_policy(exchange, policy, approvals)
    normative = (exchange.get("normative") or {}).get("state")
    if normative == "prohibited":
        decision, codes = "DENIED", ["explicit_prohibition"]
    elif normative == "unknown":
        decision, codes = "REVIEW", ["absence_is_not_permission"]
    elif normative == "obligated":
        decision, codes = "REVIEW", ["obligation_is_not_authority"]
    elif normative != "allowed":
        decision, codes = "INCOMPLETE", []
    if mode == "semantic-only" and decision == "AUTHORIZED":
        codes = codes + ["semantic_only"]
    if act in CONSEQUENTIAL and not exchange.get("authority") and decision == "AUTHORIZED":
        decision, codes = "INCOMPLETE", ["missing_authority"]
    return _finish(decision, codes, reasons)


def _presented_identifier(value):
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        for key in ("id", "authorizationId", "resourceId", "actorId", "authorityId"):
            presented = value.get(key)
            if isinstance(presented, str) and presented:
                return presented
    return None


def _identity_mismatch(exchange, authorization):
    """Return a reason when the exchange names a different authorized object.

    Comparison is exact identifier equality. A field the exchange does not
    present is not rewritten from the authorization.
    """
    resource_id = _presented_identifier(exchange.get("resource"))
    if resource_id is not None and resource_id not in list(authorization.get("resourceIds") or []):
        return "resource_mismatch"
    actor_id = _presented_identifier(exchange.get("actor"))
    if actor_id is not None and authorization.get("actorId") and actor_id != authorization.get("actorId"):
        return "actor_mismatch"
    authority_id = _presented_identifier(exchange.get("authority"))
    if authority_id is not None and authorization.get("authorityId") and authority_id != authorization.get("authorityId"):
        return "authority_mismatch"
    authorization_id = _presented_identifier(exchange.get("authorization"))
    if authorization_id is not None and authorization_id != authorization.get("authorizationId"):
        return "authorization_mismatch"
    purpose = exchange.get("purpose")
    if authorization.get("purpose") and purpose and authorization.get("purpose") != purpose:
        return "purpose_mismatch"
    return None


def _scope_ids_problem(policy, authorization, exchange):
    scope_ids = list(authorization.get("scopeIds") or [])
    if not scope_ids:
        return None
    by_id = {item.get("scopeId"): item for item in policy.get("scopes") or []}
    for scope_id in scope_ids:
        wanted = by_id.get(scope_id)
        if wanted is None:
            return ("INCOMPLETE", [])
        presented = [
            item for item in (exchange.get("scope") or [])
            if isinstance(item, dict) and item.get("dimension") == wanted.get("dimension")
        ]
        if not presented:
            return ("INCOMPLETE", [])
        if not any(item.get("value") == wanted.get("value") for item in presented):
            return ("DENIED", [])
    return None


def _exchange_against_policy(exchange, policy, approvals):
    action = exchange.get("action")
    assessed = _assess_policy(policy, approvals)
    matched = [item for item in assessed.get("grants") or [] if item["actionId"] == action]
    if not matched:
        if policy.get("authorizations"):
            return _finish("DENIED", [], ["action_mismatch"])
        return _finish("REVIEW", ["absence_is_not_permission"], [])
    grant = matched[0]
    decision = grant["authorityDecision"]
    codes = [code for code in grant["codes"] if code != "not_compiled"]
    mismatch = None
    for authorization in policy.get("authorizations") or []:
        if action not in (authorization.get("actionIds") or []):
            continue
        identity = _identity_mismatch(exchange, authorization)
        if identity:
            mismatch = identity
            continue
        scope_problem = _scope_ids_problem(policy, authorization, exchange)
        if scope_problem:
            if scope_problem[0] == "DENIED":
                mismatch = "scope_mismatch"
                continue
            return _finish(scope_problem[0], scope_problem[1], [])
        problem = _conditions(policy, authorization.get("conditions") or [], exchange, approvals)
        if problem and problem[0] == "DENIED":
            return _finish("DENIED", problem[1], [])
        if problem and SEVERITY[problem[0]] < SEVERITY.get(decision, 3):
            decision = problem[0]
            codes = problem[1] + [code for code in codes if code not in problem[1]]
        if exchange.get("credential") and not exchange.get("authorization") and decision == "AUTHORIZED":
            return _finish("DENIED", ["credential_is_not_authorization"], [])
        validity = _validity_problem((exchange.get("authorization") or {}).get("validity", "valid"))
        if validity and validity[0] == "DENIED":
            return _finish(validity[0], validity[1], [])
        return _finish(decision, codes, [])
    if mismatch:
        return _finish("DENIED", [], [mismatch])
    return _finish("REVIEW", ["absence_is_not_permission"], [])


def _assess_decision(exchange):
    decision = exchange.get("decision") or {}
    if decision.get("kind") != "approval":
        return _finish("REVIEW", [], ["decision_is_not_an_execution_grant"])
    if "validity" in decision:
        validity = _validity_problem(decision.get("validity"))
        if validity:
            return _finish(validity[0], validity[1], [])
    if decision.get("value") != "approved" or _state(decision.get("validity")) != "valid" or not decision.get("requirementId"):
        return _finish("INCOMPLETE", ["approval_required"], [])
    return _finish("AUTHORIZED", [], [], extra={"approvalRecord": True})


def _delegation(exchange, policy):
    delegation = exchange.get("delegation") or {}
    if exchange.get("coordination") is True:
        return _finish("DENIED", ["coordination_is_not_enterprise_delegation"], [])
    if delegation.get("canDelegate") is False:
        return _finish("DENIED", ["delegation_requires_explicit_authority"], [])
    if delegation.get("canDelegate") is True:
        return _finish("AUTHORIZED", ["semantic_only"] if exchange.get("mode") == "semantic-only" else [], [])
    kind = (exchange.get("authority") or {}).get("kind")
    if policy and delegation.get("authorityId"):
        for authority in policy.get("authorities") or []:
            if authority.get("authorityId") == delegation.get("authorityId"):
                kind = authority.get("kind")
    if kind == "delegable":
        return _finish("AUTHORIZED", ["semantic_only"] if exchange.get("mode") == "semantic-only" else [], [])
    return _finish("DENIED", ["delegation_requires_explicit_authority"], [])


def _blocked_inputs(exchange, act):
    attempted = exchange.get("attemptedEffect")
    if attempted and (act, attempted) in FORBIDDEN_ESCALATIONS:
        return ("DENIED", ["silent_semantic_escalation"], [])
    extensions = exchange.get("extensions")
    if isinstance(extensions, dict) and any(key in PROTECTED_EXTENSIONS for key in extensions):
        return ("DENIED", ["extension_cannot_grant_authority"], [])
    if exchange.get("authoritySource") == "free_text":
        return ("DENIED", ["authority_source_free_text"], [])
    if exchange.get("untrustedFreeText") is True and not exchange.get("authority"):
        return ("DENIED", ["free_text_cannot_manufacture_authority"], [])
    if exchange.get("channel") == "agent-to-memory" and exchange.get("attemptedEffect") == "Authorization":
        return ("DENIED", ["memory_cannot_manufacture_authority"], [])
    if exchange.get("staleReplay") is True or exchange.get("tamperedAfterBinding") is True:
        return ("DENIED", [], ["caller_asserted_integrity_failure"])
    if exchange.get("credential") and not exchange.get("authorization") and act in CONSEQUENTIAL:
        return ("DENIED", ["credential_is_not_authorization"], [])
    return None


def _conditions_for(policy, requirement):
    by_id = {item.get("conditionId"): item for item in policy.get("conditions") or []}
    found = []
    for condition_id in requirement.get("conditionIds") or []:
        condition = by_id.get(condition_id)
        if condition is None:
            return found, True
        found.append(condition)
    return found, False


def _conditions(policy, conditions, exchange, approvals=None):
    for condition in conditions:
        kind = condition.get("type")
        if kind == "custom" or kind not in ("scope-match", "validity-window", "purpose-match", "approval-present"):
            return ("INCOMPLETE", [])
        if kind == "purpose-match":
            if exchange is None:
                continue
            if not exchange.get("purpose"):
                return ("INCOMPLETE", [])
            if exchange.get("purpose") != condition.get("purpose"):
                return ("DENIED", [])
        elif kind == "scope-match":
            if exchange is None:
                continue
            wanted = None
            for item in policy.get("scopes") or []:
                if item.get("scopeId") == condition.get("scopeId"):
                    wanted = item
            if wanted is None:
                return ("INCOMPLETE", [])
            presented = [
                item for item in (exchange.get("scope") or [])
                if isinstance(item, dict) and item.get("dimension") == wanted.get("dimension")
            ]
            if not presented:
                return ("INCOMPLETE", [])
            if not any(item.get("value") == wanted.get("value") for item in presented):
                return ("DENIED", [])
        elif kind == "validity-window":
            validity_id = condition.get("validityId")
            found = None
            for item in policy.get("validities") or []:
                if item.get("validityId") == validity_id:
                    found = item
            if found is None:
                return ("INCOMPLETE", [])
            problem = _validity_problem(found.get("state"))
            if problem:
                return problem
        elif kind == "approval-present":
            requirement_id = condition.get("requirementId")
            requirement = None
            for item in policy.get("enforcementRequirements") or []:
                if item.get("requirementId") == requirement_id:
                    requirement = item
            if requirement and _approval_satisfies(requirement, approvals or []):
                continue
            if requirement and requirement.get("effect") == "require-approval":
                return ("AUTHORIZED", ["approval_required"])
            return ("INCOMPLETE", ["approval_required"])
    return None


def _state(value):
    if isinstance(value, dict):
        return value.get("state")
    return value


def _validity_problem(value):
    if value is None:
        return ("INCOMPLETE", [])
    state = _state(value)
    if state == "valid":
        if isinstance(value, dict) and value.get("notBefore") and value.get("notAfter"):
            if str(value["notBefore"]) > str(value["notAfter"]):
                return ("INCOMPLETE", [])
        return None
    code = VALIDITY_CODES.get(state)
    if code:
        return ("DENIED", [code])
    return ("INCOMPLETE", [])


def _grant(action_id, decision, codes):
    ordered = []
    for code in codes:
        if code and code not in ordered:
            ordered.append(code)
    return {"actionId": action_id, "authorityDecision": decision, "codes": ordered}


def _worse(decision, codes, new_decision, new_codes):
    merged = list(codes)
    for code in new_codes:
        if code not in merged:
            merged.append(code)
    if SEVERITY[new_decision] < SEVERITY[decision]:
        return new_decision, merged
    return decision, merged


def _index(items, key):
    found = {}
    for item in items:
        identifier = item.get(key)
        if not identifier or identifier in found:
            return None
        found[identifier] = item
    return found
