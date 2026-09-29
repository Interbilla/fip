"""Target-neutral Enforcement IR projection.

This module copies an AUTHORIZED operational slice into FIP vocabulary.
It does not decide whether a product can enforce the slice, and it does not
emit a target policy. compilationDisposition stays NOT_COMPILED.
"""

from __future__ import annotations

import copy

from .authority import assess

FORBIDDEN_TARGET_KEYS = {
    "openshell",
    "landlock",
    "seccomp",
    "network_policies",
    "filesystem_policy",
    "kubernetes",
    "opa",
}

BINDING_FIELDS = (
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

LOCATOR_FIELDS = (
    "path",
    "host",
    "port",
    "uri",
    "serviceId",
    "executableId",
    "modelId",
    "deviceId",
    "channelId",
)

# Applicable operations and the locator fields that may satisfy the kind.
# custom is intentionally absent.
KIND_RULES = {
    "filesystem": {
        "operations": {"read", "write", "create", "modify", "delete"},
        "locator_any": ("path",),
    },
    "service": {
        "operations": {"connect"},
        "locator_any": ("host", "port", "serviceId"),
    },
    "api": {
        "operations": {"query", "invoke", "read", "write", "create", "modify", "delete"},
        "locator_any": ("uri", "host", "serviceId"),
    },
    "process": {
        "operations": {"execute", "create"},
        "locator_any": ("path", "executableId"),
    },
    "executable": {
        "operations": {"execute"},
        "locator_any": ("path", "executableId"),
    },
    "model": {
        "operations": {"invoke"},
        "locator_any": ("modelId",),
    },
    "inference-provider": {
        "operations": {"invoke", "connect"},
        "locator_any": ("serviceId", "host", "uri"),
    },
    "credential": {
        "operations": {"invoke", "read"},
        "locator_any": ("serviceId", "uri"),
    },
    "device": {
        "operations": {"command"},
        "locator_any": ("deviceId",),
    },
    "message-channel": {
        "operations": {"publish", "subscribe"},
        "locator_any": ("channelId",),
    },
    "datastore": {
        "operations": {"query", "modify"},
        "locator_any": ("uri", "host", "serviceId"),
    },
}

DISCLOSURES = {"none", "proxy-mediated", "process-visible"}
LIFETIMES = {"establishment-bound", "revocable", "validity-bound"}
AUDITS = {"none", "target-native", "correlated"}
EFFECTS = {"permit", "deny", "require-approval", "audit-only"}
COMPOSITIONS = {"allOf", "anyOf"}


def project(document, policy=None, approvals=None):
    """Project one document. operationalIr is present only for an AUTHORIZED operational slice."""
    authority = assess(document, policy=policy, approvals=approvals)
    result = {
        "authorityDecision": authority["authorityDecision"],
        "compilationDisposition": "NOT_COMPILED",
        "deployable": False,
        "codes": list(authority["codes"]),
        "reasons": list(authority.get("reasons") or []),
        "operationalIr": None,
        "semanticProjection": None,
    }
    if _has_target_field(document) or _has_target_field(policy):
        result["reasons"].append("author_supplied_target_field")
        return result
    if authority["authorityDecision"] != "AUTHORIZED":
        return result
    if "approval_required" in authority["codes"]:
        result["reasons"].append("approval_blocks_operational_projection")
        return result
    if document.get("mode") == "semantic-only" or (isinstance(policy, dict) and policy.get("mode") == "semantic-only"):
        result["semanticProjection"] = _semantic_projection(document, policy if isinstance(policy, dict) else document)
        return result
    source = policy if document.get("document") == "Exchange" else document
    if not isinstance(source, dict):
        result["reasons"].append("companion_policy_not_inferred")
        return result
    ir, failure = _operational_ir(document, source, authority, approvals or [])
    if failure:
        result["reasons"].append(failure)
        return result
    result["operationalIr"] = ir
    return result


def _semantic_projection(document, source):
    trace = _trace_id(source) or _trace_id(document)
    projection = {
        "fipVersion": "0.2",
        "projection": "semantic",
        "authorityDecision": "AUTHORIZED",
        "compilationDisposition": "NOT_COMPILED",
        "deployable": False,
        "operational": False,
        "executionBindings": [],
        "traceId": trace,
    }
    if source.get("policyId"):
        projection["policyId"] = source["policyId"]
    if document.get("document") == "Exchange":
        projection["exchangeId"] = document.get("exchangeId")
    elif source.get("document") == "Exchange":
        projection["exchangeId"] = source.get("exchangeId")
    return projection


def _operational_ir(document, policy, authority, approvals):
    if not policy.get("traceId") and not _trace_id(policy):
        return None, "missing_trace"
    bindings = _index(policy.get("executionBindings") or [], "bindingId")
    requirements = _index(policy.get("enforcementRequirements") or [], "requirementId")
    conditions = _index(policy.get("conditions") or [], "conditionId")
    constraints = _index(policy.get("constraints") or [], "constraintId")
    if bindings is None or requirements is None or conditions is None or constraints is None:
        return None, "duplicate_identifier"
    exchange_action = document.get("action") if document.get("document") == "Exchange" else None
    grant_source = assess(policy, approvals=approvals) if exchange_action else authority
    grants = {item["actionId"]: item for item in grant_source.get("grants") or []}
    selected, failure = _select_requirements(
        policy, requirements, bindings, grants, exchange_action
    )
    if failure:
        return None, failure
    nodes = []
    included = set()
    for requirement_id, authorization in selected:
        node, failure = _requirement_node(
            requirement_id, requirements, bindings, conditions, constraints, authorization, policy
        )
        if failure:
            return None, failure
        nodes.append(node)
        included.add(requirement_id)
    prohibition_nodes = []
    for prohibition in policy.get("prohibitions") or []:
        snapshot, failure = _prohibition_node(prohibition, requirements, bindings, conditions, constraints, policy, included, nodes)
        if failure:
            return None, failure
        prohibition_nodes.append(snapshot)
    if not nodes:
        return None, "empty_slice"
    group_failure = _same_composition(nodes)
    if group_failure:
        return None, group_failure
    trace = _trace_id(policy)
    for node in nodes:
        node["traceId"] = trace
    groups = _groups(nodes)
    binding_snapshots, failure = _binding_snapshots(nodes, bindings)
    if failure:
        return None, failure
    approval_records, failure = _approval_records(nodes, approvals)
    if failure:
        return None, failure
    permit_ids = sorted(node["requirementId"] for node in nodes if node["effect"] == "permit")
    ir = {
        "irVersion": "0",
        "fipVersion": "0.2",
        "policyId": policy.get("policyId"),
        "traceId": trace,
        "authorityDecision": "AUTHORIZED",
        "compilationDisposition": "NOT_COMPILED",
        "deployable": False,
        "codes": ["not_compiled"],
        "authorizationIds": sorted({node["authorizationId"] for node in nodes if node.get("authorizationId")}),
        "authorityIds": sorted({node["authorityId"] for node in nodes if node.get("authorityId")}),
        "requirements": sorted(nodes, key=lambda item: item["requirementId"]),
        "groups": groups,
        "prohibitions": sorted(prohibition_nodes, key=lambda item: item["prohibitionId"]),
        "bindings": binding_snapshots,
        "coverage": {
            "fipGrants": permit_ids,
            "targetEnforcement": [
                {"requirementId": node["requirementId"], "status": "unassessed"}
                for node in sorted(nodes, key=lambda item: item["requirementId"])
            ],
            "targetBaseline": [],
            "auditCoverage": "unassessed",
        },
    }
    if document.get("document") == "Exchange" and document.get("exchangeId"):
        ir["exchangeId"] = document["exchangeId"]
    if approval_records:
        ir["approvals"] = approval_records
    return ir, None


def _select_requirements(policy, requirements, bindings, grants, exchange_action):
    selected = []
    seen = set()
    for authorization in policy.get("authorizations") or []:
        actions = list(authorization.get("actionIds") or [])
        if exchange_action and exchange_action not in actions:
            continue
        if exchange_action and grants.get(exchange_action, {}).get("authorityDecision") != "AUTHORIZED":
            continue
        for requirement_id in authorization.get("requirementIds") or []:
            requirement = requirements.get(requirement_id)
            if requirement is None:
                return None, "dangling_requirement_reference"
            if not _requirement_in_slice(requirement, bindings, grants, actions, exchange_action):
                continue
            if requirement_id not in seen:
                selected.append((requirement_id, authorization))
                seen.add(requirement_id)
    expanded, failure = _expand_groups(selected, requirements, bindings, grants)
    if failure:
        return None, failure
    return expanded, None


def _requirement_in_slice(requirement, bindings, grants, actions, exchange_action):
    bound_actions = _bound_actions(requirement, bindings)
    relevant = bound_actions or set(actions)
    if exchange_action:
        if exchange_action not in relevant and bound_actions:
            return False
        return grants.get(exchange_action, {}).get("authorityDecision") == "AUTHORIZED"
    return all(grants.get(action, {}).get("authorityDecision") == "AUTHORIZED" for action in relevant)


def _expand_groups(selected, requirements, bindings, grants):
    by_group = {}
    for requirement_id, authorization in selected:
        requirement = requirements[requirement_id]
        group_id = requirement.get("groupId") or requirement_id
        by_group.setdefault(group_id, authorization)
    expanded = list(selected)
    seen = {requirement_id for requirement_id, _ in selected}
    for group_id, authorization in by_group.items():
        members = [
            item for item in requirements.values()
            if (item.get("groupId") or item.get("requirementId")) == group_id
        ]
        composition = None
        for member in members:
            member_composition = member.get("composition") or "allOf"
            if composition is None:
                composition = member_composition
            elif member_composition != composition:
                return None, "composition_conflict"
            if member.get("effect") == "deny":
                continue
            actions = _bound_actions(member, bindings)
            authorized = not actions or all(
                grants.get(action, {}).get("authorityDecision") == "AUTHORIZED" for action in actions
            )
            if composition == "allOf" and not authorized:
                return None, "all_of_group_not_wholly_authorized"
            if composition == "anyOf" and not authorized:
                continue
            requirement_id = member["requirementId"]
            if requirement_id not in seen:
                expanded.append((requirement_id, authorization))
                seen.add(requirement_id)
    return expanded, None


def _requirement_node(requirement_id, requirements, bindings, conditions, constraints, authorization, policy):
    requirement = requirements.get(requirement_id)
    if requirement is None:
        return None, "dangling_requirement_reference"
    effect = requirement.get("effect")
    if effect not in EFFECTS:
        return None, "unknown_effect"
    composition = requirement.get("composition") or "allOf"
    if composition not in COMPOSITIONS:
        return None, "unknown_composition"
    node = {
        "requirementId": requirement_id,
        "effect": effect,
        "bindingIds": list(requirement.get("bindingIds") or []),
        "constraints": [],
        "conditions": [],
        "composition": composition,
        "groupId": requirement.get("groupId") or requirement_id,
        "coverage": "unassessed",
        "auditCoverage": "unassessed",
        "traceId": _trace_id(policy),
    }
    if requirement.get("lifetime"):
        if requirement["lifetime"] not in LIFETIMES:
            return None, "unknown_lifetime"
        node["lifetime"] = requirement["lifetime"]
    if requirement.get("audit"):
        if requirement["audit"] not in AUDITS:
            return None, "unknown_audit"
        node["audit"] = requirement["audit"]
    if requirement.get("bindingPattern"):
        node["bindingPattern"] = copy.deepcopy(requirement["bindingPattern"])
    if authorization and effect != "deny":
        node["authorizationId"] = authorization.get("authorizationId")
        node["authorityId"] = authorization.get("authorityId")
    for condition_id in requirement.get("conditionIds") or []:
        condition = conditions.get(condition_id)
        if condition is None:
            return None, "dangling_condition_reference"
        if condition.get("type") == "custom":
            return None, "custom_condition"
        node["conditions"].append(copy.deepcopy(condition))
    for constraint_id in requirement.get("constraintIds") or []:
        constraint = constraints.get(constraint_id)
        if constraint is None:
            return None, "dangling_constraint_reference"
        if constraint.get("type") == "custom":
            return None, "custom_constraint"
        node["constraints"].append(copy.deepcopy(constraint))
    for binding_id in node["bindingIds"]:
        if binding_id not in bindings:
            return None, "dangling_binding_reference"
        failure = _validate_binding(bindings[binding_id])
        if failure:
            return None, failure
    return node, None


def _prohibition_node(prohibition, requirements, bindings, conditions, constraints, policy, included, nodes):
    snapshot = {
        "prohibitionId": prohibition.get("prohibitionId"),
        "traceId": _trace_id(policy),
    }
    for field in ("actionIds", "resourceIds", "bindingIds", "requirementIds"):
        if field in prohibition:
            snapshot[field] = list(prohibition[field])
    if prohibition.get("bindingPattern"):
        snapshot["bindingPattern"] = copy.deepcopy(prohibition["bindingPattern"])
    for binding_id in prohibition.get("bindingIds") or []:
        if binding_id not in bindings:
            return None, "dangling_binding_reference"
        failure = _validate_binding(bindings[binding_id])
        if failure:
            return None, failure
    for requirement_id in prohibition.get("requirementIds") or []:
        if requirement_id in included:
            continue
        node, failure = _requirement_node(
            requirement_id, requirements, bindings, conditions, constraints, None, policy
        )
        if failure:
            return None, failure
        node["prohibitionIds"] = [prohibition.get("prohibitionId")]
        nodes.append(node)
        included.add(requirement_id)
    return snapshot, None


def _binding_snapshots(nodes, bindings):
    wanted = []
    for node in nodes:
        wanted.extend(node.get("bindingIds") or [])
    snapshots = []
    for binding_id in sorted(set(wanted)):
        binding = bindings.get(binding_id)
        if binding is None:
            return None, "dangling_binding_reference"
        failure = _validate_binding(binding)
        if failure:
            return None, failure
        snapshots.append(_snapshot_binding(binding))
    return snapshots, None


def _snapshot_binding(binding):
    snapshot = {}
    for field in BINDING_FIELDS:
        if field not in binding:
            continue
        if field == "locator":
            locator = {}
            for key in LOCATOR_FIELDS:
                if key in binding["locator"]:
                    locator[key] = copy.deepcopy(binding["locator"][key])
            snapshot["locator"] = locator
        elif field == "protocol":
            snapshot["protocol"] = copy.deepcopy(binding["protocol"])
        else:
            snapshot[field] = copy.deepcopy(binding[field])
    return snapshot


def _validate_binding(binding):
    extra = set(binding) - set(BINDING_FIELDS)
    if extra:
        return "unexpected_binding_field"
    kind = binding.get("kind")
    operation = binding.get("operation")
    if kind == "custom" or operation == "custom":
        return "custom_binding_not_operational"
    rule = KIND_RULES.get(kind)
    if rule is None:
        return "unknown_binding_kind"
    if operation not in rule["operations"]:
        return "unknown_operation"
    if binding.get("lifetime") not in LIFETIMES:
        return "unknown_lifetime"
    locator = binding.get("locator")
    if not isinstance(locator, dict) or not locator:
        return "missing_locator"
    extra_locator = set(locator) - set(LOCATOR_FIELDS)
    if extra_locator:
        return "unexpected_locator_field"
    if not any(field in locator and locator[field] not in ("", None) for field in rule["locator_any"]):
        return "missing_locator"
    if "port" in locator and (type(locator["port"]) is not int or not 1 <= locator["port"] <= 65535):
        return "invalid_port"
    if kind == "credential":
        if binding.get("disclosure") not in DISCLOSURES:
            return "missing_disclosure"
    elif "disclosure" in binding:
        return "unexpected_binding_field"
    protocol = binding.get("protocol")
    if protocol:
        if protocol.get("family") == "custom" or protocol.get("family") not in (
            "http", "mcp", "graphql", "websocket", "json-rpc"
        ):
            return "unknown_protocol"
    return None


def _approval_records(nodes, approvals):
    records = []
    for node in nodes:
        if node["effect"] != "require-approval":
            continue
        match = _matching_approval(node["requirementId"], approvals)
        if match is None:
            return None, "approval_record_missing"
        decision = match.get("decision") or {}
        actor = match.get("actor") or {}
        record = {
            "satisfied": True,
            "requirementId": node["requirementId"],
            "exchangeId": match.get("exchangeId"),
            "provenance": copy.deepcopy(match.get("provenance")),
            "effect": "require-approval",
        }
        if decision.get("decisionId"):
            record["decisionId"] = decision["decisionId"]
        actor_id = actor.get("id") if isinstance(actor, dict) else actor
        if actor_id:
            record["actorId"] = actor_id
        records.append(record)
    return records, None


def _matching_approval(requirement_id, approvals):
    for item in approvals:
        decision = item.get("decision") or {}
        validity = decision.get("validity")
        state = validity.get("state") if isinstance(validity, dict) else validity
        if (
            item.get("exchangeType") == "Decision"
            and decision.get("kind") == "approval"
            and decision.get("value") == "approved"
            and decision.get("requirementId") == requirement_id
            and state == "valid"
            and item.get("provenance")
        ):
            return item
    return None


def _groups(nodes):
    grouped = {}
    for node in nodes:
        bucket = grouped.setdefault(node["groupId"], {"composition": node["composition"], "requirementIds": []})
        if node["requirementId"] not in bucket["requirementIds"]:
            bucket["requirementIds"].append(node["requirementId"])
    groups = []
    for group_id in sorted(grouped):
        groups.append({
            "groupId": group_id,
            "composition": grouped[group_id]["composition"],
            "requirementIds": sorted(grouped[group_id]["requirementIds"]),
        })
    return groups


def _same_composition(nodes):
    seen = {}
    for node in nodes:
        prior = seen.get(node["groupId"])
        if prior is None:
            seen[node["groupId"]] = node["composition"]
        elif prior != node["composition"]:
            return "composition_conflict"
    return None


def _bound_actions(requirement, bindings):
    actions = set()
    for binding_id in requirement.get("bindingIds") or []:
        binding = bindings.get(binding_id)
        if binding and binding.get("actionId"):
            actions.add(binding["actionId"])
    return actions


def _trace_id(document):
    if not isinstance(document, dict):
        return None
    if document.get("traceId"):
        return document["traceId"]
    provenance = document.get("provenance") or {}
    return provenance.get("traceId")


def _index(items, key):
    found = {}
    for item in items:
        if not isinstance(item, dict):
            return None
        identifier = item.get(key)
        if not identifier or identifier in found:
            return None
        found[identifier] = item
    return found


def _has_target_field(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_TARGET_KEYS or _has_target_field(item):
                return True
    elif isinstance(value, list):
        return any(_has_target_field(item) for item in value)
    return False
