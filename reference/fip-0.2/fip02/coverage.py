"""Capability and coverage evaluation.

Given an M2A Enforcement IR and a target-neutral Capability Manifest, decide
whether that target can represent the authorized surface without widening it.
This module does not emit a target policy. deployable true means the IR is
eligible for a later compilation. It does not mean a policy exists, and it
does not mean runtime execution is allowed.
"""

from __future__ import annotations

import copy

FORBIDDEN_TARGET_KEYS = {
    "openshell",
    "landlock",
    "seccomp",
    "network_policies",
    "filesystem_policy",
    "kubernetes",
    "opa",
}

HOST_WIDENING_DEFAULTS = {"canconnectanyhost", "cannotrestricthost"}
WRITE_OPERATIONS = {"write", "create", "modify", "delete"}
REQUIRED_MANIFEST = (
    "manifestVersion",
    "adapterId",
    "targetType",
    "targetVersion",
    "adapterVersion",
    "acceptsFipVersions",
    "kinds",
    "operations",
    "locatorForms",
    "protocolFamilies",
    "protocolConstraints",
    "capabilities",
    "effects",
    "auditStrengths",
    "compositions",
    "approval",
    "precision",
    "substrate",
    "dangerousDefaults",
)
REQUIRED_PRECISION = (
    "filesystemOperations",
    "networkHost",
    "httpMethod",
    "httpPath",
    "modelId",
    "credentialDisclosures",
    "traceCorrelation",
)
LIFETIMES = {"establishment-bound", "revocable", "validity-bound"}
EXECUTION_CLASSES = {"restrictive", "read-only-runtime", "writable-runtime"}
SUBSTRATE_CLASSES = EXECUTION_CLASSES | {"operational-authority"}
CREDENTIAL_DIMENSIONS = {"provider", "host", "port", "path", "protocol"}


def assess_coverage(ir, manifest, profile=None):
    """Return a coverage assessment. The IR, manifest, and profile are not modified."""
    if not _operational_ir(ir):
        return _unassessed(ir, manifest, "not_an_operational_ir")
    failure = _manifest_failure(manifest)
    if failure:
        return _unassessed(ir, manifest, failure)
    ir = copy.deepcopy(ir)
    manifest = copy.deepcopy(manifest)
    profile = copy.deepcopy(profile) if isinstance(profile, dict) else None
    binding_index = {item["bindingId"]: item for item in ir.get("bindings") or []}
    requirement_rows = []
    binding_rows = {}
    audit_rows = []
    for requirement in ir.get("requirements") or []:
        status, codes, binding_notes, audit_row = _requirement(requirement, ir, manifest, binding_index)
        requirement_rows.append({
            "requirementId": requirement["requirementId"],
            "effect": requirement["effect"],
            "status": status,
            "codes": codes,
        })
        if audit_row:
            audit_rows.append(audit_row)
        for binding_id, note in binding_notes.items():
            prior = binding_rows.get(binding_id)
            if prior is None or _worse(note[0], prior["status"]):
                binding_rows[binding_id] = {
                    "bindingId": binding_id,
                    "status": note[0],
                    "codes": note[1],
                }
    by_id = {row["requirementId"]: row for row in requirement_rows}
    groups = [_group(group, by_id) for group in ir.get("groups") or []]
    prohibitions = _prohibitions(ir, by_id)
    baseline, baseline_exceeds = _baseline(ir, manifest, profile)
    disposition, codes = _disposition(requirement_rows, groups, prohibitions, baseline_exceeds)
    selected = _selected(groups, by_id)
    assessment = {
        "assessmentVersion": "0",
        "fipVersion": "0.2",
        "traceId": ir.get("traceId"),
        "authorityDecision": ir.get("authorityDecision"),
        "compilationDisposition": disposition,
        "deployable": disposition == "FULL",
        "manifestId": manifest.get("adapterId"),
        "targetType": manifest.get("targetType"),
        "targetVersion": manifest.get("targetVersion"),
        "adapterVersion": manifest.get("adapterVersion"),
        "codes": codes,
        "requirements": requirement_rows,
        "bindings": [binding_rows[key] for key in sorted(binding_rows)],
        "groups": groups,
        "prohibitions": prohibitions,
        "audit": audit_rows,
        "coverage": {
            "fipGrants": list((ir.get("coverage") or {}).get("fipGrants") or []),
            "targetEnforcement": [
                {"requirementId": row["requirementId"], "status": row["status"]}
                for row in requirement_rows
            ],
            "targetBaseline": baseline,
        },
        "selectedRequirementIds": selected,
        "diagnostics": _diagnostics(disposition, codes, baseline_exceeds),
    }
    if ir.get("policyId"):
        assessment["policyId"] = ir["policyId"]
    if ir.get("exchangeId"):
        assessment["exchangeId"] = ir["exchangeId"]
    return assessment


def _operational_ir(ir):
    return (
        isinstance(ir, dict)
        and ir.get("irVersion") == "0"
        and ir.get("fipVersion") == "0.2"
        and ir.get("authorityDecision") == "AUTHORIZED"
        and ir.get("projection") != "semantic"
        and ir.get("operational") is not False
        and isinstance(ir.get("requirements"), list)
        and isinstance(ir.get("bindings"), list)
    )


def _unassessed(ir, manifest, reason):
    source = ir if isinstance(ir, dict) else {}
    manifest = manifest if isinstance(manifest, dict) else {}
    result = {
        "assessmentVersion": "0",
        "fipVersion": "0.2",
        "traceId": source.get("traceId"),
        "authorityDecision": source.get("authorityDecision") or "INCOMPLETE",
        "compilationDisposition": "NOT_COMPILED",
        "deployable": False,
        "manifestId": manifest.get("adapterId") or "unknown-manifest",
        "codes": ["not_compiled"],
        "requirements": [],
        "bindings": [],
        "groups": [],
        "prohibitions": [],
        "audit": [],
        "coverage": {"fipGrants": [], "targetEnforcement": [], "targetBaseline": []},
        "selectedRequirementIds": [],
        "diagnostics": [reason],
    }
    if source.get("policyId"):
        result["policyId"] = source["policyId"]
    return result


def _manifest_failure(manifest):
    if not isinstance(manifest, dict) or _has_target_field(manifest):
        return "malformed_manifest"
    if any(name not in manifest for name in REQUIRED_MANIFEST):
        return "malformed_manifest"
    if manifest.get("manifestVersion") != "0":
        return "malformed_manifest"
    versions = manifest.get("acceptsFipVersions")
    if not isinstance(versions, list) or "0.2" not in versions:
        return "malformed_manifest"
    precision = manifest.get("precision")
    approval = manifest.get("approval")
    if not isinstance(precision, dict) or any(name not in precision for name in REQUIRED_PRECISION):
        return "malformed_manifest"
    if not isinstance(approval, dict) or not isinstance(approval.get("actionGate"), bool):
        return "malformed_manifest"
    if precision.get("filesystemOperations") not in ("exact", "bundle"):
        return "malformed_manifest"
    if precision.get("networkHost") not in ("exact", "unrestricted"):
        return "malformed_manifest"
    binding = precision.get("credentialBinding")
    if binding is not None:
        if not isinstance(binding, dict):
            return "malformed_manifest"
        dimensions = binding.get("dimensions")
        required = binding.get("required")
        if not isinstance(dimensions, list) or not isinstance(required, list):
            return "malformed_manifest"
        if any(item not in CREDENTIAL_DIMENSIONS for item in dimensions + required):
            return "malformed_manifest"
        if any(item not in dimensions for item in required):
            return "malformed_manifest"
    if "lifetimes" in manifest:
        return "malformed_manifest"
    if _capability_failure(manifest.get("capabilities")):
        return "malformed_manifest"
    for entry in manifest.get("substrate") or []:
        if not isinstance(entry, dict) or entry.get("authorityBearing") is not False:
            return "malformed_manifest"
        if "substrateClass" in entry and entry.get("substrateClass") not in SUBSTRATE_CLASSES:
            return "malformed_manifest"
    return None


def _capability_failure(capabilities):
    if not isinstance(capabilities, list) or not capabilities:
        return True
    seen = set()
    for capability in capabilities:
        if not isinstance(capability, dict):
            return True
        kinds = capability.get("kinds")
        lifetimes = capability.get("lifetimes")
        if not capability.get("capabilityId") or not isinstance(kinds, list) or not kinds:
            return True
        if not isinstance(lifetimes, list) or not lifetimes:
            return True
        if any(item not in LIFETIMES for item in lifetimes):
            return True
        for kind in kinds:
            if kind in seen:
                return True
            seen.add(kind)
    return False


def _requirement(requirement, ir, manifest, binding_index):
    codes = []
    binding_notes = {}
    effect = requirement.get("effect")
    if requirement.get("composition") not in (manifest.get("compositions") or []):
        return "unenforced", ["unsupported_requirement"], binding_notes, _audit_row(requirement, "unenforced")
    if effect == "require-approval":
        approval = manifest.get("approval") or {}
        if approval.get("policyMutation") is True:
            return "rejected", ["subset_not_demonstrated"], binding_notes, _audit_row(requirement, "rejected")
        if approval.get("actionGate") is not True:
            return "unenforced", ["unsupported_requirement"], binding_notes, _audit_row(requirement, "unenforced")
    if effect not in (manifest.get("effects") or []):
        if effect in ("permit", "deny", "require-approval") and (manifest.get("effects") or []) == ["audit-only"]:
            return "rejected", ["subset_not_demonstrated"], binding_notes, _audit_row(requirement, "rejected")
        return "unenforced", ["unsupported_requirement"], binding_notes, _audit_row(requirement, "unenforced")
    lifetime = requirement.get("lifetime")
    if lifetime and not _lifetime_matches(lifetime, _requirement_kinds(requirement, binding_index), manifest):
        return "rejected", ["lifetime_mismatch"], binding_notes, _audit_row(requirement, "rejected")
    for binding_id in requirement.get("bindingIds") or []:
        binding = binding_index.get(binding_id)
        if binding is None:
            return "unenforced", ["unsupported_requirement"], binding_notes, _audit_row(requirement, "unenforced")
        status, binding_codes = _binding(binding, requirement, manifest)
        binding_notes[binding_id] = (status, binding_codes)
        if status != "enforced":
            return status, binding_codes, binding_notes, _audit_row(requirement, status)
    pattern = requirement.get("bindingPattern")
    if pattern:
        status, pattern_codes = _pattern(pattern, manifest)
        if status != "enforced":
            return status, pattern_codes, binding_notes, _audit_row(requirement, status)
    elif effect in ("permit", "deny", "require-approval") and not requirement.get("bindingIds"):
        return "unenforced", ["unsupported_requirement"], binding_notes, _audit_row(requirement, "unenforced")
    audit_status = _audit_status(requirement, manifest)
    if audit_status != "enforced":
        return audit_status, ["unsupported_requirement"], binding_notes, _audit_row(requirement, audit_status)
    return "enforced", codes, binding_notes, _audit_row(requirement, "enforced")


def _binding(binding, requirement, manifest):
    kind = binding.get("kind")
    operation = binding.get("operation")
    precision = manifest["precision"]
    kinds = manifest.get("kinds") or []
    credential_declared = False
    if kind == "credential":
        decision = _credential_boundary(binding, manifest)
        if decision is not None and decision[0] != "continue":
            return decision
        credential_declared = (
            decision is not None and bool((precision.get("credentialBinding") or {}))
        )
    if kind not in kinds and not credential_declared:
        if kind == "model" and "inference-provider" in kinds:
            return "rejected", ["subset_not_demonstrated"]
        return "unenforced", ["unsupported_requirement"]
    if operation not in (manifest.get("operations") or []):
        return "unenforced", ["unsupported_requirement"]
    locator = binding.get("locator") or {}
    if kind == "filesystem":
        offered = set(manifest.get("operations") or []) & {"read", "write", "create", "modify", "delete"}
        if precision.get("filesystemOperations") == "bundle" and offered - {operation}:
            return "rejected", ["subset_not_demonstrated"]
    host_limited = (
        precision.get("networkHost") == "unrestricted"
        or bool(HOST_WIDENING_DEFAULTS & {item.lower() for item in manifest.get("dangerousDefaults") or []})
    )
    if locator.get("host") and host_limited:
        return "rejected", ["subset_not_demonstrated"]
    exactness = _network_exactness(binding, manifest)
    if exactness is not None:
        return exactness
    if _needs_http(binding, requirement) and not (precision.get("httpMethod") and precision.get("httpPath")):
        return "rejected", ["subset_not_demonstrated"]
    if kind == "model" and locator.get("modelId") and not precision.get("modelId"):
        return "rejected", ["subset_not_demonstrated"]
    for field in locator:
        if field not in (manifest.get("locatorForms") or []):
            return "unenforced", ["unsupported_requirement"]
    family = (binding.get("protocol") or {}).get("family")
    if family and family not in (manifest.get("protocolFamilies") or []):
        return "unenforced", ["unsupported_requirement"]
    return "enforced", []


def _credential_boundary(binding, manifest):
    """Return a rejection, continue, or None when no credential mechanism is declared."""
    precision = manifest.get("precision") or {}
    disclosures = precision.get("credentialDisclosures") or []
    binding_precision = precision.get("credentialBinding")
    kind_listed = "credential" in (manifest.get("kinds") or [])
    if not binding_precision and not kind_listed:
        return None
    if binding.get("disclosure") not in disclosures:
        return "rejected", ["subset_not_demonstrated"]
    if not binding_precision:
        return "continue", []
    dimensions = set(binding_precision.get("dimensions") or [])
    required = binding_precision.get("required") or []
    present = _credential_dimensions(binding)
    if any(item not in present for item in required) or any(item not in dimensions for item in present):
        return "rejected", ["subset_not_demonstrated"]
    return "continue", []


def _credential_dimensions(binding):
    locator = binding.get("locator") or {}
    present = set()
    if locator.get("serviceId"):
        present.add("provider")
    if locator.get("host"):
        present.add("host")
    if locator.get("port") is not None:
        present.add("port")
    http = ((binding.get("protocol") or {}).get("http") or {})
    if locator.get("path") or http.get("path"):
        present.add("path")
    if (binding.get("protocol") or {}).get("family"):
        present.add("protocol")
    return present


def _requirement_kinds(requirement, binding_index):
    kinds = []
    for binding_id in requirement.get("bindingIds") or []:
        binding = binding_index.get(binding_id)
        if binding and binding.get("kind") and binding["kind"] not in kinds:
            kinds.append(binding["kind"])
    for kind in (requirement.get("bindingPattern") or {}).get("kinds") or []:
        if kind not in kinds:
            kinds.append(kind)
    return kinds


def _lifetime_matches(lifetime, kinds, manifest):
    if not kinds:
        return False
    index = {}
    for capability in manifest.get("capabilities") or []:
        for kind in capability.get("kinds") or []:
            index.setdefault(kind, set()).update(capability.get("lifetimes") or [])
    return all(lifetime in index.get(kind, ()) for kind in kinds)


def _network_exactness(binding, manifest):
    """Reject a locator the pinned target would have to widen to express."""
    if manifest.get("precision", {}).get("networkHost") != "exact":
        return None
    kind = binding.get("kind")
    locator = binding.get("locator") or {}
    if kind == "executable":
        # OpenShell v0.1.2 applies a binary rule to processes that binary starts.
        # That is wider than the FIP executable identity, so the subset is not shown.
        if manifest.get("adapterId") == "openshell-v0.1.2":
            return "rejected", ["subset_not_demonstrated"]
        path = locator.get("path")
        if isinstance(path, str) and _glob_widens(path):
            return "rejected", ["subset_not_demonstrated"]
        return None
    if kind not in ("service", "api", "inference-provider"):
        return None
    if isinstance(locator.get("uri"), str) and "?" in locator["uri"]:
        return "rejected", ["subset_not_demonstrated"]
    host = locator.get("host")
    if isinstance(host, str) and _glob_widens(host):
        return "rejected", ["subset_not_demonstrated"]
    if host and locator.get("port") is None:
        return "rejected", ["subset_not_demonstrated"]
    http = ((binding.get("protocol") or {}).get("http") or {})
    method = http.get("method")
    path = http.get("path")
    if isinstance(method, str) and (method == "*" or _glob_widens(method)):
        return "rejected", ["subset_not_demonstrated"]
    if isinstance(path, str) and _glob_widens(path):
        return "rejected", ["subset_not_demonstrated"]
    if isinstance(locator.get("uri"), str) and isinstance(host, str) and locator.get("port") is not None:
        if _uri_disagrees(locator["uri"], host, locator["port"], path if isinstance(path, str) else None):
            return "rejected", ["subset_not_demonstrated"]
    return None


def _glob_widens(value):
    return any(char in value for char in "*?[]")


def _uri_disagrees(uri, host, port, http_path):
    if "://" not in uri:
        return True
    scheme, rest = uri.split("://", 1)
    authority, separator, tail = rest.partition("/")
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    uri_port = None
    if authority.startswith("["):
        return True
    if ":" in authority:
        uri_host, raw_port = authority.rsplit(":", 1)
        if not raw_port.isdigit():
            return True
        uri_port = int(raw_port)
    else:
        uri_host = authority
        implied = {"https": 443, "http": 80}.get(scheme.lower())
        if implied is not None:
            uri_port = implied
    if uri_host != host or uri_port != port:
        return True
    if http_path and separator:
        observed = "/" + tail.split("?", 1)[0].split("#", 1)[0]
        if observed != http_path:
            return True
    return False


def _needs_http(binding, requirement):
    http = ((binding.get("protocol") or {}).get("http") or {})
    if http.get("method") or http.get("path"):
        return True
    return any(item.get("method") or item.get("path") for item in requirement.get("constraints") or [])


def _pattern(pattern, manifest):
    precision = manifest["precision"]
    host_limited = (
        precision.get("networkHost") == "unrestricted"
        or bool(HOST_WIDENING_DEFAULTS & {item.lower() for item in manifest.get("dangerousDefaults") or []})
    )
    kinds = pattern.get("kinds") or []
    if any(kind not in (manifest.get("kinds") or []) for kind in kinds):
        return "unenforced", ["unsupported_requirement"]
    if host_limited and any(kind in ("service", "api", "inference-provider") for kind in kinds):
        return "rejected", ["subset_not_demonstrated"]
    if "deny" not in (manifest.get("effects") or []):
        return "unenforced", ["unsupported_requirement"]
    return "enforced", []


def _audit_status(requirement, manifest):
    required = requirement.get("audit") or "none"
    if required == "none":
        return "enforced"
    strengths = set(manifest.get("auditStrengths") or [])
    if required == "correlated":
        if "correlated" in strengths and manifest["precision"].get("traceCorrelation") is True:
            return "enforced"
        return "unenforced"
    if required == "target-native":
        if "target-native" in strengths:
            return "enforced"
        return "unenforced"
    return "unenforced"


def _audit_row(requirement, status):
    if not requirement.get("audit"):
        return None
    return {
        "requirementId": requirement["requirementId"],
        "required": requirement["audit"],
        "status": status,
    }


def _group(group, by_id):
    members = [by_id[item] for item in group.get("requirementIds") or [] if item in by_id]
    composition = group.get("composition")
    if composition == "anyOf":
        if any(item["status"] == "enforced" for item in members):
            status = "enforced"
        elif any(item["status"] == "rejected" for item in members):
            status = "rejected"
        else:
            status = "unenforced"
    else:
        if any(item["status"] == "rejected" for item in members):
            status = "rejected"
        elif any(item["status"] != "enforced" for item in members):
            status = "unenforced"
        else:
            status = "enforced"
    return {
        "groupId": group.get("groupId"),
        "composition": composition,
        "status": status,
        "requirementIds": list(group.get("requirementIds") or []),
    }


def _prohibitions(ir, by_id):
    rows = []
    for prohibition in ir.get("prohibitions") or []:
        member_ids = prohibition.get("requirementIds") or []
        members = [by_id[item] for item in member_ids if item in by_id]
        if any(item["status"] == "rejected" for item in members):
            status, codes = "rejected", ["subset_not_demonstrated"]
        elif not members or any(item["status"] != "enforced" for item in members):
            status, codes = "unenforced", ["unsupported_requirement"]
        else:
            status, codes = "enforced", []
        rows.append({"prohibitionId": prohibition.get("prohibitionId"), "status": status, "codes": codes})
    return rows


def _baseline(ir, manifest, profile):
    grants = _grant_surface(ir)
    rows = []
    exceeds = False
    declared_by = manifest.get("adapterId") or "unknown-manifest"
    for entry in manifest.get("substrate") or []:
        accepted = _substrate_accepted(entry, ir, profile)
        row = _baseline_row(entry, accepted, declared_by)
        rows.append(row)
        if not accepted and _baseline_exceeds(entry, grants):
            exceeds = True
    for flag in manifest.get("dangerousDefaults") or []:
        if flag.lower() in HOST_WIDENING_DEFAULTS:
            rows.append(_baseline_row({
                "description": flag,
                "substrateClass": "operational-authority",
                "kind": "service",
                "operation": "connect",
            }, False, declared_by))
            if not _grants_unrestricted_network(grants):
                exceeds = True
        else:
            rows.append(_baseline_row({
                "description": flag,
                "substrateClass": "operational-authority",
            }, False, declared_by))
            exceeds = True
    return rows, exceeds


def _baseline_row(entry, accepted, declared_by):
    row = {
        "description": entry.get("description"),
        "substrateClass": _entry_class(entry),
        "acceptance": "accepted" if accepted else "unaccepted",
        "declaredBy": declared_by,
        "authorityBearing": False,
        "status": "baseline",
    }
    if entry.get("substrateId"):
        row["substrateId"] = entry["substrateId"]
    if entry.get("kind"):
        row["kind"] = entry["kind"]
    if entry.get("operation"):
        row["operation"] = entry["operation"]
    if entry.get("locator"):
        row["locator"] = copy.deepcopy(entry["locator"])
    return row


def _grant_surface(ir):
    grants = []
    permitted = {
        item["requirementId"]
        for item in ir.get("requirements") or []
        if item.get("effect") == "permit"
    }
    bindings = {item["bindingId"]: item for item in ir.get("bindings") or []}
    for requirement in ir.get("requirements") or []:
        if requirement["requirementId"] not in permitted:
            continue
        for binding_id in requirement.get("bindingIds") or []:
            binding = bindings.get(binding_id)
            if binding:
                grants.append(binding)
    return grants


def _entry_class(entry):
    value = entry.get("substrateClass")
    if value in SUBSTRATE_CLASSES:
        return value
    return "operational-authority"


def _misclassified(entry):
    substrate_class = _entry_class(entry)
    if "substrateClass" not in entry:
        return False
    operation = entry.get("operation")
    kind = entry.get("kind")
    if substrate_class == "restrictive":
        return operation in WRITE_OPERATIONS or kind in ("service", "api", "inference-provider")
    if substrate_class == "read-only-runtime":
        return operation in WRITE_OPERATIONS or kind in ("service", "api", "inference-provider")
    if substrate_class == "writable-runtime":
        return kind != "filesystem" or operation not in WRITE_OPERATIONS or not (entry.get("locator") or {}).get("path")
    return False


def _substrate_accepted(entry, ir, profile):
    if _entry_class(entry) not in EXECUTION_CLASSES or _misclassified(entry):
        return False
    if _conflicts_with_prohibition(entry, ir):
        return False
    return _profile_permits(entry, profile)


def _profile_permits(entry, profile):
    if not isinstance(profile, dict):
        return False
    for rule in profile.get("acceptedExecutionSubstrate") or []:
        if not isinstance(rule, dict) or rule.get("substrateClass") != _entry_class(entry):
            continue
        if rule.get("substrateId") and rule.get("substrateId") != entry.get("substrateId"):
            continue
        if rule.get("kind") and rule.get("kind") != entry.get("kind"):
            continue
        if rule.get("operation") and rule.get("operation") != entry.get("operation"):
            continue
        locator = rule.get("locator")
        if locator and locator != entry.get("locator"):
            continue
        return True
    return False


def _conflicts_with_prohibition(entry, ir):
    bindings = {item["bindingId"]: item for item in ir.get("bindings") or []}
    statements = list(ir.get("prohibitions") or [])
    statements.extend(item for item in ir.get("requirements") or [] if item.get("effect") == "deny")
    return any(_statement_covers(statement, entry, bindings) for statement in statements)


def _statement_covers(statement, entry, bindings):
    for binding_id in statement.get("bindingIds") or []:
        binding = bindings.get(binding_id)
        if binding and _same_surface(entry, binding):
            return True
    pattern = statement.get("bindingPattern")
    if not pattern:
        return False
    kinds = pattern.get("kinds") or []
    return bool(entry.get("kind")) and entry.get("kind") in kinds


def _same_surface(entry, binding):
    if entry.get("kind") and binding.get("kind") and entry["kind"] != binding["kind"]:
        return False
    entry_locator = entry.get("locator") or {}
    binding_locator = binding.get("locator") or {}
    if entry_locator.get("path") and binding_locator.get("path") and entry_locator["path"] != binding_locator["path"]:
        return False
    if entry_locator.get("host") and binding_locator.get("host") and entry_locator["host"] != binding_locator["host"]:
        return False
    entry_operation = entry.get("operation")
    binding_operation = binding.get("operation")
    if entry_operation and binding_operation and entry_operation != binding_operation:
        return entry_operation in WRITE_OPERATIONS and binding_operation in WRITE_OPERATIONS
    return True


def _baseline_exceeds(entry, grants):
    operation = entry.get("operation")
    kind = entry.get("kind")
    path = (entry.get("locator") or {}).get("path")
    if kind == "filesystem" and operation in WRITE_OPERATIONS:
        return not any(
            item.get("kind") == "filesystem"
            and item.get("operation") == operation
            and (item.get("locator") or {}).get("path") == path
            for item in grants
        )
    if kind in ("service", "api", "inference-provider"):
        host = (entry.get("locator") or {}).get("host")
        if not host:
            return True
        return not any(_network_grant_covers(item, entry) for item in grants)
    return False


def _network_grant_covers(grant, entry):
    if grant.get("kind") not in ("service", "api", "inference-provider"):
        return False
    grant_locator = grant.get("locator") or {}
    entry_locator = entry.get("locator") or {}
    if grant_locator.get("host") != entry_locator.get("host"):
        return False
    if entry_locator.get("port") is not None and grant_locator.get("port") != entry_locator.get("port"):
        return False
    return True


def _grants_unrestricted_network(grants):
    return False


def _disposition(requirements, groups, prohibitions, baseline_exceeds):
    codes = []
    if any(item["status"] != "enforced" for item in prohibitions):
        codes.append("subset_not_demonstrated")
    if baseline_exceeds:
        codes.append("baseline_exceeds_grant")
    for requirement in requirements:
        if not _group_requires(requirement, groups):
            continue
        for code in requirement["codes"]:
            if code not in codes:
                codes.append(code)
    unenforced_required = any(item["status"] == "unenforced" for item in groups)
    any_enforced = any(item["status"] == "enforced" for item in requirements)
    if unenforced_required and "unsupported_requirement" not in codes and "subset_not_demonstrated" not in codes:
        codes.append("unsupported_requirement")
    ordered = []
    for code in codes:
        if code not in ordered:
            ordered.append(code)
    if "subset_not_demonstrated" in ordered or "baseline_exceeds_grant" in ordered or "lifetime_mismatch" in ordered:
        return "REJECTED", ordered
    if unenforced_required:
        if any_enforced:
            return "PARTIAL", ordered or ["unsupported_requirement"]
        return "REJECTED", ordered or ["unsupported_requirement"]
    if groups and all(item["status"] == "enforced" for item in groups) and all(
        item["status"] == "enforced" for item in prohibitions
    ):
        return "FULL", []
    if not required_groups and requirements and all(item["status"] == "enforced" for item in requirements):
        return "FULL", []
    return "REJECTED", ordered or ["compilation_rejected"]


def _group_requires(requirement, groups):
    for group in groups:
        if requirement["requirementId"] not in group["requirementIds"]:
            continue
        if group["composition"] == "anyOf" and group["status"] == "enforced":
            return False
        return True
    return True


def _selected(groups, by_id):
    selected = []
    for group in groups:
        if group["status"] != "enforced":
            continue
        if group["composition"] == "anyOf":
            selected.extend(
                item for item in group["requirementIds"]
                if by_id.get(item, {}).get("status") == "enforced"
            )
        else:
            selected.extend(group["requirementIds"])
    ordered = []
    for item in selected:
        if item not in ordered:
            ordered.append(item)
    return ordered


def _diagnostics(disposition, codes, baseline_exceeds):
    if disposition == "FULL":
        return []
    notes = [disposition]
    notes.extend(codes)
    if baseline_exceeds:
        notes.append("baseline_disclosed")
    return notes


def _worse(status, prior):
    rank = {"rejected": 0, "unenforced": 1, "enforced": 2}
    return rank[status] < rank[prior]


def _has_target_field(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_TARGET_KEYS or _has_target_field(item):
                return True
    elif isinstance(value, list):
        return any(_has_target_field(item) for item in value)
    return False
