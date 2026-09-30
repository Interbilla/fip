"""OpenShell v0.1.2 policy adapter.

Compiles one FULL coverage assessment into policy schema 1. Filesystem
assessments stay on the filesystem path. A qualified REST assessment is
compiled by the sibling REST compiler. This module does not invoke a
runtime and it does not decide semantic authority.

Pin: NVIDIA OpenShell v0.1.2, commit 6648bd0c290efbc41ba131ee9831ee45cd431f94,
policy schema 1.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SOURCE_COMMIT = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
ADAPTER_ID = "openshell-v0.1.2"
ADAPTER_VERSION = "0"
TARGET_TYPE = "sandbox"
TARGET_VERSION = "0.1.2"
POLICY_SCHEMA_VERSION = 1
PROFILE_ID = "openshell-v0.1.2-execution-substrate"
PROFILE_VERSION = "0"
RUNTIME_DISPOSITION = "UNOBSERVED"

_READ = "read"
_WRITE = "write"


def _filesystem_locator_issue(path):
    from fip02.coverage import filesystem_locator_issue

    return filesystem_locator_issue(path)


def compile_policy(ir, assessment, manifest, profile, document=None, policy=None, approvals=None):
    """Return an adapter result. A refused input has no generated policy.

    document and policy are the current semantic sources. A deployable policy
    requires the consumed IR to match a fresh projection of those sources.
    """
    from fip02.derivation import verify_derivation

    if isinstance(ir, dict):
        verdict = verify_derivation(ir, document, policy=policy, approvals=approvals)
        if not verdict["matched"]:
            return _empty(ir, assessment, "REJECTED", ["subset_not_demonstrated"])
    refused = _gate(assessment)
    if refused:
        diagnostics = list(refused[1])
        if _permit_requires_executable(ir):
            diagnostics.append("executable_identity_not_exact")
        if _permit_has_kind(ir, "credential"):
            diagnostics.append("credential_use_not_independent")
        if _permit_has_kind(ir, "model") or _permit_has_kind(ir, "inference-provider"):
            diagnostics.append("model_identity_unsupported")
        return _empty(ir, assessment, refused[0], diagnostics)
    refused = _identities(assessment, manifest, profile)
    if refused:
        return _empty(ir, assessment, "REJECTED", refused)
    if _permit_has_kind(ir, "credential"):
        return _empty(ir, assessment, "REJECTED", ["credential_use_not_independent"])
    if _permit_has_kind(ir, "model") or _permit_has_kind(ir, "inference-provider"):
        return _empty(ir, assessment, "REJECTED", ["model_identity_unsupported"])
    if _mcp_slice(ir, assessment):
        return _network_slices().compile_mcp(ir, assessment, manifest, profile, _compiler_host())
    if _tcp_slice(ir, assessment):
        return _network_slices().compile_tcp(ir, assessment, manifest, profile, _compiler_host())
    if _rest_slice(ir, assessment):
        return _rest_compiler().compile_slice(ir, assessment, manifest, profile, _compiler_host())
    prepared = _prepare(ir, assessment, manifest, profile)
    if prepared[0] is None:
        return _empty(ir, assessment, "REJECTED", prepared[1])
    grants, substrate, mappings, substrate_mappings = prepared
    policy = _policy(grants, substrate)
    yaml_text = render_policy_yaml(policy, mappings, substrate_mappings)
    parsed = parse_policy_yaml(yaml_text)
    if parsed != policy:
        return _empty(ir, assessment, "REJECTED", ["policy_yaml_round_trip_failed"])
    return admit_generated_policy(
        policy, ir, assessment, grants, substrate, yaml_text, mappings, substrate_mappings
    )


def admit_generated_policy(policy, ir, assessment, grants, substrate, yaml_text=None, mappings=None, substrate_mappings=None):
    """Post-generation check. A failed check returns no deployable policy."""
    reasons = verify_policy(policy, grants, substrate)
    extracted = _safe_extract(policy, grants, substrate)
    if reasons:
        return _empty(ir, assessment, "REJECTED", reasons, extracted=extracted)
    if mappings is None:
        return _empty(ir, assessment, "REJECTED", ["mapping_missing"])
    return _success(ir, assessment, policy, yaml_text, mappings, substrate_mappings or [], grants, substrate)


def verify_policy(policy, grants, substrate):
    """Return diagnostic strings when the policy widens authority. Empty means demonstrated."""
    if not isinstance(policy, dict):
        return ["policy_missing"]
    reasons = []
    if set(policy) != {"version", "filesystem_policy", "landlock"}:
        reasons.append("unexpected_policy_fields")
    if policy.get("version") != POLICY_SCHEMA_VERSION:
        reasons.append("policy_schema_mismatch")
    filesystem = policy.get("filesystem_policy")
    if not isinstance(filesystem, dict) or set(filesystem) != {"include_workdir", "read_only", "read_write"}:
        reasons.append("filesystem_policy_shape")
        return reasons
    if filesystem.get("include_workdir") is not False:
        reasons.append("workdir_implicitly_added")
    landlock = policy.get("landlock")
    if not isinstance(landlock, dict) or landlock.get("compatibility") != "hard_requirement":
        reasons.append("soft_filesystem_enforcement")
    read_only = filesystem.get("read_only")
    read_write = filesystem.get("read_write")
    if not isinstance(read_only, list) or not isinstance(read_write, list):
        reasons.append("path_lists_missing")
        return reasons
    grant_read = {path for operation, path in grants if operation == _READ}
    grant_write = {path for operation, path in grants if operation == _WRITE}
    substrate_read = {item["path"] for item in substrate if item["operation"] == _READ}
    substrate_write = {item["path"] for item in substrate if item["operation"] == _WRITE}
    if set(read_only) != grant_read | substrate_read:
        reasons.append("read_authority_mismatch")
    if set(read_write) != grant_write | substrate_write:
        reasons.append("write_authority_mismatch")
    if grant_read & set(read_write):
        reasons.append("read_emitted_as_read_write")
    if substrate_read & set(read_write):
        reasons.append("substrate_access_widened")
    extra = (set(read_only) | set(read_write)) - grant_read - grant_write - substrate_read - substrate_write
    if extra:
        reasons.append("path_broader_or_unaccepted")
    for path in list(read_only) + list(read_write):
        if _broader_than_grant(path, grant_read | grant_write | substrate_read | substrate_write):
            reasons.append("path_broader_or_unaccepted")
            break
    return reasons


def extract_authority(policy):
    """Extract the filesystem subset this adapter emits. Other policies are rejected."""
    parsed = policy if isinstance(policy, dict) else parse_policy_yaml(policy)
    filesystem = parsed.get("filesystem_policy") or {}
    return {
        "version": parsed.get("version"),
        "includeWorkdir": filesystem.get("include_workdir"),
        "landlock": (parsed.get("landlock") or {}).get("compatibility"),
        "readOnly": list(filesystem.get("read_only") or []),
        "readWrite": list(filesystem.get("read_write") or []),
    }


def render_policy_yaml(policy, mappings, substrate_mappings):
    grant_reads = {item["path"] for item in mappings if item["operation"] == _READ}
    grant_writes = {item["path"] for item in mappings if item["operation"] == _WRITE}
    read_notes = {item["path"]: item for item in mappings if item["operation"] == _READ}
    write_notes = {item["path"]: item for item in mappings if item["operation"] == _WRITE}
    substrate_notes = {item["path"]: item for item in substrate_mappings if item.get("path")}
    lines = [
        "# OpenShell policy schema 1",
        "# FIP grant paths are commented fip-grant. Accepted execution substrate paths are commented execution-substrate.",
        "version: 1",
        "filesystem_policy:",
        "  include_workdir: false",
        "  read_only:",
    ]
    for path in policy["filesystem_policy"]["read_only"]:
        lines.append(_path_comment(path, grant_reads, read_notes, substrate_notes))
        lines.append(f"    - {path}")
    lines.append("  read_write:")
    for path in policy["filesystem_policy"]["read_write"]:
        lines.append(_path_comment(path, grant_writes, write_notes, substrate_notes))
        lines.append(f"    - {path}")
    lines.extend([
        "landlock:",
        "  compatibility: hard_requirement",
        "",
    ])
    return "\n".join(lines)


def parse_policy_yaml(text):
    """Parse the filesystem subset this adapter emits."""
    if not isinstance(text, str):
        raise ValueError("policy text required")
    lines = []
    for raw in text.splitlines():
        code = raw.split("#", 1)[0].rstrip()
        if code.strip():
            lines.append(code)
    root = {}
    stack = [(-1, root)]
    for index, code in enumerate(lines):
        indent = len(code) - len(code.lstrip(" "))
        content = code.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if content.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("list item outside a list")
            parent.append(content[2:].strip())
            continue
        if ":" not in content:
            raise ValueError("unsupported policy line")
        key, value = content.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "":
            nxt = lines[index + 1].strip() if index + 1 < len(lines) else ""
            container = [] if nxt.startswith("- ") else {}
            if not isinstance(parent, dict):
                raise ValueError("nested key outside a mapping")
            parent[key] = container
            stack.append((indent, container))
            continue
        if not isinstance(parent, dict):
            raise ValueError("scalar outside a mapping")
        parent[key] = _scalar(value)
    return root


def verify_network_policy(policy, grants, substrate, binaries):
    """Check a generated REST base policy. Filesystem policies use verify_policy."""
    return _rest_compiler().verify_network_policy(policy, grants, substrate, binaries)


def verify_effective_policy(policy, grants, substrate, binaries):
    """Check a policy get --full document. Compiler success does not call this."""
    return _rest_compiler().verify_effective_policy(policy, grants, substrate, binaries)


def admit_network_policy(policy, ir, assessment, grants, substrate, binaries, yaml_text=None, mappings=None, substrate_mappings=None):
    """Re-check a REST base policy after a mutation."""
    return _rest_compiler().admit_network_policy(
        policy, ir, assessment, grants, substrate, binaries, _compiler_host(),
        yaml_text, mappings, substrate_mappings,
    )


def _permit_requires_executable(ir):
    """True when a permit lists an executable binding.

    On pinned v0.1.2 that binding is an exact FIP identity the binary rule
    widens to descendant processes. The adapter must not compile it.
    """
    if not isinstance(ir, dict):
        return False
    bindings = {
        item.get("bindingId"): item
        for item in ir.get("bindings") or []
        if isinstance(item, dict)
    }
    for requirement in ir.get("requirements") or []:
        if not isinstance(requirement, dict) or requirement.get("effect") != "permit":
            continue
        for binding_id in requirement.get("bindingIds") or []:
            if (bindings.get(binding_id) or {}).get("kind") == "executable":
                return True
    return False


def _permit_has_kind(ir, kind):
    if not isinstance(ir, dict):
        return False
    bindings = {
        item.get("bindingId"): item
        for item in ir.get("bindings") or []
        if isinstance(item, dict)
    }
    for requirement in ir.get("requirements") or []:
        if not isinstance(requirement, dict) or requirement.get("effect") != "permit":
            continue
        for binding_id in requirement.get("bindingIds") or []:
            if (bindings.get(binding_id) or {}).get("kind") == kind:
                return True
    return False


def _selected_bindings(ir, assessment):
    requirements = {
        item.get("requirementId"): item
        for item in (ir or {}).get("requirements") or []
        if isinstance(item, dict)
    }
    bindings = {
        item.get("bindingId"): item
        for item in (ir or {}).get("bindings") or []
        if isinstance(item, dict)
    }
    found = []
    for requirement_id in (assessment or {}).get("selectedRequirementIds") or []:
        requirement = requirements.get(requirement_id) or {}
        if requirement.get("effect") != "permit":
            continue
        for binding_id in requirement.get("bindingIds") or []:
            binding = bindings.get(binding_id)
            if isinstance(binding, dict):
                found.append((requirement, binding))
    return found


def _mcp_slice(ir, assessment):
    return any(
        (binding.get("protocol") or {}).get("family") == "mcp"
        for _requirement, binding in _selected_bindings(ir, assessment)
    )


def _tcp_slice(ir, assessment):
    for _requirement, binding in _selected_bindings(ir, assessment):
        family = (binding.get("protocol") or {}).get("family")
        http = (binding.get("protocol") or {}).get("http") or {}
        if binding.get("kind") == "service" and binding.get("operation") == "connect" and family != "mcp" and not http:
            return True
    return False


def _rest_slice(ir, assessment):
    if not isinstance(ir, dict) or not isinstance(assessment, dict):
        return False
    requirements = {
        item.get("requirementId"): item
        for item in ir.get("requirements") or []
        if isinstance(item, dict)
    }
    bindings = {
        item.get("bindingId"): item
        for item in ir.get("bindings") or []
        if isinstance(item, dict)
    }
    saw_network = False
    for requirement_id in assessment.get("selectedRequirementIds") or []:
        requirement = requirements.get(requirement_id) or {}
        if requirement.get("effect") != "permit":
            continue
        kinds = [
            (bindings.get(binding_id) or {}).get("kind")
            for binding_id in requirement.get("bindingIds") or []
        ]
        if "filesystem" in kinds:
            return False
        if any(kind in ("api", "service") for kind in kinds):
            saw_network = True
    return saw_network


class _CompilerHost:
    def __init__(self):
        self.empty = _empty
        self.base = _base
        self.substrate = _substrate


def _compiler_host():
    return _CompilerHost()


_REST = None
_SLICES = None


def _network_slices():
    global _SLICES
    if _SLICES is None:
        path = Path(__file__).with_name("network_slices.py")
        spec = importlib.util.spec_from_file_location("openshell_network_slices", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SLICES = module
    return _SLICES


def _rest_compiler():
    global _REST
    if _REST is None:
        path = Path(__file__).with_name("rest.py")
        spec = importlib.util.spec_from_file_location("openshell_rest_compiler", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _REST = module
    return _REST


def _gate(assessment):
    if not isinstance(assessment, dict):
        return "NOT_COMPILED", ["assessment_missing"]
    authority = assessment.get("authorityDecision")
    disposition = assessment.get("compilationDisposition")
    deployable = assessment.get("deployable")
    if authority == "AUTHORIZED" and disposition == "FULL" and deployable is True:
        return None
    if disposition in ("PARTIAL", "REJECTED", "NOT_COMPILED"):
        kept = disposition
    else:
        kept = "REJECTED"
    return kept, ["assessment_not_deployable"]


def _identities(assessment, manifest, profile):
    reasons = []
    if not isinstance(manifest, dict):
        return ["manifest_missing"]
    if manifest.get("adapterId") != ADAPTER_ID or assessment.get("manifestId") != ADAPTER_ID:
        reasons.append("manifest_identity_mismatch")
    if manifest.get("targetVersion") != TARGET_VERSION or assessment.get("targetVersion") != TARGET_VERSION:
        reasons.append("target_version_mismatch")
    if manifest.get("adapterVersion") != ADAPTER_VERSION or assessment.get("adapterVersion") != ADAPTER_VERSION:
        reasons.append("adapter_version_mismatch")
    if manifest.get("targetType") != TARGET_TYPE or assessment.get("targetType") != TARGET_TYPE:
        reasons.append("target_type_mismatch")
    if manifest.get("manifestVersion") != "0" or assessment.get("fipVersion") != "0.2":
        reasons.append("version_mismatch")
    if not isinstance(profile, dict) or profile.get("profileId") != PROFILE_ID or profile.get("profileVersion") != PROFILE_VERSION:
        reasons.append("execution_profile_mismatch")
    return reasons


def _prepare(ir, assessment, manifest, profile):
    if not isinstance(ir, dict) or ir.get("irVersion") != "0" or ir.get("fipVersion") != "0.2":
        return None, ["ir_not_operational"]
    if ir.get("authorityDecision") != "AUTHORIZED":
        return None, ["ir_authority_mismatch"]
    requirements = {item.get("requirementId"): item for item in ir.get("requirements") or []}
    bindings = {item.get("bindingId"): item for item in ir.get("bindings") or []}
    selected = list(assessment.get("selectedRequirementIds") or [])
    statuses = {item.get("requirementId"): item.get("status") for item in assessment.get("requirements") or []}
    reasons = []
    for group in ir.get("groups") or []:
        if group.get("composition") != "allOf":
            continue
        for member in group.get("requirementIds") or []:
            if member not in requirements:
                reasons.append("requirement_omitted")
            if member not in selected or statuses.get(member) != "enforced":
                reasons.append("allof_member_omitted")
    if reasons:
        return None, reasons
    prohibited = _prohibited_paths(ir)
    grants = []
    mappings = []
    for requirement_id in selected:
        requirement = requirements.get(requirement_id)
        if requirement is None:
            return None, ["requirement_omitted"]
        if requirement.get("effect") != "permit" or statuses.get(requirement_id) != "enforced":
            return None, ["requirement_not_a_selected_permit"]
        binding_ids = list(requirement.get("bindingIds") or [])
        if len(binding_ids) != 1:
            return None, ["binding_path_missing"]
        binding = bindings.get(binding_ids[0])
        if binding is None:
            return None, ["binding_path_missing"]
        compiled = _filesystem_grant(binding)
        if compiled[0] is None:
            return None, [compiled[1]]
        operation, path = compiled
        if "*" in prohibited or path in prohibited:
            return None, ["grant_conflicts_with_prohibition"]
        grants.append((operation, path))
        mappings.append({
            "requirementId": requirement_id,
            "bindingId": binding["bindingId"],
            "effect": "permit",
            "operation": operation,
            "path": path,
            "policyField": "filesystem_policy.read_only" if operation == _READ else "filesystem_policy.read_write",
            "source": "fip-grant",
        })
    if not grants:
        return None, ["no_filesystem_grant"]
    substrate, substrate_mappings, substrate_reasons = _substrate(assessment, manifest, profile, ir)
    if substrate_reasons:
        return None, substrate_reasons
    return grants, substrate, mappings, substrate_mappings


def _filesystem_grant(binding):
    if binding.get("kind") != "filesystem":
        return None, "unsupported_binding_operation"
    operation = binding.get("operation")
    if operation not in (_READ, _WRITE):
        return None, "unsupported_binding_operation"
    path = (binding.get("locator") or {}).get("path")
    if not isinstance(path, str) or not path:
        return None, "binding_path_missing"
    if _filesystem_locator_issue(path):
        return None, "filesystem_locator_not_exact"
    return operation, path


def _substrate(assessment, manifest, profile, ir):
    manifest_rows = {item.get("substrateId"): item for item in manifest.get("substrate") or []}
    accepted_rules = [item for item in profile.get("acceptedExecutionSubstrate") or [] if isinstance(item, dict)]
    prohibited = _prohibited_paths(ir)
    emitted = []
    mappings = []
    reasons = []
    for row in (assessment.get("coverage") or {}).get("targetBaseline") or []:
        if row.get("acceptance") != "accepted":
            continue
        substrate_id = row.get("substrateId")
        declared = manifest_rows.get(substrate_id)
        if declared is None:
            reasons.append("substrate_not_in_manifest")
            continue
        if not _profile_accepts(declared, accepted_rules):
            reasons.append("substrate_not_accepted")
            continue
        if declared.get("substrateClass") != row.get("substrateClass"):
            reasons.append("substrate_class_mismatch")
            continue
        path = (declared.get("locator") or {}).get("path")
        operation = declared.get("operation")
        if "*" in prohibited or path in prohibited:
            reasons.append("substrate_conflicts_with_prohibition")
            continue
        if declared.get("substrateClass") == "restrictive" or not path:
            mappings.append({
                "substrateId": substrate_id,
                "profileId": PROFILE_ID,
                "substrateClass": declared.get("substrateClass"),
                "operation": operation,
                "path": None,
                "policyField": None,
                "emitted": False,
                "source": "execution-substrate",
            })
            continue
        if _filesystem_locator_issue(path) or operation not in (_READ, _WRITE):
            reasons.append("substrate_access_widened")
            continue
        if declared.get("kind") != "filesystem":
            reasons.append("substrate_not_filesystem")
            continue
        emitted.append({
            "substrateId": substrate_id,
            "operation": operation,
            "path": path,
            "substrateClass": declared.get("substrateClass"),
        })
        mappings.append({
            "substrateId": substrate_id,
            "profileId": PROFILE_ID,
            "substrateClass": declared.get("substrateClass"),
            "operation": operation,
            "path": path,
            "policyField": "filesystem_policy.read_only" if operation == _READ else "filesystem_policy.read_write",
            "emitted": True,
            "source": "execution-substrate",
        })
    return emitted, mappings, reasons


def _profile_accepts(entry, rules):
    for rule in rules:
        if rule.get("substrateId") != entry.get("substrateId"):
            continue
        if rule.get("substrateClass") != entry.get("substrateClass"):
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


def _prohibited_paths(ir):
    bindings = {item.get("bindingId"): item for item in ir.get("bindings") or []}
    paths = set()
    statements = [item for item in ir.get("requirements") or [] if item.get("effect") == "deny"]
    statements.extend(ir.get("prohibitions") or [])
    for statement in statements:
        pattern = statement.get("bindingPattern") or {}
        if "filesystem" in (pattern.get("kinds") or []):
            paths.add("*")
        for binding_id in statement.get("bindingIds") or []:
            path = ((bindings.get(binding_id) or {}).get("locator") or {}).get("path")
            if path:
                paths.add(path)
    return paths


def _policy(grants, substrate):
    read_only = _ordered(grants, substrate, _READ)
    read_write = _ordered(grants, substrate, _WRITE)
    return {
        "version": POLICY_SCHEMA_VERSION,
        "filesystem_policy": {
            "include_workdir": False,
            "read_only": read_only,
            "read_write": read_write,
        },
        "landlock": {"compatibility": "hard_requirement"},
    }


def _ordered(grants, substrate, operation):
    granted = sorted(path for item_operation, path in grants if item_operation == operation)
    accepted = [item["path"] for item in substrate if item["operation"] == operation]
    return granted + accepted


def _exact_path(path):
    return isinstance(path, str) and path.startswith("/") and path != "/" and ".." not in path.split("/")


def _broader_than_grant(path, known):
    if path in known:
        return False
    for item in known:
        if item.startswith(path.rstrip("/") + "/"):
            return True
    return True


def _extract(policy, grants, substrate):
    extracted = extract_authority(policy)
    grant_read = {path for operation, path in grants if operation == _READ}
    grant_write = {path for operation, path in grants if operation == _WRITE}
    substrate_ids = {item["path"]: item["substrateId"] for item in substrate}
    mission = [{"operation": _READ, "path": path} for path in extracted["readOnly"] if path in grant_read]
    mission.extend({"operation": _WRITE, "path": path} for path in extracted["readWrite"] if path in grant_write)
    accepted = []
    for path in extracted["readOnly"]:
        if path in substrate_ids and path not in grant_read:
            accepted.append({"substrateId": substrate_ids[path], "operation": _READ, "path": path})
    for path in extracted["readWrite"]:
        if path in substrate_ids and path not in grant_write:
            accepted.append({"substrateId": substrate_ids[path], "operation": _WRITE, "path": path})
    extracted["mission"] = mission
    extracted["substrate"] = accepted
    return extracted


def _success(ir, assessment, policy, yaml_text, mappings, substrate_mappings, grants, substrate):
    result = _base(ir, assessment)
    result.update({
        "sourceRequirementIds": [item["requirementId"] for item in mappings],
        "sourceBindingIds": [item["bindingId"] for item in mappings],
        "compilationDisposition": "FULL",
        "deployable": True,
        "runtimeDisposition": RUNTIME_DISPOSITION,
        "generatedPolicy": policy,
        "policyYaml": yaml_text,
        "ruleMappings": mappings,
        "substrateMappings": substrate_mappings,
        "extractedAuthority": _extract(policy, grants, substrate),
        "monotonicity": "demonstrated",
        "diagnostics": [],
    })
    return result


def _empty(ir, assessment, disposition, diagnostics, extracted=None):
    result = _base(ir, assessment)
    result.update({
        "sourceRequirementIds": [],
        "sourceBindingIds": [],
        "compilationDisposition": disposition,
        "deployable": False,
        "runtimeDisposition": RUNTIME_DISPOSITION,
        "generatedPolicy": None,
        "policyYaml": None,
        "ruleMappings": [],
        "substrateMappings": [],
        "extractedAuthority": extracted,
        "monotonicity": "not_demonstrated",
        "diagnostics": list(diagnostics),
    })
    return result


def _base(ir, assessment):
    source = ir if isinstance(ir, dict) else {}
    covered = assessment if isinstance(assessment, dict) else {}
    return {
        "adapterId": ADAPTER_ID,
        "adapterVersion": ADAPTER_VERSION,
        "targetType": TARGET_TYPE,
        "targetVersion": TARGET_VERSION,
        "policySchemaVersion": POLICY_SCHEMA_VERSION,
        "sourceCommit": SOURCE_COMMIT,
        "policyId": source.get("policyId") or covered.get("policyId"),
        "traceId": source.get("traceId") or covered.get("traceId"),
    }


def _path_comment(path, grants, grant_notes, substrate_notes):
    if path in grants:
        note = grant_notes[path]
        return f"    # fip-grant {note['requirementId']} {note['bindingId']}"
    note = substrate_notes[path]
    return f"    # execution-substrate {note['substrateId']}"


def _safe_extract(policy, grants, substrate):
    if not isinstance(policy, dict):
        return None
    try:
        return _extract(policy, grants, substrate)
    except (AttributeError, TypeError, KeyError):
        return extract_authority(policy) if isinstance(policy, dict) else None


def _scalar(value):
    if value == "false":
        return False
    if value == "true":
        return True
    if value.isdigit():
        return int(value)
    return value
