"""OpenShell v0.1.2 REST base-policy compiler.

A permit that requires an executable identity is not compiled: v0.1.2 applies
a binary rule to descendant processes, which is wider than that identity.
A locator URI that contains a query component is unsupported. Query-string
precision is outside this compilation profile. This module does not invoke a
runtime.
"""

from __future__ import annotations

POLICY_SCHEMA_VERSION = 1
EXECUTABLE_IDENTITY = "approximated"
AUTHORITY_ROLE = "target-side restriction"
QUERY_PRECISION = "outside-profile"
EFFECTIVE_POLICY = "unverified"
POLICY_LAYER = "base"

_NETWORK_KINDS = ("api", "service")
_ALLOWED_OPERATIONS = {"api": "query", "service": "connect"}


def compile_slice(ir, assessment, manifest, profile, host):
    """Compile one FULL REST assessment. A failed check returns no policy."""
    substrate, substrate_mappings, substrate_reasons = host.substrate(assessment, manifest, profile, ir)
    if substrate_reasons:
        return host.empty(ir, assessment, "REJECTED", substrate_reasons)
    prepared = _prepare(ir, assessment, profile)
    if prepared[0] is None:
        return host.empty(ir, assessment, "REJECTED", prepared[1])
    grants, binaries, mappings = prepared
    policy = _policy(grants, binaries, substrate)
    yaml_text = render_network_yaml(policy, mappings, substrate_mappings)
    parsed = parse_network_yaml(yaml_text)
    if parsed != policy:
        return host.empty(ir, assessment, "REJECTED", ["policy_yaml_round_trip_failed"])
    reasons = verify_network_policy(policy, grants, substrate, binaries)
    extracted = _safe_extract(policy, grants, substrate, binaries)
    if reasons:
        return host.empty(ir, assessment, "REJECTED", reasons, extracted=extracted)
    result = host.base(ir, assessment)
    result.update({
        "sourceRequirementIds": _requirement_ids(mappings),
        "sourceBindingIds": [item["bindingId"] for item in mappings if item.get("bindingId")],
        "compilationDisposition": "FULL",
        "deployable": True,
        "runtimeDisposition": "UNOBSERVED",
        "generatedPolicy": policy,
        "policyYaml": yaml_text,
        "ruleMappings": mappings,
        "substrateMappings": substrate_mappings,
        "extractedAuthority": extracted,
        "networkGrants": grants,
        "binaryRestrictions": binaries,
        "monotonicity": "demonstrated",
        "policyLayer": POLICY_LAYER,
        "effectivePolicy": EFFECTIVE_POLICY,
        "executableIdentity": EXECUTABLE_IDENTITY,
        "descendantInheritance": True,
        "authorityRole": AUTHORITY_ROLE,
        "targetExecutableRestriction": binaries[0] if len(binaries) == 1 else None,
        "queryPrecision": QUERY_PRECISION,
        "diagnostics": [],
    })
    return result


def admit_network_policy(policy, ir, assessment, grants, substrate, binaries, host, yaml_text=None, mappings=None, substrate_mappings=None):
    """Re-check a base policy. Widening emits no deployable policy."""
    reasons = verify_network_policy(policy, grants, substrate, binaries)
    extracted = _safe_extract(policy, grants, substrate, binaries)
    if reasons:
        return host.empty(ir, assessment, "REJECTED", reasons, extracted=extracted)
    if not mappings:
        return host.empty(ir, assessment, "REJECTED", ["mapping_missing"])
    result = host.base(ir, assessment)
    result.update({
        "sourceRequirementIds": _requirement_ids(mappings),
        "sourceBindingIds": [item["bindingId"] for item in mappings if item.get("bindingId")],
        "compilationDisposition": "FULL",
        "deployable": True,
        "runtimeDisposition": "UNOBSERVED",
        "generatedPolicy": policy,
        "policyYaml": yaml_text,
        "ruleMappings": mappings,
        "substrateMappings": substrate_mappings or [],
        "extractedAuthority": extracted,
        "networkGrants": grants,
        "binaryRestrictions": binaries,
        "monotonicity": "demonstrated",
        "policyLayer": POLICY_LAYER,
        "effectivePolicy": EFFECTIVE_POLICY,
        "executableIdentity": EXECUTABLE_IDENTITY,
        "descendantInheritance": True,
        "authorityRole": AUTHORITY_ROLE,
        "targetExecutableRestriction": binaries[0] if len(binaries) == 1 else None,
        "queryPrecision": QUERY_PRECISION,
        "diagnostics": [],
    })
    return result


def verify_network_policy(policy, grants, substrate, binaries):
    """Return diagnostics when a base policy exceeds the FIP grant plus substrate."""
    reasons = _surface(policy, substrate)
    reasons.extend(_network_subset(policy, grants, binaries))
    return _unique(reasons)


def verify_effective_policy(policy, grants, substrate, binaries):
    """Check a policy get --full document against the full network tuple.

    Comparison uses the same extraction as a generated base policy: host, port,
    protocol, enforcement, HTTP method, HTTP path, binary scope, access preset,
    and TLS inspection. The same host is not sufficient. Provider rules are not
    FIP grants. A base-policy compile does not call this function.
    """
    reasons = verify_network_policy(policy, grants, substrate, binaries)
    extracted = extract_network_authority(policy) if isinstance(policy, dict) else {"endpoints": [], "binaryRestriction": []}
    for endpoint in extracted.get("endpoints") or []:
        reasons.extend(_tuple_reasons(endpoint, grants))
    if list(extracted.get("binaryRestriction") or []) != list(binaries):
        reasons.append("binary_restriction_widened")
    rules = policy.get("network_policies") if isinstance(policy, dict) else None
    if isinstance(rules, dict):
        for name in rules:
            if str(name).startswith("_provider_"):
                reasons.append("provider_authority_not_a_grant")
    return _unique(reasons)


def extract_network_authority(policy):
    """Recover the network fields this compiler emits from a base policy."""
    if not isinstance(policy, dict):
        policy = parse_network_yaml(policy)
    endpoints = []
    binaries = []
    rules = policy.get("network_policies") or {}
    if isinstance(rules, dict):
        for name in rules:
            rule = rules.get(name) or {}
            for endpoint in rule.get("endpoints") or []:
                if not isinstance(endpoint, dict):
                    continue
                allow = _allow(endpoint)
                endpoints.append({
                    "rule": name,
                    "host": endpoint.get("host"),
                    "port": endpoint.get("port"),
                    "protocol": endpoint.get("protocol"),
                    "enforcement": endpoint.get("enforcement"),
                    "method": allow.get("method") if isinstance(allow, dict) else None,
                    "path": allow.get("path") if isinstance(allow, dict) else None,
                    "access": endpoint.get("access"),
                    "tls": endpoint.get("tls"),
                })
            for binary in rule.get("binaries") or []:
                if isinstance(binary, dict):
                    binaries.append(binary.get("path"))
    return {
        "version": policy.get("version"),
        "endpoints": endpoints,
        "binaryRestriction": binaries,
        "defaultDeny": isinstance(rules, dict) and len(endpoints) == len(rules),
        "query": QUERY_PRECISION,
        "executableIdentity": EXECUTABLE_IDENTITY,
        "authorityRole": AUTHORITY_ROLE,
        "descendantInheritance": True,
    }


def render_network_yaml(policy, mappings, substrate_mappings):
    grant_notes = {item["bindingId"]: item for item in mappings if item.get("source") == "fip-grant"}
    binary_notes = {item["path"]: item for item in mappings if item.get("source") == "target-restriction"}
    substrate_notes = {item["path"]: item for item in substrate_mappings if item.get("path")}
    lines = [
        "# OpenShell policy schema 1",
        "# Base policy. This document is not an effective policy and does not observe a runtime.",
        "# The binary path is a target-side restriction from the compilation profile.",
        "# It is not a FIP executable grant. Descendant processes are not an exact identity.",
        "# Query precision is outside this compilation profile.",
        "version: 1",
        "filesystem_policy:",
        "  include_workdir: false",
        "  read_only:",
    ]
    for path in policy["filesystem_policy"]["read_only"]:
        note = substrate_notes[path]
        lines.append(f"    # execution-substrate {note['substrateId']}")
        lines.append(f"    - {path}")
    lines.append("  read_write:")
    for path in policy["filesystem_policy"]["read_write"]:
        note = substrate_notes[path]
        lines.append(f"    # execution-substrate {note['substrateId']}")
        lines.append(f"    - {path}")
    lines.extend([
        "landlock:",
        "  compatibility: hard_requirement",
        "network_policies:",
    ])
    for name in policy["network_policies"]:
        rule = policy["network_policies"][name]
        lines.append(f"  {name}:")
        lines.append("    endpoints:")
        for endpoint in rule["endpoints"]:
            grant = _grant_note(grant_notes, endpoint)
            lines.append(f"      # fip-grant {grant['requirementId']} {grant['bindingId']}")
            lines.append(f"      - host: {endpoint['host']}")
            lines.append(f"        port: {endpoint['port']}")
            lines.append("        protocol: rest")
            lines.append("        enforcement: enforce")
            lines.append("        rules:")
            lines.append("          - allow:")
            lines.append(f"              method: {endpoint['rules'][0]['allow']['method']}")
            lines.append(f"              path: {endpoint['rules'][0]['allow']['path']}")
        lines.append("    binaries:")
        for binary in rule["binaries"]:
            note = binary_notes[binary["path"]]
            lines.append(f"      # target-restriction {note['profileId']} approximated")
            lines.append(f"      - path: {binary['path']}")
    lines.append("")
    return "\n".join(lines)


def parse_network_yaml(text):
    """Parse the REST base-policy subset this compiler emits."""
    if not isinstance(text, str):
        raise ValueError("policy text required")
    tokens = []
    for raw in text.splitlines():
        code = raw.split("#", 1)[0].rstrip()
        if code.strip():
            tokens.append((len(code) - len(code.lstrip(" ")), code.strip()))
    parsed, index = _read_map(tokens, 0, -1)
    if index != len(tokens):
        raise ValueError("trailing policy content")
    return parsed


def _prepare(ir, assessment, profile):
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
        return None, _unique(reasons)
    grants = []
    binaries = []
    mappings = []
    for requirement_id in selected:
        requirement = requirements.get(requirement_id)
        if requirement is None:
            return None, ["requirement_omitted"]
        if statuses.get(requirement_id) != "enforced":
            return None, ["requirement_not_enforced"]
        if requirement.get("effect") == "deny":
            mappings.append({
                "requirementId": requirement_id,
                "effect": "deny",
                "policyField": "network_policies",
                "source": "unmatched-egress-deny",
            })
            continue
        if requirement.get("effect") != "permit":
            return None, ["requirement_not_a_selected_permit"]
        compiled = _permit(requirement, bindings, profile)
        if compiled[0] is None:
            return None, compiled[1]
        grant, binary, grant_mappings = compiled
        grants.append(grant)
        binaries.append(binary)
        mappings.extend(grant_mappings)
    if not grants:
        return None, ["no_rest_grant"]
    return grants, binaries, mappings


def _permit(requirement, bindings, profile):
    reasons = []
    if requirement.get("audit") != "target-native":
        reasons.append("correlated_audit" if requirement.get("audit") == "correlated" else "unsupported_audit")
    if requirement.get("lifetime") != "establishment-bound":
        reasons.append("lifetime_not_establishment_bound")
    network = []
    executables = []
    for binding_id in requirement.get("bindingIds") or []:
        binding = bindings.get(binding_id)
        if binding is None:
            return None, ["binding_missing"]
        kind = binding.get("kind")
        if kind in _NETWORK_KINDS:
            network.append(binding)
        elif kind == "executable":
            executables.append(binding)
        else:
            reasons.append("unsupported_binding_operation")
    if len(network) != 1:
        reasons.append("unsupported_binding_operation")
    binary_path = None
    if executables:
        reasons.append("executable_identity_not_exact")
    else:
        binary_path, binary_reasons = _profile_binary(profile)
        reasons.extend(binary_reasons)
    grant = None
    if len(network) == 1:
        grant_reasons, grant = _network_grant(network[0], requirement)
        reasons.extend(grant_reasons)
    if reasons:
        return None, _unique(reasons)
    if grant is None or binary_path is None:
        return None, ["target_binary_not_configured"]
    mappings = [
        {
            "requirementId": requirement["requirementId"],
            "bindingId": grant["bindingId"],
            "effect": "permit",
            "host": grant["host"],
            "port": grant["port"],
            "method": grant["method"],
            "path": grant["path"],
            "policyField": f"network_policies.{requirement['requirementId']}.endpoints",
            "source": "fip-grant",
        },
        {
            "requirementId": requirement["requirementId"],
            "effect": "permit",
            "path": binary_path,
            "policyField": f"network_policies.{requirement['requirementId']}.binaries",
            "source": "target-restriction",
            "profileId": profile.get("profileId"),
            "authorityRole": AUTHORITY_ROLE,
            "executableIdentity": EXECUTABLE_IDENTITY,
            "descendantInheritance": True,
        },
    ]
    return grant, binary_path, mappings


def _profile_binary(profile):
    """Read one explicit target restriction. Do not invent a path."""
    if not isinstance(profile, dict):
        return None, ["target_binary_not_configured"]
    rows = profile.get("targetExecutableRestrictions")
    if not isinstance(rows, list) or len(rows) == 0:
        return None, ["target_binary_not_configured"]
    if len(rows) != 1 or not isinstance(rows[0], dict) or set(rows[0]) != {"path"}:
        return None, ["binary_restriction_widened"]
    path = rows[0].get("path")
    if not isinstance(path, str) or not path.startswith("/") or path == "/" or _glob_widens(path) or ".." in path.split("/"):
        return None, ["target_binary_not_configured"]
    return path, []


def _network_grant(binding, requirement):
    reasons = []
    kind = binding.get("kind")
    if binding.get("operation") != _ALLOWED_OPERATIONS[kind]:
        reasons.append("unsupported_binding_operation")
    if binding.get("lifetime") != "establishment-bound":
        reasons.append("lifetime_not_establishment_bound")
    protocol = binding.get("protocol") or {}
    if protocol.get("family") != "http":
        reasons.append("protocol_not_rest")
    http = protocol.get("http") or {}
    method = http.get("method")
    path = http.get("path")
    locator = binding.get("locator") or {}
    host = locator.get("host")
    port = locator.get("port")
    if not isinstance(host, str) or _glob_widens(host):
        reasons.append("host_not_exact")
    if port is None:
        reasons.append("port_missing")
    elif not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        reasons.append("port_missing")
    if not isinstance(method, str) or method == "*" or _glob_widens(method):
        reasons.append("method_not_exact")
    elif method != "GET":
        reasons.append("unsupported_method")
    if not isinstance(path, str) or not path.startswith("/") or _glob_widens(path):
        reasons.append("path_not_exact")
    uri = locator.get("uri")
    if isinstance(uri, str) and "?" in uri:
        reasons.append("query_precision_unsupported")
    elif isinstance(uri, str) and isinstance(host, str) and isinstance(port, int) and not isinstance(port, bool):
        if _uri_disagrees(uri, host, port, path if isinstance(path, str) else None):
            reasons.append("uri_disagrees")
    if reasons:
        return _unique(reasons), None
    return [], {
        "requirementId": requirement["requirementId"],
        "bindingId": binding["bindingId"],
        "host": host,
        "port": port,
        "method": method,
        "path": path,
    }


def _policy(grants, binaries, substrate):
    read_only = [item["path"] for item in substrate if item["operation"] == "read"]
    read_write = [item["path"] for item in substrate if item["operation"] == "write"]
    rules = {}
    for grant, binary in zip(grants, binaries):
        rules[grant["requirementId"]] = {
            "endpoints": [{
                "host": grant["host"],
                "port": grant["port"],
                "protocol": "rest",
                "enforcement": "enforce",
                "rules": [{"allow": {"method": grant["method"], "path": grant["path"]}}],
            }],
            "binaries": [{"path": binary}],
        }
    return {
        "version": POLICY_SCHEMA_VERSION,
        "filesystem_policy": {
            "include_workdir": False,
            "read_only": read_only,
            "read_write": read_write,
        },
        "landlock": {"compatibility": "hard_requirement"},
        "network_policies": rules,
    }


def _surface(policy, substrate):
    if not isinstance(policy, dict):
        return ["policy_missing"]
    reasons = []
    if set(policy) != {"version", "filesystem_policy", "landlock", "network_policies"}:
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
    substrate_read = [item["path"] for item in substrate if item["operation"] == "read"]
    substrate_write = [item["path"] for item in substrate if item["operation"] == "write"]
    if read_only != substrate_read or read_write != substrate_write:
        reasons.append("filesystem_authority_mismatch")
    return reasons


def _network_subset(policy, grants, binaries):
    rules = policy.get("network_policies")
    if not isinstance(rules, dict) or not rules:
        return ["network_policy_missing"]
    reasons = []
    extracted = []
    found_binaries = []
    for name, rule in rules.items():
        if str(name).startswith("_provider_"):
            reasons.append("provider_authority_not_a_grant")
        allowed = {"endpoints", "binaries"}
        if isinstance(rule, dict) and "name" in rule:
            if rule.get("name") == name:
                allowed.add("name")
            else:
                reasons.append("unexpected_rule_fields")
        if not isinstance(rule, dict) or set(rule) != allowed:
            reasons.append("unexpected_rule_fields")
            continue
        endpoints = rule.get("endpoints")
        rule_binaries = rule.get("binaries")
        if not isinstance(endpoints, list) or not isinstance(rule_binaries, list):
            reasons.append("endpoint_outside_grant")
            continue
        if len(endpoints) != 1:
            reasons.append("endpoint_outside_grant")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                reasons.append("endpoint_outside_grant")
                continue
            reasons.extend(_endpoint_shape(endpoint))
            allow = _allow(endpoint)
            extracted.append({
                "host": endpoint.get("host"),
                "port": endpoint.get("port"),
                "method": allow.get("method") if isinstance(allow, dict) else None,
                "path": allow.get("path") if isinstance(allow, dict) else None,
                "protocol": endpoint.get("protocol"),
                "enforcement": endpoint.get("enforcement"),
                "access": endpoint.get("access"),
                "tls": endpoint.get("tls"),
            })
        for binary in rule_binaries:
            if isinstance(binary, dict):
                path = binary.get("path")
                found_binaries.append(path)
                if not isinstance(path, str) or _glob_widens(path):
                    reasons.append("executable_identity_not_exact")
    if len(extracted) != len(grants):
        reasons.append("endpoint_outside_grant")
    for endpoint in extracted:
        match = next((grant for grant in grants if _same_endpoint(endpoint, grant)), None)
        if match is None:
            reasons.append(_mismatch(endpoint, grants))
        elif endpoint.get("protocol") != "rest":
            reasons.append("protocol_downgraded" if endpoint.get("protocol") == "tcp" else "protocol_not_rest")
        elif endpoint.get("enforcement") != "enforce":
            reasons.append("audit_enforcement_does_not_block" if endpoint.get("enforcement") == "audit" else "enforcement_not_enforce")
    if found_binaries != list(binaries):
        reasons.append("binary_restriction_widened")
    return reasons


def _endpoint_shape(endpoint):
    reasons = []
    if "access" in endpoint:
        reasons.append("access_preset_widens")
    if endpoint.get("tls") == "skip" or (endpoint.get("tls") not in (None,) and "tls" in endpoint and endpoint.get("tls") != "automatic"):
        reasons.append("tls_inspection_disabled")
    if "query" in endpoint or _allow_has_query(endpoint):
        reasons.append("query_precision_unclaimed")
    allowed = {"host", "port", "protocol", "enforcement", "rules"}
    extra = set(endpoint) - allowed - {"access", "tls"}
    if extra:
        reasons.append("unexpected_endpoint_field")
    rules = endpoint.get("rules")
    if "access" not in endpoint:
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            reasons.append("method_not_exact")
        elif set(rules[0]) != {"allow"}:
            reasons.append("unexpected_endpoint_field")
        else:
            allow = rules[0].get("allow")
            if not isinstance(allow, dict) or set(allow) - {"query"} != {"method", "path"}:
                reasons.append("method_not_exact")
            elif not isinstance(allow.get("method"), str) or allow.get("method") in ("*",) or _glob_widens(str(allow.get("method"))):
                reasons.append("method_widened")
            elif _glob_widens(str(allow.get("path"))):
                reasons.append("path_widened")
    if endpoint.get("protocol") == "tcp":
        reasons.append("protocol_downgraded")
    elif endpoint.get("protocol") != "rest":
        reasons.append("protocol_not_rest")
    if endpoint.get("enforcement") == "audit":
        reasons.append("audit_enforcement_does_not_block")
    elif endpoint.get("enforcement") != "enforce":
        reasons.append("enforcement_not_enforce")
    return reasons


def _tuple_reasons(endpoint, grants):
    """Compare one effective endpoint to the permitted host, port, method, and path.

    Protocol, enforcement, access, and TLS are part of the same tuple.
    """
    reasons = []
    match = next((grant for grant in grants if _same_endpoint(endpoint, grant)), None)
    if match is None:
        reasons.append(_mismatch(endpoint, grants))
    if endpoint.get("protocol") != "rest":
        reasons.append("protocol_downgraded" if endpoint.get("protocol") == "tcp" else "protocol_not_rest")
    if endpoint.get("enforcement") != "enforce":
        reasons.append(
            "audit_enforcement_does_not_block" if endpoint.get("enforcement") == "audit" else "enforcement_not_enforce"
        )
    if endpoint.get("access") is not None:
        reasons.append("access_preset_widens")
    if endpoint.get("tls") == "skip":
        reasons.append("tls_inspection_disabled")
    method = endpoint.get("method")
    path = endpoint.get("path")
    if isinstance(method, str) and (method == "*" or _glob_widens(method)):
        reasons.append("method_widened")
    if isinstance(path, str) and _glob_widens(path):
        reasons.append("path_widened")
    return reasons


def _mismatch(endpoint, grants):
    if not grants:
        return "endpoint_outside_grant"
    grant = grants[0]
    if endpoint.get("host") != grant["host"]:
        return "host_widened"
    if endpoint.get("port") != grant["port"]:
        return "port_widened"
    if endpoint.get("method") != grant["method"]:
        return "method_widened"
    if endpoint.get("path") != grant["path"]:
        return "path_widened"
    return "endpoint_outside_grant"


def _same_endpoint(endpoint, grant):
    return (
        endpoint.get("host") == grant["host"]
        and endpoint.get("port") == grant["port"]
        and endpoint.get("method") == grant["method"]
        and endpoint.get("path") == grant["path"]
    )


def _allow(endpoint):
    rules = endpoint.get("rules") if isinstance(endpoint, dict) else None
    if isinstance(rules, list) and rules and isinstance(rules[0], dict):
        allow = rules[0].get("allow")
        if isinstance(allow, dict):
            return allow
    return {}


def _allow_has_query(endpoint):
    return "query" in _allow(endpoint)


def _grant_note(notes, endpoint):
    for note in notes.values():
        if note.get("host") == endpoint["host"] and note.get("path") == endpoint["rules"][0]["allow"]["path"]:
            return note
    raise KeyError(endpoint["host"])


def _extract(policy, grants, substrate, binaries):
    extracted = extract_network_authority(policy)
    extracted["mission"] = [
        {
            "host": grant["host"],
            "port": grant["port"],
            "method": grant["method"],
            "path": grant["path"],
            "requirementId": grant["requirementId"],
            "bindingId": grant["bindingId"],
        }
        for grant in grants
        if any(_same_endpoint(endpoint, grant) for endpoint in extracted["endpoints"])
    ]
    extracted["substrate"] = [
        {"substrateId": item["substrateId"], "operation": item["operation"], "path": item["path"]}
        for item in substrate
    ]
    extracted["binaryRestriction"] = [path for path in extracted["binaryRestriction"] if path in binaries]
    extracted["semanticAuthority"] = [
        {
            "host": item["host"],
            "port": item["port"],
            "method": item["method"],
            "path": item["path"],
            "requirementId": item["requirementId"],
            "bindingId": item["bindingId"],
        }
        for item in extracted["mission"]
    ]
    extracted["targetRestrictions"] = [
        {
            "path": path,
            "executableIdentity": EXECUTABLE_IDENTITY,
            "descendantInheritance": True,
            "authorityRole": AUTHORITY_ROLE,
        }
        for path in extracted["binaryRestriction"]
    ]
    return extracted


def _safe_extract(policy, grants, substrate, binaries):
    if not isinstance(policy, dict):
        return None
    try:
        return _extract(policy, grants, substrate, binaries)
    except (AttributeError, TypeError, KeyError):
        return None


def _requirement_ids(mappings):
    found = []
    for item in mappings:
        requirement_id = item.get("requirementId")
        if requirement_id not in found:
            found.append(requirement_id)
    return found


def _read_map(tokens, index, indent):
    mapping = {}
    while index < len(tokens):
        level, content = tokens[index]
        if level <= indent or content.startswith("- "):
            break
        key, value, index = _read_key(tokens, index)
        mapping[key] = value
    return mapping, index


def _read_key(tokens, index):
    level, content = tokens[index]
    key, raw = content.split(":", 1)
    key = key.strip()
    raw = raw.strip()
    index += 1
    if raw == "":
        if index < len(tokens) and tokens[index][0] > level and tokens[index][1].startswith("- "):
            value, index = _read_list(tokens, index, level)
        elif index < len(tokens) and tokens[index][0] > level:
            value, index = _read_map(tokens, index, level)
        else:
            value = {}
        return key, value, index
    return key, _scalar(raw), index


def _read_list(tokens, index, indent):
    items = []
    while index < len(tokens):
        level, content = tokens[index]
        if level <= indent or not content.startswith("- "):
            break
        item = content[2:].strip()
        index += 1
        if item == "":
            child, index = _read_map(tokens, index, level)
            items.append(child)
            continue
        if ":" in item and not item.startswith("/"):
            key, raw = item.split(":", 1)
            child = {}
            raw = raw.strip()
            if raw == "":
                if index < len(tokens) and tokens[index][0] > level and tokens[index][1].startswith("- "):
                    nested, index = _read_list(tokens, index, level)
                elif index < len(tokens) and tokens[index][0] > level:
                    nested, index = _read_map(tokens, index, level)
                else:
                    nested = {}
                child[key.strip()] = nested
            else:
                child[key.strip()] = _scalar(raw)
            while index < len(tokens) and tokens[index][0] > level and not tokens[index][1].startswith("- "):
                sibling, value, index = _read_key(tokens, index)
                child[sibling] = value
            items.append(child)
            continue
        items.append(_scalar(item))
    return items, index


def _glob_widens(value):
    return any(char in value for char in "*?[]")


def _uri_disagrees(uri, host, port, http_path):
    if "://" not in uri:
        return True
    scheme, rest = uri.split("://", 1)
    authority, separator, tail = rest.partition("/")
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        return True
    if ":" in authority:
        uri_host, raw_port = authority.rsplit(":", 1)
        if not raw_port.isdigit():
            return True
        uri_port = int(raw_port)
    else:
        uri_host = authority
        uri_port = {"https": 443, "http": 80}.get(scheme.lower())
    if uri_host != host or uri_port != port:
        return True
    if http_path and separator:
        observed = "/" + tail.split("?", 1)[0].split("#", 1)[0]
        if observed != http_path:
            return True
    return False


def _unique(reasons):
    found = []
    for reason in reasons:
        if reason not in found:
            found.append(reason)
    return found


def _scalar(value):
    if value == "false":
        return False
    if value == "true":
        return True
    if value.isdigit():
        return int(value)
    return value
