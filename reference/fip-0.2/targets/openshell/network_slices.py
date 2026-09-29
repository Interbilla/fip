"""TCP connect and MCP tool compilation for pinned OpenShell v0.1.2.

TCP is service connect with an exact host and port. It has no HTTP method or
path. MCP is one exact method, and tools/call also names one exact tool.
Neither slice compiles an executable identity, a credential, or a model id.
Query arguments and MCP tool arguments are outside the grant.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

POLICY_SCHEMA_VERSION = 1
EXECUTABLE_IDENTITY = "approximated"
AUTHORITY_ROLE = "target-side restriction"


def compile_tcp(ir, assessment, manifest, profile, host):
    return _compile(ir, assessment, manifest, profile, host, "tcp")


def compile_mcp(ir, assessment, manifest, profile, host):
    return _compile(ir, assessment, manifest, profile, host, "mcp")


def verify_tcp_policy(policy, grant, substrate, binary):
    reasons = _surface(policy, substrate)
    reasons.extend(_tcp_endpoint(policy, grant, binary))
    return _unique(reasons)


def verify_mcp_policy(policy, grant, substrate, binary):
    reasons = _surface(policy, substrate)
    reasons.extend(_mcp_endpoint(policy, grant, binary))
    return _unique(reasons)


def _compile(ir, assessment, manifest, profile, host, mode):
    substrate, substrate_mappings, substrate_reasons = host.substrate(assessment, manifest, profile, ir)
    if substrate_reasons:
        return host.empty(ir, assessment, "REJECTED", substrate_reasons)
    prepared = _prepare(ir, assessment, profile, mode)
    if prepared[0] is None:
        return host.empty(ir, assessment, "REJECTED", prepared[1])
    grant, binary, mappings = prepared
    policy = _policy(grant, binary, substrate, mode)
    reasons = verify_tcp_policy(policy, grant, substrate, binary) if mode == "tcp" else verify_mcp_policy(policy, grant, substrate, binary)
    if reasons:
        return host.empty(ir, assessment, "REJECTED", reasons)
    result = host.base(ir, assessment)
    result.update({
        "sourceRequirementIds": [grant["requirementId"]],
        "sourceBindingIds": [grant["bindingId"]],
        "compilationDisposition": "FULL",
        "deployable": True,
        "runtimeDisposition": "UNOBSERVED",
        "generatedPolicy": policy,
        "policyYaml": _yaml(policy, mode),
        "ruleMappings": mappings,
        "substrateMappings": substrate_mappings,
        "monotonicity": "demonstrated",
        "policyLayer": "base",
        "effectivePolicy": "unverified",
        "executableIdentity": EXECUTABLE_IDENTITY,
        "descendantInheritance": True,
        "authorityRole": AUTHORITY_ROLE,
        "targetExecutableRestriction": binary,
        "diagnostics": [],
    })
    return result


def _prepare(ir, assessment, profile, mode):
    selected = assessment.get("selectedRequirementIds") or []
    statuses = {item["requirementId"]: item["status"] for item in assessment.get("requirements") or []}
    requirements = {item["requirementId"]: item for item in ir.get("requirements") or []}
    bindings = {item["bindingId"]: item for item in ir.get("bindings") or []}
    permits = []
    for requirement_id in selected:
        requirement = requirements.get(requirement_id) or {}
        if requirement.get("effect") != "permit" or statuses.get(requirement_id) != "enforced":
            continue
        permits.append(requirement)
    if len(permits) != 1:
        return None, ["unsupported_binding_operation"]
    requirement = permits[0]
    reasons = []
    if requirement.get("audit") != "target-native":
        reasons.append("correlated_audit" if requirement.get("audit") == "correlated" else "unsupported_audit")
    if requirement.get("lifetime") != "establishment-bound":
        reasons.append("lifetime_not_establishment_bound")
    network = []
    for binding_id in requirement.get("bindingIds") or []:
        binding = bindings.get(binding_id)
        if binding is None:
            return None, ["binding_missing"]
        if binding.get("kind") == "executable":
            reasons.append("executable_identity_not_exact")
        elif binding.get("kind") in ("credential", "model", "inference-provider"):
            reasons.append("credential_use_not_independent" if binding.get("kind") == "credential" else "model_identity_unsupported")
        else:
            network.append(binding)
    if len(network) != 1:
        reasons.append("unsupported_binding_operation")
    binary, binary_reasons = _profile_binary(profile)
    reasons.extend(binary_reasons)
    grant = None
    if len(network) == 1:
        grant_reasons, grant = (_tcp_grant if mode == "tcp" else _mcp_grant)(network[0], requirement)
        reasons.extend(grant_reasons)
    if reasons or grant is None or binary is None:
        return None, _unique(reasons or ["target_binary_not_configured"])
    return grant, binary, [
        {
            "requirementId": requirement["requirementId"],
            "bindingId": grant["bindingId"],
            "source": "fip-grant",
        },
        {
            "requirementId": requirement["requirementId"],
            "path": binary,
            "source": "target-restriction",
            "authorityRole": AUTHORITY_ROLE,
            "executableIdentity": EXECUTABLE_IDENTITY,
            "descendantInheritance": True,
        },
    ]


def _tcp_grant(binding, requirement):
    reasons = []
    if binding.get("kind") != "service" or binding.get("operation") != "connect":
        reasons.append("unsupported_binding_operation")
    protocol = binding.get("protocol") or {}
    if protocol.get("family") not in (None,):
        reasons.append("protocol_not_tcp")
    if protocol.get("http") or protocol.get("mcp"):
        reasons.append("protocol_not_tcp")
    host, port, locator_reasons = _host_port(binding.get("locator") or {})
    reasons.extend(locator_reasons)
    if reasons:
        return reasons, None
    return [], {
        "requirementId": requirement["requirementId"],
        "bindingId": binding["bindingId"],
        "host": host,
        "port": port,
    }


def _mcp_grant(binding, requirement):
    reasons = []
    if binding.get("kind") != "api" or binding.get("operation") != "invoke":
        reasons.append("unsupported_binding_operation")
    protocol = binding.get("protocol") or {}
    if protocol.get("family") != "mcp":
        reasons.append("protocol_not_mcp")
    mcp = protocol.get("mcp") or {}
    method = mcp.get("method")
    tool = mcp.get("tool")
    if not isinstance(method, str) or method in ("*",) or _glob_widens(method):
        reasons.append("method_not_exact")
    elif method == "tools/call":
        if not isinstance(tool, str) or not tool or _glob_widens(tool):
            reasons.append("tool_not_exact")
    elif tool:
        reasons.append("tool_not_exact")
    host, port, locator_reasons = _host_port(binding.get("locator") or {})
    reasons.extend(locator_reasons)
    if reasons:
        return reasons, None
    grant = {
        "requirementId": requirement["requirementId"],
        "bindingId": binding["bindingId"],
        "host": host,
        "port": port,
        "method": method,
    }
    if method == "tools/call":
        grant["tool"] = tool
    return [], grant


def _host_port(locator):
    reasons = []
    host = locator.get("host")
    port = locator.get("port")
    if not isinstance(host, str) or _glob_widens(host):
        reasons.append("host_not_exact")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        reasons.append("port_missing")
    uri = locator.get("uri")
    if isinstance(uri, str) and "?" in uri:
        reasons.append("query_precision_unsupported")
    return host, port, reasons


def _policy(grant, binary, substrate, mode):
    endpoint = {"host": grant["host"], "port": grant["port"], "protocol": mode}
    if mode == "mcp":
        allow = {"method": grant["method"]}
        if "tool" in grant:
            allow["tool"] = grant["tool"]
        endpoint["enforcement"] = "enforce"
        endpoint["rules"] = [{"allow": allow}]
    return {
        "version": POLICY_SCHEMA_VERSION,
        "filesystem_policy": {
            "include_workdir": False,
            "read_only": [item["path"] for item in substrate if item["operation"] == "read"],
            "read_write": [item["path"] for item in substrate if item["operation"] == "write"],
        },
        "landlock": {"compatibility": "hard_requirement"},
        "network_policies": {
            grant["requirementId"]: {
                "endpoints": [endpoint],
                "binaries": [{"path": binary}],
            }
        },
    }


def _surface(policy, substrate):
    if not isinstance(policy, dict) or set(policy) != {"version", "filesystem_policy", "landlock", "network_policies"}:
        return ["unexpected_policy_fields"]
    filesystem = policy.get("filesystem_policy") or {}
    if filesystem.get("include_workdir") is not False:
        return ["workdir_implicitly_added"]
    reads = [item["path"] for item in substrate if item["operation"] == "read"]
    writes = [item["path"] for item in substrate if item["operation"] == "write"]
    if filesystem.get("read_only") != reads or filesystem.get("read_write") != writes:
        return ["filesystem_authority_mismatch"]
    return []


def _tcp_endpoint(policy, grant, binary):
    unpacked = _one_endpoint(policy, binary)
    if unpacked[0] is None:
        return unpacked[1]
    endpoint, _found = unpacked
    reasons = []
    allowed = {"host", "port", "protocol"}
    if set(endpoint) != allowed:
        reasons.append("unexpected_endpoint_field")
    if endpoint.get("protocol") != "tcp":
        reasons.append("protocol_not_tcp")
    if endpoint.get("host") != grant["host"]:
        reasons.append("host_widened")
    if endpoint.get("port") != grant["port"]:
        reasons.append("port_widened")
    if "rules" in endpoint or "enforcement" in endpoint or "access" in endpoint or endpoint.get("tls") == "skip":
        reasons.append("tcp_does_not_carry_application_authority")
    return reasons


def _mcp_endpoint(policy, grant, binary):
    unpacked = _one_endpoint(policy, binary)
    if unpacked[0] is None:
        return unpacked[1]
    endpoint, _found = unpacked
    reasons = []
    if endpoint.get("protocol") != "mcp":
        reasons.append("protocol_not_mcp")
    if endpoint.get("enforcement") != "enforce":
        reasons.append("enforcement_not_enforce")
    if endpoint.get("access") is not None or endpoint.get("tls") == "skip":
        reasons.append("access_preset_widens" if endpoint.get("access") is not None else "tls_inspection_disabled")
    if endpoint.get("host") != grant["host"]:
        reasons.append("host_widened")
    if endpoint.get("port") != grant["port"]:
        reasons.append("port_widened")
    rules = endpoint.get("rules")
    if not isinstance(rules, list) or len(rules) != 1 or set(rules[0]) != {"allow"}:
        return reasons + ["method_not_exact"]
    allow = rules[0]["allow"]
    if not isinstance(allow, dict) or allow.get("method") != grant["method"]:
        reasons.append("method_widened")
    if grant.get("tool"):
        if allow.get("tool") != grant["tool"] or not isinstance(allow.get("tool"), str):
            reasons.append("tool_widened")
    elif "tool" in allow:
        reasons.append("tool_widened")
    if isinstance(allow.get("tool"), dict) or (isinstance(allow.get("method"), str) and "*" in allow.get("method")):
        reasons.append("tool_widened")
    return reasons


def _one_endpoint(policy, binary):
    rules = policy.get("network_policies") if isinstance(policy, dict) else None
    if not isinstance(rules, dict) or len(rules) != 1:
        return None, ["endpoint_outside_grant"]
    name, rule = next(iter(rules.items()))
    if str(name).startswith("_provider_"):
        return None, ["provider_authority_not_a_grant"]
    if not isinstance(rule, dict) or set(rule) - {"name"} != {"endpoints", "binaries"}:
        return None, ["unexpected_rule_fields"]
    if "name" in rule and rule.get("name") != name:
        return None, ["unexpected_rule_fields"]
    endpoints = rule.get("endpoints") or []
    if len(endpoints) != 1 or not isinstance(endpoints[0], dict):
        return None, ["endpoint_outside_grant"]
    if rule.get("binaries") != [{"path": binary}]:
        return None, ["binary_restriction_widened"]
    return endpoints[0], []


def _yaml(policy, mode):
    filesystem = policy["filesystem_policy"]
    lines = [
        "version: 1",
        "filesystem_policy:",
        "  include_workdir: false",
        "  read_only:",
    ]
    lines.extend(f"    - {path}" for path in filesystem["read_only"])
    lines.append("  read_write:")
    lines.extend(f"    - {path}" for path in filesystem["read_write"])
    lines.extend(["landlock:", "  compatibility: hard_requirement", "network_policies:"])
    for name, rule in policy["network_policies"].items():
        endpoint = rule["endpoints"][0]
        lines.append(f"  {name}:")
        lines.append("    endpoints:")
        lines.append(f"      - host: {endpoint['host']}")
        lines.append(f"        port: {endpoint['port']}")
        lines.append(f"        protocol: {mode}")
        if mode == "mcp":
            allow = endpoint["rules"][0]["allow"]
            lines.append("        enforcement: enforce")
            lines.append("        rules:")
            lines.append(f"          - allow:")
            lines.append(f"              method: {allow['method']}")
            if "tool" in allow:
                lines.append(f"              tool: {allow['tool']}")
        lines.append(f"    binaries:")
        lines.append(f"      - path: {rule['binaries'][0]['path']}")
    return "\n".join(lines) + "\n"


def _profile_binary(profile):
    rest = _rest_module()
    return rest._profile_binary(profile)


def _glob_widens(value):
    return any(char in value for char in "*?[]")


def _unique(items):
    found = []
    for item in items:
        if item not in found:
            found.append(item)
    return found


def _rest_module():
    path = Path(__file__).with_name("rest.py")
    spec = importlib.util.spec_from_file_location("openshell_rest_for_slices", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
