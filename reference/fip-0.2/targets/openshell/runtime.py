"""OpenShell v0.1.2 runtime correlation for the filesystem slice.

This module does not decide semantic authority and does not widen a policy.
The sandbox runner lives in integration/openshell-m4/run_m4.py so the portable
unit suite can import these helpers without an OpenShell installation.

Canonical policy representation: UTF-8 JSON, object keys sorted, separators
(",", ":"), ensure_ascii true, no trailing newline. YAML comments and key
order are not part of the hash.
"""

from __future__ import annotations

import hashlib
import json

PINNED_VERSION = "0.1.2"
PINNED_COMMIT = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
DENIAL_ERRNOS = {1, 13}  # EPERM, EACCES

PROBES = (
    {
        "id": "authorized-read",
        "operation": "read",
        "path": "/mission/input/input.txt",
        "expect": "allow",
        "authorityClass": "fip-grant",
        "requirementId": "req-read",
        "bindingId": "in-read",
        "critical": False,
    },
    {
        "id": "authorized-write",
        "operation": "write",
        "path": "/mission/output/result.txt",
        "expect": "allow",
        "authorityClass": "fip-grant",
        "requirementId": "req-write",
        "bindingId": "out-write",
        "critical": False,
    },
    {
        "id": "unauthorized-input-write",
        "operation": "write",
        "path": "/mission/input/unauthorized.txt",
        "expect": "deny",
        "authorityClass": "unauthorized",
        "requirementId": None,
        "bindingId": None,
        "critical": True,
    },
    {
        "id": "unauthorized-unrelated-read",
        "operation": "read",
        "path": "/mission/unrelated/secret.txt",
        "expect": "deny",
        "authorityClass": "unauthorized",
        "requirementId": None,
        "bindingId": None,
        "critical": False,
    },
    {
        "id": "unauthorized-unrelated-write",
        "operation": "write",
        "path": "/mission/unrelated/unauthorized.txt",
        "expect": "deny",
        "authorityClass": "unauthorized",
        "requirementId": None,
        "bindingId": None,
        "critical": True,
    },
    {
        "id": "critical-input-write",
        "operation": "write",
        "path": "/mission/input/should-fail.txt",
        "expect": "deny",
        "authorityClass": "unauthorized",
        "requirementId": None,
        "bindingId": None,
        "critical": True,
    },
    {
        "id": "critical-unrelated-write",
        "operation": "write",
        "path": "/mission/unrelated/should-fail.txt",
        "expect": "deny",
        "authorityClass": "unauthorized",
        "requirementId": None,
        "bindingId": None,
        "critical": True,
    },
    {
        "id": "substrate-tmp-write",
        "operation": "write",
        "path": "/tmp/fip-m4-test.txt",
        "expect": "allow",
        "authorityClass": "execution-substrate",
        "requirementId": None,
        "bindingId": None,
        "substrateId": "runtime-tmp",
        "critical": False,
    },
    {
        "id": "substrate-etc-read",
        "operation": "read",
        "path": "/etc/os-release",
        "expect": "allow",
        "authorityClass": "execution-substrate",
        "requirementId": None,
        "bindingId": None,
        "substrateId": "runtime-etc",
        "critical": False,
    },
    {
        "id": "workdir-read",
        "operation": "read",
        "path": "/sandbox/only-via-workdir.txt",
        "expect": "deny",
        "authorityClass": "implicit-workdir",
        "requirementId": None,
        "bindingId": None,
        "critical": False,
    },
)


def canonical_policy_bytes(policy):
    return json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_policy_hash(policy):
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def version_accepted(reported_version, reported_commit=None):
    """True only for the pinned release. A different exposed commit is rejected."""
    if reported_version != PINNED_VERSION:
        return False
    if reported_commit and not reported_commit.startswith(PINNED_COMMIT):
        return False
    return True


def covers(root, path):
    if not isinstance(root, str) or not isinstance(path, str):
        return False
    if path == root:
        return True
    prefix = root.rstrip("/")
    return path.startswith(prefix + "/")


def covering_rules(mappings, operation, path):
    found = []
    for item in mappings or []:
        if item.get("operation") != operation:
            continue
        if covers(item.get("path"), path):
            found.append(item)
    return found


def interpret_probe(spec, observation):
    """Map one workload observation to a runtime disposition.

    ENOENT is not an enforcement denial. A successful unauthorized write is a
    monotonicity violation. Substrate success is not a FIP grant.
    """
    outcome = observation.get("outcome")
    errno_value = observation.get("errno")
    if spec["expect"] == "allow" and outcome == "success":
        disposition = "ENFORCED_ALLOW"
        classification = "enforced-allow" if spec["authorityClass"] == "fip-grant" else "substrate-observation"
        if spec["authorityClass"] == "implicit-workdir":
            classification = "monotonicity-violation"
        passed = spec["authorityClass"] != "implicit-workdir"
        return _judgment(spec, disposition, classification, passed, observation)
    if spec["expect"] == "deny" and outcome == "failure" and errno_value in DENIAL_ERRNOS:
        return _judgment(spec, "ENFORCED_DENY", "enforcement-denial", True, observation)
    if spec["expect"] == "deny" and outcome == "success":
        return _judgment(spec, "ENFORCED_ALLOW", "monotonicity-violation", False, observation)
    if outcome == "failure" and errno_value not in DENIAL_ERRNOS:
        kind = "evidence-failure" if spec["expect"] == "deny" else "workload-failure"
        return _judgment(spec, "UNOBSERVED", kind, False, observation)
    return _judgment(spec, "UNOBSERVED", "workload-failure", False, observation)


def _judgment(spec, disposition, classification, passed, observation):
    return {
        "probe": spec["id"],
        "passed": passed,
        "runtimeDisposition": disposition,
        "classification": classification,
        "authorityClass": spec["authorityClass"],
        "fipGrant": spec["authorityClass"] == "fip-grant" and disposition == "ENFORCED_ALLOW" and passed,
        "critical": spec["critical"],
        "errno": observation.get("errno"),
        "errnoName": observation.get("errnoName"),
    }


def correlation_record(spec, observation, adapter_result, policy_hash, target_evidence):
    """FIP-side correlation. Target-native evidence stays in its own object."""
    requirement_id = None
    binding_id = None
    substrate_id = spec.get("substrateId")
    if spec["authorityClass"] == "fip-grant":
        grants = covering_rules(adapter_result.get("ruleMappings"), spec["operation"], spec["path"])
        if len(grants) == 1:
            requirement_id = grants[0]["requirementId"]
            binding_id = grants[0]["bindingId"]
    if spec["authorityClass"] == "execution-substrate":
        rows = covering_rules(
            [item for item in adapter_result.get("substrateMappings") or [] if item.get("emitted")],
            spec["operation"],
            spec["path"],
        )
        if len(rows) == 1:
            substrate_id = rows[0]["substrateId"]
    return {
        "recordType": "fip-runtime-correlation",
        "correlationSource": "fip-side",
        "traceId": adapter_result.get("traceId"),
        "policyId": adapter_result.get("policyId"),
        "exchangeId": None,
        "authorizationId": "az-openshell-files",
        "requirementId": requirement_id,
        "bindingId": binding_id,
        "substrateId": substrate_id,
        "adapterId": adapter_result.get("adapterId"),
        "targetPolicyHash": policy_hash,
        "openshellEventId": (target_evidence or {}).get("eventId"),
        "observedOperation": spec["operation"],
        "observedPath": spec["path"],
        "runtimeDisposition": None,
        "authorityClass": spec["authorityClass"],
        "fipGrant": False,
        "observedAt": observation.get("observedAt"),
        "targetNativeEvidence": target_evidence,
    }


def landlock_confirmed(log_text):
    """Require a hard_requirement ruleset on ABI 3 or newer."""
    if not isinstance(log_text, str) or "landlock" not in log_text.lower():
        return False, "landlock event absent"
    lowered = log_text.lower()
    if "hardrequirement" not in lowered.replace("_", "").replace("-", "") and "hard_requirement" not in lowered:
        return False, "hard_requirement not present"
    if "besteffort" in lowered.replace("_", "").replace("-", "") and "hardrequirement" not in lowered.replace("_", ""):
        return False, "best_effort"
    applied = _field(log_text, "rules_applied")
    abi = _field(log_text, "abi")
    if applied is None or int(applied) < 1:
        return False, "no rules applied"
    if abi is None:
        return False, "abi absent"
    abi_number = int(abi.lower().lstrip("v"))
    if abi_number < 3:
        return False, f"abi {abi}"
    return True, f"abi {abi} rules_applied {applied}"


def _field(text, name):
    token = name + ":"
    for line in text.splitlines():
        if token not in line:
            continue
        tail = line.split(token, 1)[1]
        return tail.split()[0].rstrip("]")
    return None
