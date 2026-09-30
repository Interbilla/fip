#!/usr/bin/env python3
"""Q13 adversarial campaign runner.

Q13A is the semantic-regression gate. Later phases are not started when
that gate fails. This runner does not change FIP semantics, the pinned
adapter, or frozen evidence.
"""

from __future__ import annotations

import copy
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
Q13 = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project  # noqa: E402

BASELINE = "6435895898dd089ad545941fa226eb1c0a6860a9"
OPENSHELL_VERSION = "0.1.2"
OPENSHELL_COMMIT = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
RUN_ID = "q13-run-3"
NON_VALID_STATES = ("expired", "revoked", "superseded", "not-yet-valid")
VALIDITY_CODES = {
    "expired": "validity_expired",
    "revoked": "validity_revoked",
    "superseded": "validity_superseded",
    "not-yet-valid": "validity_not_yet_valid",
}
FROZEN_01_PRIMITIVES = [
    "Actor", "Resource", "Role", "Identity", "Credential", "Request", "Response",
    "Action", "Assertion", "Recommendation", "Instruction", "Delegation", "Decision",
    "Purpose", "Condition", "Constraint", "Authority", "Authorization", "Permission",
    "Prohibition", "Obligation", "Policy", "Evidence", "Provenance", "Validity", "Scope",
]
FROZEN_01_RELATIONS = [
    "requests", "respondsTo", "usesResource", "hasPurpose", "hasIdentity",
    "presentsCredential", "hasRole", "ownedBy", "controlledBy", "actsUnderAuthority",
    "authorizedBy", "governedBy", "permits", "prohibits", "obligates", "constrainedBy",
    "appliesWithin", "validDuring", "delegatesTo", "delegatesAuthority", "hasEvidence",
    "derivedFrom", "assertedBy", "decidedBy",
]


def _load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _adapter():
    import importlib.util

    path = ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "adapter.py"
    spec = importlib.util.spec_from_file_location("openshell_adapter_q13", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case(case_id, expected, actual, ok, note, semantic=None, compilation=None, runtime="UNOBSERVED"):
    return {
        "id": case_id,
        "expected": expected,
        "actual": actual,
        "experimental": "PASS" if ok else "FAIL",
        "semantic": semantic,
        "compilation": compilation,
        "runtime": runtime,
        "note": note,
    }


def _exchange(exchange_type, **extra):
    document = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "semantic-only",
        "exchangeId": "q13-" + exchange_type.lower(),
        "exchangeType": exchange_type,
        "actor": {"id": "agent-field"},
        "resource": {"id": "mission:InspectionInput"},
        "action": "ReadInspectionInput",
        "purpose": "FieldInspection",
        "authority": {"id": "auth-mission-control", "kind": "direct"},
        "authorization": {"id": "az-1", "validity": "valid"},
        "provenance": {
            "assertedBy": "mission-control",
            "derivedFrom": ["q13"],
            "independent": True,
            "traceId": "trace-q13",
        },
    }
    document.update(extra)
    return document


def _compile(document):
    adapter = _adapter()
    projected = project(document)
    ir = projected.get("operationalIr")
    if ir is None:
        return projected, None, None
    manifest = _load("reference/fip-0.2/targets/openshell/manifest.json")
    profile = _load("reference/fip-0.2/targets/openshell/execution-profile.json")
    coverage = assess_coverage(ir, manifest, profile, document=document)
    compiled = adapter.compile_policy(ir, coverage, manifest, profile, document=document)
    return projected, coverage, compiled


def phase_a():
    cases = []
    vocabulary = _load("docs/specification/fip-0.2/vocabulary/fip-0.2.jsonld")
    primitives = vocabulary["primitives"]
    relations = vocabulary["relations"]
    cases.append(_case(
        "primitive-count",
        "28",
        str(len(primitives)),
        primitives == FROZEN_01_PRIMITIVES + ["ExecutionBinding", "EnforcementRequirement"],
        "FIP 0.2 adds ExecutionBinding and EnforcementRequirement after the frozen 26.",
        semantic="AUTHORIZED" if len(primitives) == 28 else "REVIEW",
    ))
    cases.append(_case(
        "relationship-count",
        "26",
        str(len(relations)),
        relations == FROZEN_01_RELATIONS + ["hasExecutionBinding", "requiresEnforcement"],
        "FIP 0.2 adds hasExecutionBinding and requiresEnforcement after the frozen 24.",
    ))
    vector_count = len(list((ROOT / "conformance" / "vectors").glob("*.json")))
    cases.append(_case(
        "frozen-conformance-vectors",
        "47",
        str(vector_count),
        vector_count == 47,
        "FIP 0.1 vector files are counted, not relabeled as FIP 0.2 evidence.",
    ))

    prohibition = assess(_load("examples/fip-0.2/prohibition.json"))
    cases.append(_case(
        "prohibition-dominance",
        "DENIED",
        prohibition["authorityDecision"],
        prohibition["authorityDecision"] == "DENIED" and "prohibition_dominates" in prohibition["codes"],
        "A permit and a prohibition on the same action resolve to DENIED.",
        semantic=prohibition["authorityDecision"],
        compilation=prohibition["compilationDisposition"],
    ))

    missing_authority = copy.deepcopy(_load("examples/fip-0.2/openshell-filesystem-read-write.json"))
    missing_authority["authorities"] = []
    missing_result = assess(missing_authority)
    missing_ir = project(missing_authority)["operationalIr"]
    cases.append(_case(
        "missing-authority",
        "INCOMPLETE",
        missing_result["authorityDecision"],
        missing_result["authorityDecision"] == "INCOMPLETE"
        and "missing_authority" in missing_result["codes"]
        and missing_ir is None,
        "An empty authority list is not permission and does not project an operational IR.",
        semantic=missing_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    missing_binding = copy.deepcopy(_load("examples/fip-0.2/openshell-filesystem-read-write.json"))
    missing_binding["executionBindings"] = []
    binding_result = assess(missing_binding)
    cases.append(_case(
        "missing-binding",
        "INCOMPLETE",
        binding_result["authorityDecision"],
        binding_result["authorityDecision"] == "INCOMPLETE"
        and "missing_execution_binding" in binding_result["codes"]
        and project(missing_binding)["operationalIr"] is None,
        "A permit that names a missing binding is not execution authorization.",
        semantic=binding_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    obligation = copy.deepcopy(_load("examples/fip-0.2/openshell-filesystem-read-write.json"))
    obligation["authorizations"] = []
    obligation["obligations"] = [{"obligationId": "ob-read", "requirementIds": ["req-read"]}]
    obligation_result = assess(obligation)
    cases.append(_case(
        "obligation-is-not-authority",
        "INCOMPLETE",
        obligation_result["authorityDecision"],
        obligation_result["authorityDecision"] == "INCOMPLETE"
        and "obligation_is_not_authority" in obligation_result["codes"]
        and project(obligation)["operationalIr"] is None,
        "An obligation without an authorization does not project an operational IR.",
        semantic=obligation_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    approval = _load("examples/fip-0.2/human-approval.json")
    approval_result = assess(approval)
    approval_projected = project(approval)
    cases.append(_case(
        "require-approval-blocks-projection",
        "no operational IR",
        "IR present" if approval_projected["operationalIr"] else "no operational IR",
        approval_result["authorityDecision"] == "AUTHORIZED"
        and "approval_required" in approval_result["codes"]
        and approval_projected["operationalIr"] is None,
        "require-approval may record AUTHORIZED with approval_required, and projection stops until a valid Decision exists.",
        semantic=approval_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    foreign = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "q13-foreign-decision",
        "exchangeType": "Decision",
        "policyId": "pol-approval",
        "traceId": "trace-approval",
        "actor": {"id": "foreign-approver"},
        "decision": {
            "kind": "approval",
            "value": "approved",
            "requirementId": "req-delete",
            "validity": {"state": "valid"},
        },
        "provenance": {
            "assertedBy": "foreign-enterprise",
            "derivedFrom": ["q13-synthetic"],
            "independent": True,
            "traceId": "trace-foreign",
        },
        "evidenceLabel": "synthetic-foreign-decision",
    }
    foreign_projected = project(approval, approvals=[foreign])
    cases.append(_case(
        "foreign-decision-is-not-local-authorization",
        "no operational IR",
        "IR present" if foreign_projected["operationalIr"] else "no operational IR",
        foreign_projected["operationalIr"] is None,
        "A Decision whose actor is outside approverIds does not satisfy require-approval. The Decision object is synthetic.",
        semantic=foreign_projected["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    filesystem = _load("examples/fip-0.2/openshell-filesystem-read-write.json")
    projected, coverage, compiled = _compile(filesystem)
    grants = (coverage or {}).get("coverage", {}).get("fipGrants") or []
    substrate = (compiled or {}).get("substrateMappings") or []
    substrate_sources = {item.get("source") for item in substrate}
    substrate_paths = [item.get("path") for item in substrate if item.get("path")]
    grant_ids = [item if isinstance(item, str) else item.get("requirementId") for item in grants]
    substrate_in_grants = [path for path in substrate_paths if path in grant_ids]
    cases.append(_case(
        "substrate-is-not-a-fip-grant",
        "substrate source execution-substrate and absent from fipGrants",
        "sources=%s substrateInGrants=%s" % (
            ",".join(sorted(str(item) for item in substrate_sources)),
            ",".join(substrate_in_grants) or "none",
        ),
        compiled is not None
        and compiled.get("deployable") is True
        and substrate_sources == {"execution-substrate"}
        and "/usr" in substrate_paths
        and "/tmp" in substrate_paths
        and not substrate_in_grants,
        "Accepted substrate paths such as /usr and /tmp are compiled beside the grant. They are not fipGrant identifiers. Run 1 treated those paths as leakage; that oracle was a harness bug and is preserved under q13-run-1.",
        semantic=projected["authorityDecision"],
        compilation=(compiled or {}).get("compilationDisposition"),
        runtime=(compiled or {}).get("runtimeDisposition", "UNOBSERVED"),
    ))

    target_policy = copy.deepcopy(filesystem)
    target_policy["filesystem_policy"] = {"include_workdir": True}
    target_projected = project(target_policy)
    cases.append(_case(
        "target-policy-is-not-a-fip-grant",
        "no operational IR",
        "IR present" if target_projected["operationalIr"] else "no operational IR",
        target_projected["operationalIr"] is None
        and "author_supplied_target_field" in target_projected["reasons"],
        "An embedded filesystem policy does not become an operational projection.",
        semantic=target_projected["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    prover = _exchange(
        "Request",
        extensions={"decision": "PROVER_PASS"},
        evidenceLabel="synthetic-prover-pass",
    )
    prover_result = assess(prover)
    cases.append(_case(
        "prover-pass-is-not-a-fip-grant",
        "DENIED",
        prover_result["authorityDecision"],
        prover_result["authorityDecision"] == "DENIED"
        and "extension_cannot_grant_authority" in prover_result["codes"],
        "Synthetic PROVER_PASS evidence in a protected extension is not a FIP authorization. No prover CLI was executed.",
        semantic=prover_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    auto = _exchange(
        "Request",
        extensions={"authority": "NVIDIA_AUTO_APPROVED"},
        evidenceLabel="synthetic-advisor-auto-approval",
    )
    auto_result = assess(auto)
    cases.append(_case(
        "automatic-target-approval-is-not-a-fip-grant",
        "DENIED",
        auto_result["authorityDecision"],
        auto_result["authorityDecision"] == "DENIED"
        and "extension_cannot_grant_authority" in auto_result["codes"],
        "Synthetic NVIDIA_AUTO_APPROVED evidence is not a FIP Decision. No Advisor CLI was executed.",
        semantic=auto_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    openshell_approved = _exchange(
        "Request",
        extensions={"authority": "OPENSHELL_APPROVED"},
        evidenceLabel="synthetic-target-approval",
    )
    openshell_result = assess(openshell_approved)
    cases.append(_case(
        "target-approval-is-not-a-fip-grant",
        "DENIED",
        openshell_result["authorityDecision"],
        openshell_result["authorityDecision"] == "DENIED"
        and "extension_cannot_grant_authority" in openshell_result["codes"],
        "Synthetic OPENSHELL_APPROVED evidence is not a FIP Decision.",
        semantic=openshell_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    expired_authorization = copy.deepcopy(filesystem)
    expired_authorization["authorizations"][0]["validity"] = {"state": "expired"}
    expired_authorization_result = assess(expired_authorization)
    cases.append(_case(
        "expired-authorization-validity",
        "DENIED",
        expired_authorization_result["authorityDecision"],
        expired_authorization_result["authorityDecision"] == "DENIED"
        and "validity_expired" in expired_authorization_result["codes"]
        and project(expired_authorization)["operationalIr"] is None,
        "Authorization validity expired denies the grant and blocks projection. This is the working validity control.",
        semantic=expired_authorization_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    expired_policy = copy.deepcopy(filesystem)
    expired_policy["validity"] = {"state": "expired"}
    expired_policy_result = assess(expired_policy)
    expired_projected, expired_coverage, expired_compiled = _compile(expired_policy)
    emitted = bool(expired_compiled and expired_compiled.get("generatedPolicy") and expired_compiled.get("deployable"))
    cases.append(_case(
        "expired-policy-validity",
        "DENIED",
        expired_policy_result["authorityDecision"],
        expired_policy_result["authorityDecision"] == "DENIED"
        and "validity_expired" in expired_policy_result["codes"]
        and "policy_validity" in expired_policy_result["reasons"]
        and expired_projected["operationalIr"] is None
        and not emitted,
        "AuthorityPolicy.validity expired is denied. No operational IR is projected and no deployable target policy is emitted. "
        "The historical run-2 result was AUTHORIZED with a deployable policy.",
        semantic=expired_policy_result["authorityDecision"],
        compilation=(expired_compiled or {}).get("compilationDisposition") or expired_projected["compilationDisposition"],
        runtime=(expired_compiled or {}).get("runtimeDisposition", "UNOBSERVED"),
    ))

    expired_delegation = _exchange(
        "Delegation",
        delegation={"canDelegate": True, "authorityId": "auth-mission-control"},
        authority={"id": "auth-mission-control", "kind": "delegable"},
        validity={"state": "expired"},
    )
    expired_delegation_result = assess(expired_delegation)
    cases.append(_case(
        "expired-delegation-exchange",
        "DENIED",
        expired_delegation_result["authorityDecision"],
        expired_delegation_result["authorityDecision"] == "DENIED"
        and "validity_expired" in expired_delegation_result["codes"]
        and project(expired_delegation)["operationalIr"] is None,
        "A Delegation exchange carrying validity expired is denied. The historical run-2 result was AUTHORIZED.",
        semantic=expired_delegation_result["authorityDecision"],
        compilation=expired_delegation_result["compilationDisposition"],
    ))

    for state in NON_VALID_STATES:
        if state == "expired":
            continue
        varied_policy = copy.deepcopy(filesystem)
        varied_policy["validity"] = {"state": state}
        varied_policy_result = assess(varied_policy)
        varied_compiled_ir = project(varied_policy)["operationalIr"]
        cases.append(_case(
            "policy-validity-" + state,
            "DENIED",
            varied_policy_result["authorityDecision"],
            varied_policy_result["authorityDecision"] == "DENIED"
            and VALIDITY_CODES[state] in varied_policy_result["codes"]
            and "policy_validity" in varied_policy_result["reasons"]
            and varied_compiled_ir is None,
            "AuthorityPolicy.validity %s denies use of the policy and blocks the operational IR." % state,
            semantic=varied_policy_result["authorityDecision"],
            compilation="NOT_COMPILED",
        ))
        varied_delegation = _exchange(
            "Delegation",
            delegation={"canDelegate": True, "authorityId": "auth-mission-control"},
            authority={"id": "auth-mission-control", "kind": "delegable"},
            validity={"state": state},
        )
        varied_delegation_result = assess(varied_delegation)
        cases.append(_case(
            "delegation-exchange-validity-" + state,
            "DENIED",
            varied_delegation_result["authorityDecision"],
            varied_delegation_result["authorityDecision"] == "DENIED"
            and VALIDITY_CODES[state] in varied_delegation_result["codes"],
            "Delegation exchange validity %s denies the delegation act." % state,
            semantic=varied_delegation_result["authorityDecision"],
            compilation="NOT_COMPILED",
        ))

    absent_policy = copy.deepcopy(filesystem)
    del absent_policy["validity"]
    absent_policy_result = assess(absent_policy)
    cases.append(_case(
        "policy-validity-absent",
        "INCOMPLETE",
        absent_policy_result["authorityDecision"],
        absent_policy_result["authorityDecision"] == "INCOMPLETE"
        and "validity" in absent_policy_result["reasons"]
        and project(absent_policy)["operationalIr"] is None,
        "AuthorityPolicy.validity is required. Absence is incomplete, which is distinct from a non-valid state.",
        semantic=absent_policy_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    absent_authorization = copy.deepcopy(filesystem)
    del absent_authorization["authorizations"][0]["validity"]
    absent_authorization_result = assess(absent_authorization)
    cases.append(_case(
        "authorization-validity-absent",
        "AUTHORIZED",
        absent_authorization_result["authorityDecision"],
        absent_authorization_result["authorityDecision"] == "AUTHORIZED",
        "Authorization validity is optional. Absence keeps the current usable authorization.",
        semantic=absent_authorization_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))

    valid_decision = {
        "fipVersion": "0.2",
        "document": "Exchange",
        "status": "ENFORCEMENT CANDIDATE",
        "mode": "operational",
        "exchangeId": "q13-valid-decision",
        "exchangeType": "Decision",
        "policyId": "pol-approval",
        "traceId": "trace-approval",
        "actor": {"id": "approver-mission"},
        "decision": {
            "kind": "approval",
            "value": "approved",
            "requirementId": "req-delete",
            "validity": {"state": "valid"},
        },
        "provenance": {
            "assertedBy": "approver-mission",
            "derivedFrom": ["q13"],
            "independent": True,
            "traceId": "trace-approval",
        },
    }
    valid_decision_result = assess(valid_decision)
    satisfied = assess(approval, approvals=[valid_decision])
    cases.append(_case(
        "valid-approval-decision",
        "AUTHORIZED",
        valid_decision_result["authorityDecision"],
        valid_decision_result["authorityDecision"] == "AUTHORIZED"
        and valid_decision_result.get("approvalRecord") is True
        and valid_decision_result["deployable"] is False
        and "approval_required" not in satisfied["codes"],
        "A valid approval Decision records approval and satisfies require-approval. It is not a deployable policy.",
        semantic=valid_decision_result["authorityDecision"],
        compilation="NOT_COMPILED",
    ))
    for state in NON_VALID_STATES:
        invalid_decision = copy.deepcopy(valid_decision)
        invalid_decision["decision"]["validity"] = {"state": state}
        invalid_decision_result = assess(invalid_decision)
        still_waiting = assess(approval, approvals=[invalid_decision])
        cases.append(_case(
            "approval-decision-validity-" + state,
            "DENIED",
            invalid_decision_result["authorityDecision"],
            invalid_decision_result["authorityDecision"] == "DENIED"
            and VALIDITY_CODES[state] in invalid_decision_result["codes"]
            and "approval_required" in still_waiting["codes"]
            and project(approval, approvals=[invalid_decision])["operationalIr"] is None,
            "Approval Decision validity %s does not establish authorization and does not satisfy require-approval." % state,
            semantic=invalid_decision_result["authorityDecision"],
            compilation="NOT_COMPILED",
        ))

    return cases


def _gate(cases):
    failed = [item["id"] for item in cases if item["experimental"] == "FAIL"]
    return {
        "gate": "FAIL" if failed else "PASS",
        "failedCaseIds": failed,
        "passCount": sum(1 for item in cases if item["experimental"] == "PASS"),
        "failCount": len(failed),
    }


def _run(command):
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return {
        "command": command[1:],
        "exitCode": completed.returncode,
        "stdoutTail": "\n".join((completed.stdout or "").splitlines()[-8:]),
        "stderrTail": "\n".join((completed.stderr or "").splitlines()[-8:]),
    }


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _report_a(cases, gate, commands):
    lines = [
        "# Q13A semantic regression",
        "",
        "Run id: `%s`" % RUN_ID,
        "",
        "Baseline commit: `%s`" % BASELINE,
        "",
        "OpenShell pin: v%s `%s`" % (OPENSHELL_VERSION, OPENSHELL_COMMIT),
        "",
        "Gate: **%s**" % gate["gate"],
        "",
        "Passed cases: %s. Failed cases: %s." % (gate["passCount"], gate["failCount"]),
        "",
        "Q13B, Q13C, and Q13D were not started.",
        "",
        "## Cases",
        "",
        "| Case | Expected | Actual | Result |",
        "| --- | --- | --- | --- |",
    ]
    for item in cases:
        lines.append("| %s | %s | %s | %s |" % (item["id"], item["expected"], item["actual"], item["experimental"]))
    lines.extend(["", "## Notes", ""])
    for item in cases:
        lines.append("- `%s`: %s" % (item["id"], item["note"]))
    lines.extend(["", "## Command tails", ""])
    for item in commands:
        lines.append("- exit %s: `%s`" % (item["exitCode"], " ".join(item["command"])))
        if item["stdoutTail"]:
            lines.append("")
            lines.append("```")
            lines.append(item["stdoutTail"])
            lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _not_run(phase, reason):
    return "\n".join([
        "# %s" % phase,
        "",
        "Status: NOT_RUN",
        "",
        reason,
        "",
        "Run id that stopped the campaign: `%s`" % RUN_ID,
        "",
    ])


def main():
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cases = phase_a()
    gate = _gate(cases)
    commands = [
        _run([sys.executable, "conformance/runners/python_runner.py"]),
        _run(["node", "conformance/runners/javascript-runner.js"]),
    ]
    environment = {
        "runId": RUN_ID,
        "startedAt": started,
        "baselineCommit": BASELINE,
        "openshellVersion": OPENSHELL_VERSION,
        "openshellCommit": OPENSHELL_COMMIT,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "proverCli": "not-executed",
        "advisorCli": "not-executed",
        "sentry": "FUTURE_TARGET_CANDIDATE",
        "liveSandbox": "not-started",
    }
    changed = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    environment.update({
        "prospectiveSource": "uncommitted post-fix working tree",
        "baselineCommit": BASELINE,
        "fixReason": "Apply the existing non-valid Validity rule to AuthorityPolicy and to authority-relevant exchanges. Run-2 preserved the failures.",
        "preservedFailure": "docs/evidence/fip-0.2/q13/q13a-semantic-regression/q13-run-2/report.md",
        "filesChanged": [line for line in (changed.stdout or "").splitlines() if line],
        "filesUntracked": [line for line in (untracked.stdout or "").splitlines() if line],
    })
    payload = {"environment": environment, "gate": gate, "cases": cases, "commands": commands}
    _write(Q13 / "q13a-semantic-regression" / "results.json", json.dumps(payload, indent=2) + "\n")
    _write(Q13 / "q13a-semantic-regression" / "report.md", _report_a(cases, gate, commands))
    _write(Q13 / "q13a-semantic-regression" / RUN_ID / "results.json", json.dumps(payload, indent=2) + "\n")
    _write(Q13 / "q13a-semantic-regression" / RUN_ID / "report.md", _report_a(cases, gate, commands))
    if gate["gate"] == "PASS":
        reason = (
            "Q13A run %s passed. This step stops for review and does not start Q13B, Q13C, or Q13D."
            % RUN_ID
        )
    else:
        reason = (
            "Q13A gate is %s. Failed cases: %s. "
            "The campaign stops before static, runtime, and combinatorial attacks."
            % (gate["gate"], ", ".join(gate["failedCaseIds"]) or "none")
        )
    _write(Q13 / "q13b-static-enforcement" / "NOT_RUN.md", _not_run("Q13B static enforcement adversary", reason))
    _write(Q13 / "q13c-runtime-authority" / "NOT_RUN.md", _not_run("Q13C runtime authority evolution", reason))
    _write(Q13 / "q13d-combinatorial" / "NOT_RUN.md", _not_run("Q13D combinatorial campaign", reason))
    print(json.dumps({"gate": gate, "commands": [{k: item[k] for k in ("exitCode", "command")} for item in commands]}, indent=2))
    return 0 if gate["gate"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
