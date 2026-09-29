"""Run the M3B filesystem policy in pinned OpenShell v0.1.2.

The portable unit suite does not import this runner. Invoke it directly:

    python integration/openshell-m4/run_m4.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference" / "fip-0.2"))

from fip02 import assess, assess_coverage, project  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "openshell_adapter", ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "adapter.py"
)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)
runtime_spec = importlib.util.spec_from_file_location(
    "openshell_runtime", ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "runtime.py"
)
runtime = importlib.util.module_from_spec(runtime_spec)
runtime_spec.loader.exec_module(runtime)

ARTIFACTS = ROOT / "conformance" / "fip-0.2" / "openshell" / "m4"
SANDBOX = "fip-m4-files"
IMAGE = "fip-m4-fixture:local"
DISTRO = "Ubuntu-22.04"


def wsl(script, timeout=180):
    completed = subprocess.run(
        ["wsl", "-d", DISTRO, "--", "bash", "-lc", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode, completed.stdout, completed.stderr


def openshell(args, timeout=180):
    quoted = " ".join(_quote(part) for part in args)
    return wsl(f'export PATH="$HOME/.local/bin:$PATH"; openshell --color never {quoted}', timeout=timeout)


def _quote(part):
    return "'" + part.replace("'", "'\\''") + "'"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def compile_slice():
    document = load(ROOT / "examples" / "fip-0.2" / "openshell-filesystem-read-write.json")
    manifest = load(ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "manifest.json")
    profile = load(ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "execution-profile.json")
    authority = assess(document)
    projected = project(document)
    coverage = assess_coverage(projected["operationalIr"], manifest, profile)
    result = adapter.compile_policy(projected["operationalIr"], coverage, manifest, profile)
    return authority, projected, coverage, result


def preflight():
    code, out, err = openshell(["--version"])
    version_text = (out or err).strip()
    status_code, status_out, status_err = openshell(["status"])
    reported = _version_token(version_text) or _version_token(status_out)
    commit = _commit_token(version_text + "\n" + status_out)
    kernel_code, kernel_out, _kernel_err = wsl("uname -sr")
    docker_code, docker_out, _docker_err = wsl("docker version --format '{{.Server.Version}}'")
    return {
        "cliVersionText": version_text,
        "gatewayStatus": status_out.strip(),
        "reportedVersion": reported,
        "reportedCommit": commit,
        "accepted": runtime.version_accepted(reported, commit) and code == 0 and status_code == 0,
        "kernel": kernel_out.strip() if kernel_code == 0 else None,
        "dockerServer": docker_out.strip() if docker_code == 0 else None,
        "policySchemaVersion": 1,
        "pinnedCommit": runtime.PINNED_COMMIT,
        "commitExposedByBinary": commit is not None,
    }


def _version_token(text):
    for token in text.split():
        if token.startswith("0."):
            return token
    return None


def _commit_token(text):
    for token in text.replace(",", " ").split():
        if len(token) >= 40 and all(char in "0123456789abcdef" for char in token[:40]):
            return token[:40]
    return None


def write_policy(result):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    policy_path = ARTIFACTS / "runtime-policy.yaml"
    policy_path.write_bytes(result["policyYaml"].replace("\r\n", "\n").encode("utf-8"))
    (ARTIFACTS / "generated-policy.json").write_text(
        json.dumps(result["generatedPolicy"], indent=2) + "\n", encoding="utf-8"
    )
    return policy_path


def build_image():
    fixture = (ROOT / "integration" / "openshell-m4" / "fixture").as_posix()
    wsl_path = "/mnt/" + fixture[0].lower() + fixture[2:]
    return wsl(
        "mkdir -p /tmp/fip-m4-docker && printf '%s\\n' '{\"auths\":{}}' > /tmp/fip-m4-docker/config.json && "
        f"DOCKER_CONFIG=/tmp/fip-m4-docker docker build -t {IMAGE} {wsl_path}",
        timeout=600,
    )


def create_sandbox(policy_path):
    openshell(["sandbox", "delete", SANDBOX])
    wsl_policy = _wsl_path(policy_path)
    return openshell(
        [
            "sandbox", "create",
            "--name", SANDBOX,
            "--from", IMAGE,
            "--policy", wsl_policy,
            "--detach",
            "--no-tty",
            "--output", "json",
            "--", "/usr/bin/sleep", "3600",
        ],
        timeout=600,
    )


def _wsl_path(path):
    text = path.resolve().as_posix()
    return "/mnt/" + text[0].lower() + text[2:]


def installed_policy():
    code, out, err = openshell(["policy", "get", SANDBOX, "--base", "--output", "json"], timeout=60)
    if code != 0:
        return None, out + err
    payload = json.loads(_json_blob(out))
    policy = payload.get("policy", payload)
    return policy, out


def _json_blob(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("no json object")
    return text[start:end + 1]


def run_probe(probe_id):
    code, out, err = openshell(
        [
            "sandbox", "exec",
            "-n", SANDBOX,
            "--no-login-shell",
            "--no-tty",
            "--workdir", "/sandbox",
            "--",
            "/usr/bin/python3",
            "/mission/input/probe.py",
            probe_id,
        ],
        timeout=90,
    )
    observation = None
    for line in out.splitlines():
        if line.startswith("{"):
            observation = json.loads(line)
    return code, observation, out, err


def collect_logs():
    script = _wsl_path(ROOT / "integration" / "openshell-m4" / "collect-evidence.sh")
    _code, streamed, err = wsl(f"sed -i 's/\\r$//' {script}; bash {script} {SANDBOX}", timeout=40)
    return _evidence_lines(streamed + "\n" + err)


def _evidence_lines(text):
    keys = (
        "landlock",
        "rules_applied",
        "==== containers",
        "==== docker-logs",
        "docker-list-failed",
        "docker-logs-failed",
        "isolation boundary enforcement",
        "config:loaded",
        "/mission/",
        "/tmp/fip-m4",
        "/sandbox/only-via-workdir",
        "/etc/os-release",
    )
    kept = []
    for line in (text or "").splitlines():
        lowered = line.lower()
        if any(key in lowered for key in keys):
            kept.append(line)
    return "\n".join(kept) + ("\n" if kept else "")


def relevant_lines(log_text, path):
    if not log_text:
        return []
    return [line for line in log_text.splitlines() if path in line or "Landlock" in line]


def main():
    report = {
        "milestone": "M4",
        "sandbox": SANDBOX,
        "image": IMAGE,
        "m4": "FAIL",
        "failureClass": None,
    }
    environment = preflight()
    report["environment"] = environment
    if not environment["accepted"]:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = "OpenShell version does not match the v0.1.2 pin"
        _finish(report, 2)

    authority, projected, coverage, compiled = compile_slice()
    report["authorityDecision"] = authority["authorityDecision"]
    report["coverageDisposition"] = coverage["compilationDisposition"]
    report["coverageDeployable"] = coverage["deployable"]
    report["adapterDisposition"] = compiled["compilationDisposition"]
    report["monotonicity"] = compiled["monotonicity"]
    if authority["authorityDecision"] != "AUTHORIZED" or projected["operationalIr"] is None:
        report["failureClass"] = "authorization-failure"
        _finish(report, 2)
    if coverage["compilationDisposition"] != "FULL" or compiled["compilationDisposition"] != "FULL":
        report["failureClass"] = "compilation-failure"
        _finish(report, 2)
    if compiled["monotonicity"] != "demonstrated" or not compiled["deployable"]:
        report["failureClass"] = "compilation-failure"
        _finish(report, 2)

    policy_path = write_policy(compiled)
    generated_hash = runtime.canonical_policy_hash(compiled["generatedPolicy"])
    report["generatedPolicyHash"] = generated_hash
    build_code, build_out, build_err = build_image()
    if build_code != 0:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = (build_err or build_out)[-2000:]
        _finish(report, 2)

    create_code, create_out, create_err = create_sandbox(policy_path)
    report["sandboxCreate"] = _release_sandbox_create(create_code, create_out, create_err)
    if create_code != 0:
        report["failureClass"] = "policy-installation-failure" if "policy" in (create_err + create_out).lower() else "sandbox-launch-failure"
        _finish(report, 2)

    installed, installed_text = installed_policy()
    if not isinstance(installed, dict):
        report["failureClass"] = "policy-installation-failure"
        report["detail"] = installed_text[-2000:]
        _cleanup()
        _finish(report, 2)
    runtime_hash = runtime.canonical_policy_hash(installed)
    report["runtimePolicyHash"] = runtime_hash
    report["policyMatch"] = installed == compiled["generatedPolicy"]
    (ARTIFACTS / "runtime-policy-readback.json").write_text(json.dumps(installed, indent=2) + "\n", encoding="utf-8")
    if installed != compiled["generatedPolicy"] or runtime_hash != generated_hash:
        report["failureClass"] = "policy-installation-failure"
        _cleanup()
        _finish(report, 2)

    log_text = ""
    results = []
    correlations = []
    stopped = False
    for spec in runtime.PROBES:
        if stopped:
            break
        code, observation, out, err = run_probe(spec["id"])
        if observation is None:
            judgment = {
                "probe": spec["id"],
                "passed": False,
                "runtimeDisposition": "UNOBSERVED",
                "classification": "workload-failure",
                "authorityClass": spec["authorityClass"],
                "fipGrant": False,
                "critical": spec["critical"],
                "detail": (out + err)[-1000:],
                "execCode": code,
            }
        else:
            judgment = runtime.interpret_probe(spec, observation)
            judgment["observation"] = observation
            judgment["execCode"] = code
        evidence = {
            "source": "target-native",
            "eventId": None,
            "ocsfRecord": None,
            "workload": observation,
            "logLines": [],
        }
        record = runtime.correlation_record(spec, observation or {}, compiled, generated_hash, evidence)
        record["runtimeDisposition"] = judgment["runtimeDisposition"]
        record["fipGrant"] = judgment["fipGrant"]
        results.append(judgment)
        correlations.append(record)
        if spec["critical"] and not judgment["passed"]:
            report["failureClass"] = "monotonicity-violation" if judgment["classification"] == "monotonicity-violation" else judgment["classification"]
            stopped = True

    log_text = collect_logs()
    (ARTIFACTS / "openshell.log").write_text(log_text or "", encoding="utf-8")
    confirmed, landlock_detail = runtime.landlock_confirmed(log_text or "")
    report["landlock"] = {"confirmed": confirmed, "detail": landlock_detail}
    for record, spec in zip(correlations, runtime.PROBES[:len(correlations)]):
        lines = [line for line in (log_text or "").splitlines() if spec["path"] in line]
        record["targetNativeEvidence"]["logLines"] = lines
        record["targetNativeEvidence"]["landlock"] = landlock_detail
    report["probes"] = results
    report["correlations"] = correlations
    report["fipGrantSuccessCount"] = sum(1 for item in results if item.get("fipGrant"))
    report["runtimeMonotonicity"] = not any(item.get("classification") == "monotonicity-violation" for item in results)
    if report.get("failureClass") is None and not confirmed:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = "Landlock hard_requirement was not confirmed"
    if report.get("failureClass") is None and not all(item.get("passed") for item in results):
        failed = next(item for item in results if not item.get("passed"))
        report["failureClass"] = failed["classification"]
    if report.get("failureClass") is None and report["fipGrantSuccessCount"] != 2:
        report["failureClass"] = "evidence-failure"
    if report.get("failureClass") is None:
        report["m4"] = "PASS"
    _cleanup()
    _finish(report, 0 if report["m4"] == "PASS" else 1)


def _cleanup():
    openshell(["sandbox", "delete", SANDBOX], timeout=120)


def _release_sandbox_create(code, stdout, _stderr):
    """Keep admission facts. Do not publish gateway tokens or sandbox ids."""
    policy_hash = None
    phase = None
    text = stdout or ""
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            payload = {}
        admission = payload.get("configuration_admission") or {}
        policy_hash = admission.get("policy_hash")
        phase = payload.get("phase")
    return {
        "code": code,
        "phase": phase,
        "openshellPolicyLoadHash": policy_hash,
        "gatewayTokenId": "[redacted]",
        "sandboxId": "[redacted]",
        "runtimeGeneration": "[redacted]",
        "stderr": "Provisioning sandbox (structured output on stdout)..." if code == 0 else "[redacted]",
    }


def _finish(report, code):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "m4-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "m4": report["m4"],
        "failureClass": report.get("failureClass"),
        "detail": report.get("detail"),
        "generatedPolicyHash": report.get("generatedPolicyHash"),
        "runtimePolicyHash": report.get("runtimePolicyHash"),
        "policyMatch": report.get("policyMatch"),
        "landlock": report.get("landlock"),
        "fipGrantSuccessCount": report.get("fipGrantSuccessCount"),
        "probes": [
            {
                "probe": item.get("probe"),
                "passed": item.get("passed"),
                "runtimeDisposition": item.get("runtimeDisposition"),
                "classification": item.get("classification"),
                "errnoName": item.get("errnoName"),
            }
            for item in report.get("probes") or []
        ],
    }, indent=2))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
