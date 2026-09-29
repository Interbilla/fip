"""Run the API-only REST fixture on pinned OpenShell v0.1.2.

The portable unit suite does not import this runner. Invoke it directly:

    python integration/openshell-m5d/run_m5d.py

example.com GET / is a reachable runtime target. It does not replace the
weather.example.com conformance probe. The TCP proxy, when used, is
environment plumbing. It is not a FIP grant.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
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

ARTIFACTS = ROOT / "conformance" / "fip-0.2" / "openshell" / "m5d"
SANDBOX = "fip-m5d-rest"
IMAGE = "fip-m5d-fixture:local"
DISTRO = "Ubuntu-22.04"
DOCUMENT = ROOT / "examples" / "fip-0.2" / "openshell-rest-runtime.json"
CONFORMANCE_HASH = "487cf5c82708397a7a45e48d6d7f2b97d7d948715f235dba215ca2ab53c8b504"
DENIAL_MARKERS = ("policy_denied", "rule_missing", "blocked by policy", "no matching policy", "permission denied")
ORIGIN_MARKER = "Example Domain"


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
    return "'" + str(part).replace("'", "'\\''") + "'"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compile_twice():
    document = load(DOCUMENT)
    manifest = load(ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "manifest.json")
    profile = load(ROOT / "reference" / "fip-0.2" / "targets" / "openshell" / "execution-profile.json")
    authority = assess(document)
    projected = project(document)
    coverage = assess_coverage(projected["operationalIr"], manifest, profile)
    first = adapter.compile_policy(projected["operationalIr"], coverage, manifest, profile)
    second = adapter.compile_policy(projected["operationalIr"], coverage, manifest, profile)
    return document, authority, projected, coverage, first, second


def _version_token(text):
    for token in (text or "").split():
        if token.startswith("0."):
            return token
    return None


def _wsl_path(path):
    text = Path(path).resolve().as_posix()
    return "/mnt/" + text[0].lower() + text[2:]


def ensure_gateway():
    code, out, err = openshell(["status"])
    if code == 0:
        return out.strip(), False
    script = _wsl_path(ROOT / "integration" / "openshell-m4" / "start-gateway.sh")
    wsl(f"sed -i 's/\\r$//' {script}; setsid bash {script} >/tmp/fip-m5d-gateway.log 2>&1 < /dev/null &")
    last = ""
    for _ in range(30):
        time.sleep(1)
        code, out, err = openshell(["status"])
        last = (out or err).strip()
        if code == 0:
            return last, True
    raise RuntimeError("gateway did not become reachable: " + last[-500:])


def preflight(gateway_text, gateway_started):
    code, out, err = openshell(["--version"])
    version_text = (out or err).strip()
    gateway_code, gateway_out, _gateway_err = wsl('export PATH="$HOME/.local/bin:$PATH"; openshell-gateway -V')
    kernel_code, kernel_out, _kernel_err = wsl("uname -sr")
    docker_code, docker_out, _docker_err = wsl("docker version --format '{{.Server.Version}}'")
    reported = _version_token(version_text)
    return {
        "cliVersionText": version_text,
        "gatewayVersionText": (gateway_out or "").strip() if gateway_code == 0 else None,
        "gatewayStatus": gateway_text,
        "gatewayStartedForRun": gateway_started,
        "reportedVersion": reported,
        "accepted": runtime.version_accepted(reported, None) and code == 0,
        "kernel": kernel_out.strip() if kernel_code == 0 else None,
        "dockerServer": docker_out.strip() if docker_code == 0 else None,
        "policySchemaVersion": 1,
        "pinnedCommit": runtime.PINNED_COMMIT,
        "environmentPlumbing": "WSL/Docker TCP forwarding is used only when the sandbox cannot reach the gateway. It is not FIP authority.",
    }


def write_policy(result):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    policy_path = ARTIFACTS / "runtime-policy.yaml"
    policy_path.write_bytes(result["policyYaml"].replace("\r\n", "\n").encode("utf-8"))
    (ARTIFACTS / "generated-policy.json").write_text(
        json.dumps(result["generatedPolicy"], indent=2) + "\n", encoding="utf-8"
    )
    return policy_path


def build_image():
    fixture = (ROOT / "integration" / "openshell-m5d" / "fixture").as_posix()
    wsl_fixture = "/mnt/" + fixture[0].lower() + fixture[2:]
    return wsl(
        "mkdir -p /tmp/fip-m4-docker && printf '%s\\n' '{\"auths\":{}}' > /tmp/fip-m4-docker/config.json && "
        f"DOCKER_CONFIG=/tmp/fip-m4-docker docker build -t {IMAGE} {wsl_fixture}",
        timeout=600,
    )


def create_sandbox(policy_path):
    openshell(["sandbox", "delete", SANDBOX])
    return openshell(
        [
            "sandbox", "create",
            "--name", SANDBOX,
            "--from", IMAGE,
            "--policy", _wsl_path(policy_path),
            "--detach",
            "--no-tty",
            "--output", "json",
            "--", "/usr/bin/sleep", "3600",
        ],
        timeout=600,
    )


def policy_get(flag):
    code, out, err = openshell(["policy", "get", SANDBOX, flag, "--output", "json"], timeout=60)
    if code != 0:
        return None, out + err
    payload = json.loads(_json_blob(out))
    policy = payload.get("policy", payload)
    return policy, out


def _authored_match(generated, readback):
    """OpenShell echoes the network-policy map key as name. That is not a new grant."""
    if not isinstance(readback, dict):
        return False, ["readback-missing"]
    compared = json.loads(json.dumps(readback))
    notes = []
    rules = compared.get("network_policies")
    if isinstance(rules, dict):
        for key, rule in rules.items():
            if isinstance(rule, dict) and "name" in rule:
                if rule.get("name") != key:
                    return False, [f"name-disagrees:{key}"]
                notes.append(key)
                rule.pop("name")
    return compared == generated, notes


def _json_blob(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("no json object")
    return text[start:end + 1]


def sandbox_exec(argv, timeout=60):
    return openshell(
        ["sandbox", "exec", "-n", SANDBOX, "--no-login-shell", "--no-tty", "--", *argv],
        timeout=timeout,
    )


def curl_probe(probe_id, curl_args):
    sandbox_exec(["/bin/sh", "-c", "rm -f /tmp/fip-m5d-body"])
    code, out, err = sandbox_exec(["/usr/bin/curl", "-sS", "--max-time", "25", "-D", "-", "-o", "/tmp/fip-m5d-body", *curl_args])
    _body_code, body, body_err = sandbox_exec(["/bin/sh", "-c", "if [ -f /tmp/fip-m5d-body ]; then wc -c < /tmp/fip-m5d-body; head -c 400 /tmp/fip-m5d-body; else echo 0; fi"])
    text = _redact(out + "\n" + err + "\n" + body + "\n" + body_err)
    http_code = _http_code(out)
    return {
        "probe": probe_id,
        "execCode": code,
        "httpCode": http_code,
        "originPage": ORIGIN_MARKER in text,
        "policyMarker": any(marker in text.lower() for marker in DENIAL_MARKERS),
        "text": text[-2000:],
        "bodyBytes": (body or "").splitlines()[0].strip() if body else None,
    }


def _http_code(header_text):
    codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", header_text or "")
    return codes[-1] if codes else None


def _log_matches(probe_id, line):
    needles = {
        "authorized-get": "ALLOWED GET http://example.com:443/ [",
        "wrong-path": "fip-unauthorized-path",
        "wrong-method": "HTTP:POST",
        "wrong-host": "example.org",
        "wrong-port": ":8443",
    }
    return needles[probe_id] in line


def classify_allow(probe):
    if probe["execCode"] == 0 and probe["originPage"] and not probe["policyMarker"] and probe["httpCode"] == "200":
        return "ENFORCED_ALLOW", "fip-grant", True, True
    return "UNOBSERVED", "fip-grant", False, False


def classify_deny(probe):
    """A remote HTTP error is not an OpenShell denial. Policy evidence is required."""
    if probe["policyMarker"] and not probe["originPage"]:
        return "ENFORCED_DENY", "unauthorized", False, True
    return "UNOBSERVED", "unauthorized", False, False


def observation_record(probe_id, disposition, authority_class, fip_grant, requirement_id, binding_id, observed_path, detail, evidence_lines):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "recordType": "fip-runtime-correlation",
        "correlationSource": "fip-side",
        "traceId": "trace-openshell-example",
        "policyId": "pol-openshell-example",
        "exchangeId": None,
        "authorizationId": "az-openshell-example",
        "requirementId": requirement_id,
        "bindingId": binding_id,
        "substrateId": None,
        "adapterId": "openshell-v0.1.2",
        "targetPolicyHash": None,
        "openshellEventId": None,
        "observedOperation": "query",
        "observedPath": observed_path,
        "runtimeDisposition": disposition,
        "authorityClass": authority_class,
        "fipGrant": fip_grant,
        "observedAt": now,
        "targetNativeEvidence": {
            "source": "target-native",
            "eventId": None,
            "workload": {
                "probe": probe_id,
                "operation": "query",
                "path": observed_path,
                "observedAt": now,
                "outcome": "success" if disposition == "ENFORCED_ALLOW" else "failure",
                "errno": None,
                "errnoName": None,
                "detail": detail[:500],
            },
            "logLines": evidence_lines,
        },
    }


def validate_records(records):
    import jsonschema
    from referencing import Registry, Resource

    schema_dir = ROOT / "docs" / "specification" / "fip-0.2" / "schema"
    common = load(schema_dir / "common.schema.json")
    schema = load(schema_dir / "runtime-observation.schema.json")
    registry = Registry().with_resources([
        ("urn:fip:0.2:common", Resource.from_contents(common)),
        (schema["$id"], Resource.from_contents(schema)),
    ])
    validator = jsonschema.Draft202012Validator(schema, registry=registry)
    errors = []
    for record in records:
        errors.extend(validator.iter_errors(record))
    return [error.message for error in errors]


def collect_logs():
    script = _wsl_path(ROOT / "integration" / "openshell-m4" / "collect-evidence.sh")
    _code, streamed, err = wsl(f"sed -i 's/\\r$//' {script}; bash {script} {SANDBOX}", timeout=40)
    return _redact(streamed + "\n" + err)


def _redact(text):
    text = text or ""
    text = re.sub(r"(?i)(gateway[-_ ]?token[^\s\"']*)", "[redacted]", text)
    text = re.sub(r"(?i)(authorization:\s*)\S+", r"\1[redacted]", text)
    text = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}(?:-[0-9a-f]{12}|-\[redacted\])",
        "[redacted]",
        text,
    )
    text = re.sub(r"\b[0-9a-f]{12}\b", "[redacted]", text)
    return text


def _release_sandbox_create(code, stdout):
    policy_hash = None
    phase = None
    text = stdout or ""
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            payload = json.loads(text[start:end + 1])
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
    }


def _cleanup():
    openshell(["sandbox", "delete", SANDBOX], timeout=120)


def _finish(report, code):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "m5d-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "m5d": report.get("m5d"),
        "failureClass": report.get("failureClass"),
        "detail": report.get("detail"),
        "generatedPolicyHash": report.get("generatedPolicyHash"),
        "basePolicyReadbackHash": report.get("basePolicyReadbackHash"),
        "effectivePolicy": report.get("effectivePolicy"),
        "probes": report.get("probeSummary"),
    }, indent=2))
    raise SystemExit(code)


def main():
    report = {"milestone": "M5D", "sandbox": SANDBOX, "image": IMAGE, "m5d": "FAIL", "failureClass": None}
    document, authority, projected, coverage, first, second = compile_twice()
    report["authorityDecision"] = authority["authorityDecision"]
    report["projectionDisposition"] = projected["compilationDisposition"]
    report["coverageDisposition"] = coverage["compilationDisposition"]
    report["coverageDeployable"] = coverage["deployable"]
    report["adapterDisposition"] = first["compilationDisposition"]
    report["adapterDeployable"] = first["deployable"]
    report["runtimeDispositionBeforeObservation"] = first.get("runtimeDisposition")
    report["monotonicity"] = first.get("monotonicity")
    report["fixture"] = {
        "host": "example.com",
        "port": 443,
        "method": "GET",
        "path": "/",
        "note": "Runtime fixture host and path. The conformance probe remains weather.example.com GET /weather.",
    }
    if first.get("generatedPolicy") != second.get("generatedPolicy"):
        report["failureClass"] = "compilation-failure"
        report["detail"] = "two compilations differed"
        _finish(report, 2)
    ready = (
        authority["authorityDecision"] == "AUTHORIZED"
        and coverage["compilationDisposition"] == "FULL"
        and coverage["deployable"] is True
        and first["compilationDisposition"] == "FULL"
        and first["deployable"] is True
        and first.get("runtimeDisposition") == "UNOBSERVED"
        and first.get("monotonicity") == "demonstrated"
        and first.get("generatedPolicy")
    )
    if not ready:
        report["failureClass"] = "compilation-failure"
        report["diagnostics"] = first.get("diagnostics")
        _finish(report, 2)
    generated_hash = runtime.canonical_policy_hash(first["generatedPolicy"])
    second_hash = runtime.canonical_policy_hash(second["generatedPolicy"])
    report["generatedPolicyHash"] = generated_hash
    report["secondCompilationHash"] = second_hash
    report["hashStable"] = generated_hash == second_hash
    report["conformanceHashUnchanged"] = CONFORMANCE_HASH
    if generated_hash != second_hash or generated_hash == CONFORMANCE_HASH:
        report["failureClass"] = "compilation-failure"
        _finish(report, 2)

    gateway_text, gateway_started = ensure_gateway()
    environment = preflight(gateway_text, gateway_started)
    report["environment"] = environment
    if not environment["accepted"]:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = "OpenShell version does not match the v0.1.2 pin"
        _finish(report, 2)

    policy_path = write_policy(first)
    build_code, build_out, build_err = build_image()
    if build_code != 0:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = _redact((build_err or build_out)[-1500:])
        _finish(report, 2)

    create_code, create_out, create_err = create_sandbox(policy_path)
    report["sandboxCreate"] = _release_sandbox_create(create_code, create_out)
    if create_code != 0:
        report["failureClass"] = "sandbox-launch-failure"
        report["detail"] = _redact((create_err or create_out)[-1500:])
        _finish(report, 2)

    base_policy, base_text = policy_get("--base")
    full_policy, full_text = policy_get("--full")
    if not isinstance(base_policy, dict) or not isinstance(full_policy, dict):
        report["failureClass"] = "policy-installation-failure"
        report["detail"] = _redact((base_text or "")[-1000:] + (full_text or "")[-1000:])
        _cleanup()
        _finish(report, 2)
    (ARTIFACTS / "base-policy-readback.json").write_text(json.dumps(base_policy, indent=2) + "\n", encoding="utf-8")
    (ARTIFACTS / "full-policy-readback.json").write_text(json.dumps(full_policy, indent=2) + "\n", encoding="utf-8")
    report["basePolicyReadbackHash"] = runtime.canonical_policy_hash(base_policy)
    report["fullPolicyReadbackHash"] = runtime.canonical_policy_hash(full_policy)
    authored_match, echo = _authored_match(first["generatedPolicy"], base_policy)
    report["basePolicyMatch"] = authored_match
    report["basePolicyReadbackNormalization"] = echo
    report["openshellPolicyLoadHash"] = report["sandboxCreate"].get("openshellPolicyLoadHash")
    if not report["basePolicyMatch"]:
        report["failureClass"] = "policy-installation-failure"
        report["detail"] = "base policy readback differs from the generated policy"
        report["baseKeys"] = sorted(base_policy)
        report["generatedKeys"] = sorted(first["generatedPolicy"])
        _cleanup()
        _finish(report, 2)

    reasons = adapter.verify_effective_policy(
        full_policy,
        first["networkGrants"],
        first["extractedAuthority"]["substrate"],
        first["binaryRestrictions"],
    )
    report["effectivePolicy"] = "PASS" if not reasons else "FAIL"
    report["effectivePolicyDiagnostics"] = reasons
    report["fullPolicyKeys"] = sorted(full_policy)
    rules = full_policy.get("network_policies") if isinstance(full_policy.get("network_policies"), dict) else {}
    report["observedNetworkRuleNames"] = sorted(rules)
    report["providerRules"] = [name for name in rules if str(name).startswith("_provider_")]
    if reasons:
        report["failureClass"] = "effective-policy-failure"
        report["detail"] = "live effective policy is outside the FIP grant plus the profile binary"
        _cleanup()
        _finish(report, 2)

    identity_code, identity_out, identity_err = sandbox_exec(["/bin/sh", "-c", "readlink -f /usr/bin/curl; command -v wget || true; command -v python3 || true"])
    report["sandboxClients"] = _redact(identity_out + identity_err)
    specs = [
        ("authorized-get", ["https://example.com/"], "allow", "GET /", "https://example.com/"),
        ("wrong-path", ["https://example.com/fip-unauthorized-path"], "deny", "GET /fip-unauthorized-path", "https://example.com/fip-unauthorized-path"),
        ("wrong-method", ["-X", "POST", "--data", "", "https://example.com/"], "deny", "POST /", "https://example.com/"),
        ("wrong-host", ["https://example.org/"], "deny", "GET example.org /", "https://example.org/"),
        ("wrong-port", ["https://example.com:8443/"], "deny", "GET example.com:8443 /", "https://example.com:8443/"),
    ]
    raw_probes = []
    for probe_id, args, expect, label, observed_path in specs:
        probe = curl_probe(probe_id, args)
        probe["expect"] = expect
        probe["label"] = label
        probe["observedPath"] = observed_path
        raw_probes.append(probe)

    query = curl_probe("query-bearing", ["https://example.com/?x=1"])
    query["claim"] = "not a FIP query authorization"
    report["queryProbe"] = query
    report["queryAcceptedByExactPathRule"] = query.get("httpCode") == "200" and query.get("originPage") is True
    log_text = collect_logs()
    (ARTIFACTS / "openshell.log").write_text(log_text, encoding="utf-8")
    probes = []
    records = []
    for probe in raw_probes:
        related = [line for line in log_text.splitlines() if _log_matches(probe["probe"], line)]
        evidence = probe["text"] + "\n" + "\n".join(related)
        probe["policyMarker"] = any(marker in probe["text"].lower() for marker in DENIAL_MARKERS) or any(
            "DENIED" in line or "policy_denied" in line.lower() for line in related
        )
        probe["logLines"] = related[:12]
        probe["originPage"] = probe["originPage"] or (ORIGIN_MARKER in evidence and "policy_denied" not in evidence.lower())
        if probe["expect"] == "allow":
            disposition, authority_class, fip_grant, passed = classify_allow(probe)
            requirement_id, binding_id = ("req-example-get", "example-get") if fip_grant else (None, None)
        else:
            disposition, authority_class, fip_grant, passed = classify_deny(probe)
            requirement_id, binding_id = None, None
        probe["runtimeDisposition"] = disposition
        probe["fipGrant"] = fip_grant
        probe["passed"] = passed
        probes.append(probe)
        if disposition in {"ENFORCED_ALLOW", "ENFORCED_DENY"}:
            record = observation_record(
                probe["probe"], disposition, authority_class, fip_grant, requirement_id, binding_id,
                probe["observedPath"], evidence, related[:20],
            )
            record["targetPolicyHash"] = generated_hash
            records.append(record)

    binary = None
    if "wget" in (report.get("sandboxClients") or ""):
        code, out, err = sandbox_exec(["/usr/bin/wget", "-q", "-O", "/tmp/fip-m5d-wget", "https://example.com/"])
        binary = {"probe": "unlisted-binary", "execCode": code, "text": _redact(out + err)[-1500:]}
        disposition, authority_class, fip_grant, passed = classify_deny({
            "execCode": code,
            "originPage": ORIGIN_MARKER in (out + err),
            "policyMarker": any(marker in (out + err).lower() for marker in DENIAL_MARKERS),
            "httpCode": None,
        })
        binary["runtimeDisposition"] = disposition
        binary["passed"] = passed
        binary["classification"] = "target-restriction"
        if disposition == "ENFORCED_DENY":
            record = observation_record(
                "unlisted-binary", disposition, "unauthorized", False, None, None, "https://example.com/", "target-restriction " + binary["text"], []
            )
            record["targetPolicyHash"] = generated_hash
            records.append(record)
    report["unlistedBinary"] = binary or {
        "probe": "unlisted-binary",
        "performed": False,
        "classification": "target-restriction",
        "reason": "The fixture image provides /usr/bin/curl. wget and python3 are not installed, and no extra client was installed for this probe.",
    }

    schema_errors = validate_records(records)
    report["observationSchemaErrors"] = schema_errors
    (ARTIFACTS / "runtime-observations.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    report["probes"] = [{key: item.get(key) for key in ("probe", "execCode", "httpCode", "originPage", "policyMarker", "runtimeDisposition", "fipGrant", "passed", "text")} for item in probes]
    report["probeSummary"] = [{key: item.get(key) for key in ("probe", "passed", "runtimeDisposition", "fipGrant", "httpCode")} for item in probes]
    critical_ok = all(item["passed"] for item in probes)
    report["runtimeMonotonicity"] = (
        report["basePolicyMatch"]
        and report["effectivePolicy"] == "PASS"
        and critical_ok
        and not schema_errors
        and not report.get("queryAcceptedByExactPathRule")
    )
    report["recommendation"] = (
        "REST_RUNTIME_PASS"
        if report["runtimeMonotonicity"]
        else "REST_RUNTIME_PASS_WITH_LIMITATIONS"
        if critical_ok and report["effectivePolicy"] == "PASS" and not schema_errors
        else "REST_RUNTIME_FAIL"
    )
    if schema_errors:
        report["failureClass"] = "evidence-failure"
    elif not critical_ok:
        report["failureClass"] = "enforcement-failure"
    elif report["recommendation"] != "REST_RUNTIME_FAIL":
        report["m5d"] = "PASS"
    _cleanup()
    _finish(report, 0 if report.get("recommendation") != "REST_RUNTIME_FAIL" else 1)


if __name__ == "__main__":
    main()
