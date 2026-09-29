# FIP 0.2 OpenShell Filesystem Vertical Slice

This document states what the uncommitted baseline on
`feature/openshell-integration` has demonstrated. It is a release boundary,
not a new capability.

The pin is NVIDIA OpenShell v0.1.2, commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`, policy schema 1.

## Validated

- FIP 0.2 authority evaluation.
- Target-neutral Enforcement IR.
- Capability coverage.
- Compilation profile and trusted execution substrate.
- OpenShell v0.1.2 capability profile.
- Filesystem adapter.
- Post-generation monotonicity.
- Real OpenShell and Landlock filesystem enforcement.
- FIP-side runtime observation, recorded separately from audit correlation.

## Not yet validated

- REST or network compilation and runtime.
- Model identity.
- Provider compilation.
- Credentials end to end.
- Action approval.
- Correlated audit as a target-native capability.
- GPU.
- Process policy compilation.
- Validity-bound enforcement.
- A second enforcement target.
- CAMEO integration.

`AUTHORIZED`, `FULL`, a generated target policy, and `ENFORCED_ALLOW` are
different facts. Coverage `FULL` means the slice is eligible for compilation.
The adapter may then emit a schema-1 policy whose `runtimeDisposition` is
`UNOBSERVED`. Only an observed authorized success is `ENFORCED_ALLOW`. An
observed runtime denial is `ENFORCED_DENY`. Those outcomes are FIP-side
runtime observations
([schema/runtime-observation.schema.json](schema/runtime-observation.schema.json)).
They are not audit-correlation records and they do not show that OpenShell
provides correlated audit.

## Policy hashes

The FIP canonical policy hash is SHA-256 of UTF-8 JSON with sorted keys,
comma and colon separators, `ensure_ascii` true, and no trailing newline:

`6cf6240b86186a0d94fcffe49034e8cb2fb5a03835dea68c765ceddb47456afb`

The OpenShell-native policy-load hash is a different value. It is the hash
OpenShell reported when it loaded the policy. It is not the FIP canonical
hash:

`0b78911ec0b9fd74c6d1aba4749097bc2fc8b73a960907c1e261e2a194deb907`

## Landlock evidence

`conformance/fip-0.2/openshell/m4/openshell.log` is a sanitized extract. The
extraction procedure is:

1. Run `integration/openshell-m4/collect-evidence.sh` with the sandbox name.
2. That script reads `docker logs` for containers whose names contain the
   sandbox name. The workload container, not the supervisor, carries the
   Landlock lines.
3. The published log keeps the Landlock and configuration lines and replaces
   container identifiers with `[redacted]`.

The retained sentences include Landlock availability at ABI v7 with
`HardRequirement`, ruleset application at ABI V3 with `HardRequirement`, and
`rules_applied:14`. Those sentences are the runtime text. They were not
rewritten.

## Environment plumbing

On the demonstration host, Docker Desktop and the WSL Ubuntu gateway were in
different network namespaces. `integration/openshell-m4/tcp_proxy.py` and
`start-gateway.sh` are the plumbing used for that layout. They are not FIP
semantics, not OpenShell policy, and not execution authority. A host where
the gateway and the sandbox share a network namespace does not need the proxy.

Gateway certificates and the proxy process stay outside the repository.

## Portable reproduction

From a clean checkout, with Python 3.11 or later and no OpenShell install:

```text
python tools/test_all.py
python tools/generate_provenance.py --check
python tools/generate_fip02_provenance.py --check
```

`python tools/test_all.py` does not start a container, a gateway, or the
proxy. The FIP 0.1 check covers 96 frozen artifacts. The FIP 0.2 check is a
separate validated-baseline manifest, `docs/fip-0.2-artifact-hashes.sha256`.

To regenerate the filesystem policy from the FIP source, evaluate
`examples/fip-0.2/openshell-filesystem-read-write.json` with `assess`,
`project`, and `assess_coverage` against
`reference/fip-0.2/targets/openshell/manifest.json` and
`execution-profile.json`, then `compile_policy`. The canonical hash above is
the expected result. Do not hash the stored policy file as if it were the
generator input.

The repository has no third-party Python dependencies for this suite.

## M4 prerequisites

A second runtime run needs Linux or WSL, Docker, and the pinned OpenShell
v0.1.2 CLI and gateway. Install the release binaries for that tag. The
binary does not expose the source commit; the tag object is
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. If the reported version is not
`0.1.2`, stop.

Then:

```text
python integration/openshell-m4/run_m4.py
```

Use the gateway and, only when the sandbox cannot reach the gateway directly,
the TCP proxy. The proxy must not be copied into a FIP grant, an Enforcement
IR, a Capability Manifest, or the generated policy.
