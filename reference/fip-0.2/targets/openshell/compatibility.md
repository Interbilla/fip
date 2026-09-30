# OpenShell v0.1.2 capability profile

This profile models one pinned OpenShell release as a FIP 0.2 Capability Manifest.
It does not emit an OpenShell policy and it does not change FIP vocabulary.

## Pin

| Item | Value |
|---|---|
| Product | NVIDIA OpenShell |
| Release | `v0.1.2` |
| Source commit | `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Commit date | 2026-09-28 |
| Policy schema version | integer `1` |
| Documentation | the `v0.1.2` tag tree, read 2026-09-28 |
| FIP manifest | `manifest.json` in this directory, `manifestVersion` `0`, `adapterVersion` `0` |

Documentation read from that tag:

- `docs/how-it-works/policies/schema.mdx`
- `docs/how-it-works/policies/default-policy.mdx`
- `docs/how-it-works/inference.mdx`
- `docs/observability/logging.mdx`
- `docs/index.yml`

The `dev` channel and later documentation are not this pin.

## What the manifest claims

The manifest uses only the generic Capability Manifest schema.

- Filesystem read and write are separate lists of absolute paths. `filesystemOperations` is `exact`.
- Network hosts can be an exact hostname. `networkHost` is `exact`.
- REST method and path can be enforced when an endpoint sets `protocol: rest` and `enforcement: enforce`. `httpMethod` and `httpPath` are true for that mode.
- Calling binaries are a network-rule field. A FIP `executable` binding is an executable identity. On v0.1.2 the same rule also applies to processes that binary starts, so the identity is not exact.
- Effects that the engine can apply as a control are `permit` and `deny`.
- OCSF v1.8.0 sandbox logs are `target-native` audit. `traceCorrelation` is false. `correlated` is absent from `auditStrengths`.
- Lifetimes are scoped. Filesystem and process are `establishment-bound`. Network and credential are `establishment-bound` and `revocable`.
- `approval.actionGate` is false. `approval.policyMutation` is true because the Policy Advisor proposes a policy change.
- `modelId` is false. Kind `model` is absent. Kind `inference-provider` is present, so a model binding is evaluated as a provider substitution.
- Disclosure `proxy-mediated` is listed. `credentialBinding` requires `host` and `port`. Kind `credential` is absent. A `serviceId` alone does not match that boundary.
- `dangerousDefaults` is empty. Unsafe modes are adapter obligations recorded below, because an unknown dangerous-default string would reject every assessment, including a filesystem-only one.

`allOf` and `anyOf` are listed so a later adapter must emit every member of a required group. OpenShell itself has no group object. A partial group is an adapter failure.

## Filesystem

Unlisted paths are inaccessible. `read_only` and `read_write` are separate. A path is absolute, contains no `..`, and the policy holds at most 256 paths. `/` as read-write is rejected. Filesystem, Landlock, and process fields take effect at startup. Replacing them recreates the sandbox context, which is `establishment-bound`.

Pinned v0.1.2 does not glob a filesystem path. `PathFd` opens the string literally, and Landlock `PathBeneath` then applies to that inode. If the inode is a directory, the rule covers the hierarchy beneath it. If it is a file, the rule uses file rights only. The static adapter cannot see the inode, so it does not treat every absolute path as a directory grant and it does not reject `/mission/input`.

`normalize_path` is lexical. It collapses repeated separators, drops `.`, and drops a trailing slash. It keeps `..` for a separate validation error. It does not resolve symlinks. This profile does not rewrite a locator into that normalized form. A locator that would change under that normalization is not an exact representable path.

`*`, `?`, and `[` are pattern syntax in this product's path globs. They are ordinary filename bytes to `open`, and this profile still refuses them. `filesystemOperations: exact` may be `FULL` only for an absolute path whose segments are nonempty and are not `.`, `..`, or that pattern syntax. A refused locator stays `AUTHORIZED` at semantics and is `REJECTED` at coverage with `unsupported_requirement` and diagnostic `filesystem_locator_not_exact`. That is not `subset_not_demonstrated`. A missing path fails `hard_requirement` startup instead of being skipped into a wider ruleset. Symlink targets are followed by `open` and are not proved by this static check.

`include_workdir` defaults to false when `filesystem_policy` is present, and to true when that section is omitted. A faithful adapter that emits the section can leave the workdir out of `read_write`. The usual workdir `/sandbox` is therefore not an always-on substrate entry.

Landlock `compatibility` defaults to `best_effort`. If no listed path can be applied, `best_effort` runs the sandbox without the filesystem rules and logs a finding. `hard_requirement` fails startup in that case. Both modes skip an individual missing path, and both require Landlock ABI v3. A faithful translation sets `hard_requirement`. `best_effort` is not exact enforcement.

There is no separate delete operation. Write access to a path includes modification of files under that path. Filesystem `delete` is not in `operations`.

## Network

`network_policies` is live: a policy update can change network rules on a running sandbox. Each rule allows every listed binary to reach every listed endpoint. An empty binary list matches no binary. Egress is denied when no rule matches.

An endpoint can name an exact host, a port or port list, and a path glob. Host wildcards exist (`*.example.com` and related forms). A wildcard is not an exact host. The manifest's `networkHost: exact` describes a faithful adapter that emits one exact host. It does not authorize wildcard compilation.

`protocol: rest` with `enforcement: enforce` checks method and path and blocks a request that breaks the rules. The default `enforcement` is `audit`, which logs the request and still forwards it. That default does not satisfy a FIP `permit` or `deny`. A later adapter must set `enforcement: enforce` for any FIP permit or deny. `tls: skip` relays traffic without inspection, so method and path are not enforced in that mode. `protocol: tcp`, and an endpoint with no protocol, do not inspect the HTTP request. Method and path enforcement is not claimed from a host-only or TCP rule.

## Process

`run_as_user` and `run_as_group` are startup fields. Docker and Podman apply them from the policy passed at sandbox creation. Root is rejected. Kubernetes and VM sandboxes use the driver identity. This is configurable process identity.

Seccomp filtering is applied by the supervisor and is not a policy field. The manifest records it as substrate with `authorityBearing: false`. It is not a FIP process grant. Kind `process` is absent from `kinds`.

## Credentials and inference

Provider attachment gives the workload an opaque placeholder. The proxy substitutes the provider credential only at an endpoint the provider profile authorizes. Detach removes that provider's policy and credential access. That mechanism is endpoint-bound.

The FIP proxy-mediated examples locate a credential by `serviceId` and require disclosure `proxy-mediated`. This manifest lists that disclosure. Kind `credential` is absent. Pinned v0.1.2 does not enforce credential use independently of provider attachment. A provider profile that names endpoints injects those endpoints and the credential together. `credential_binding.provider` still requires an attached provider, and attaching one requires a secret this adapter does not hold. Coverage therefore rejects kind `credential` on this adapter even when the binding names a host and port. The diagnostic is `credential_use_not_independent`. Secret confidentiality is not credential authorization.

Provider profiles can add endpoint and binary rules to the effective policy. That extra network access appears only when a provider is attached. It is not an always-on substrate entry, for the same reason GPU paths are not. A hostless network substrate entry would reject every assessment, including a filesystem policy with no provider.

Inference access is the same provider attachment. The workload calls the provider's native API and chooses the model identifier. Provider attachment does not select or rewrite a model. Kind `model` is absent and `modelId` is false, so an exact `modelId` requirement cannot receive `FULL`. Provider or endpoint reachability is not model enforcement.

## Audit

Sandbox logs include OCSF v1.8.0 events for network, HTTP, process, filesystem, and configuration. An event can name a policy key, binary, host, port, method, and path. The v0.1.2 log format does not carry FIP `traceId`, `requirementId`, `bindingId`, or a FIP `targetRuleId`. The manifest therefore records `target-native` and leaves `traceCorrelation` false. A future correlation sidecar would be a separate capability.

## Approval

OpenShell has a Policy Advisor that can propose a narrower network rule and wait for a policy reload. That is approval of a policy change. It is not an approval Decision for a FIP action. `actionGate` is false and `policyMutation` is true, so a `require-approval` requirement is `subset_not_demonstrated`.

## Lifetime

| OpenShell control | M0 lifetime this profile records |
|---|---|
| Filesystem, Landlock, process identity | `establishment-bound`. Changing the control starts a new sandbox context. |
| Network policy and provider attach or detach | Live update on a running sandbox. This may meet `revocable` for network only. |
| Validity clock that ends an effect while the process keeps running | Not provided. `validity-bound` is not listed. |

Each capability class carries its own lifetimes. `revocable` on the network class does not satisfy a filesystem or process requirement. `validity-bound` is not listed on any class. The published REST example uses `revocable` on an `api` binding, and that lifetime matches the network class.

## Baseline and its coverage effect

These entries are substrate. `authorityBearing` is false. They are not FIP grants.

| Baseline | Class | Effect when `execution-profile.json` accepts the exact item |
|---|---|---|
| Read-only `/usr`, `/lib`, `/etc`, `/app`, `/var/log`, `/proc`, `/dev/urandom` | `read-only-runtime` | Accepted and visible. Not a grant. |
| Runtime read-only `/run/openshell-supervisor-ca` | `read-only-runtime` | Accepted and visible. Not saved in the policy file. |
| Read-write `/tmp` | `writable-runtime` | Accepted only by the exact profile entry. Without that entry, `baseline_exceeds_grant`. |
| Read-write `/dev/null` | `writable-runtime` | Same as `/tmp`. |
| Supervisor syscall restriction | `restrictive` | Accepted when the profile names it. It is not a process grant. |
| Workdir via `include_workdir` | Not in this manifest. An explicit `filesystem_policy` defaults the flag to false. |
| GPU device paths and read-write `/proc` on GPU sandboxes | Not in this manifest. See below. |
| Provider-contributed endpoints | Not in this manifest. Present only when a provider is attached. |

v0.1.2 adds `/tmp` and `/dev/null` as read-write when the effective policy has a network rule and the policy does not already list those paths. A path the policy already lists keeps the access the policy states, so an adapter can list them read-only. This manifest classifies those paths as `writable-runtime`. `execution-profile.json` accepts each declared runtime item by id and path. That file is a FIP compilation profile. It is not an OpenShell policy, and it does not accept any other path the manifest might label the same way. Without the profile, the writable entries are `baseline_exceeds_grant`.

The restrictive default policy, used only when no other policy is selected, also grants read-only `/bin` and read-write `/tmp` and `/dev/null`, with `include_workdir` true. An explicit policy does not automatically include `/bin`.

`/.openshell` is protected by a mandatory Landlock baseline and cannot be exposed by the filesystem policy. That is a restriction, not an extra grant.

### GPU sandboxes

On Docker and VM drivers, a sandbox that requests a GPU can receive extra paths when the device exists, including read-write `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`, `/dev/nvidia-modeset`, `/dev/dxg`, numbered NVIDIA device nodes, and `/proc`. CUDA initialization is why `/proc` moves from read-only to read-write. These paths are runtime-only. They are not in `manifest.json`. A GPU sandbox needs its own profile. This profile does not assume GPU access.

## Coverage of the M2A examples

Assessed with `assess_coverage` against `manifest.json` and `execution-profile.json`. No example is `FULL`. `deployable` is false for each. Accepted substrate is visible and is not in `fipGrants`.

| Example | Disposition | Requirement coverage | Audit | Lifetime | Baseline | Reason codes |
|---|---|---|---|---|---|---|
| Filesystem read/write | `REJECTED` | `req-read` and `req-write` unenforced | correlated unmet | establishment-bound matches the filesystem class | accepted runtime substrate | `unsupported_requirement` |
| REST GET | `PARTIAL` | `req-weather` unenforced; `req-no-other-network` enforced | permit correlated unmet; deny target-native matches | `revocable` matches the network class and does not apply to filesystem | accepted runtime substrate | `unsupported_requirement` |
| Model inference | `REJECTED` | `req-model` rejected; `req-provider` rejected | correlated not reached | model has no capability, so its `revocable` lifetime does not borrow the network class; an inference-provider binding is not exact model authority | accepted runtime substrate | `lifetime_mismatch`, `subset_not_demonstrated` |
| Proxy-mediated credential | `REJECTED` | permit rejected because host and port are absent; credential deny unenforced | correlated unmet, not reached | `revocable` matches the credential class | accepted runtime substrate | `subset_not_demonstrated`, `unsupported_requirement` |
| Multi-binding action | `REJECTED` | connect and GET unenforced on correlated audit; credential rejected on the missing host and port | correlated unmet for connect and GET | network `revocable` matches connect and GET | accepted runtime substrate | `unsupported_requirement`, `subset_not_demonstrated` |
| Prohibition, authorized ReadInspectionInput exchange | `PARTIAL` | permit unenforced; deny enforced | permit correlated unmet; deny target-native matches | establishment-bound matches | accepted runtime substrate | `unsupported_requirement` |
| Human approval, satisfied Decision | `REJECTED` | `require-approval` rejected | correlated not reached | establishment-bound, not reached | accepted runtime substrate | `subset_not_demonstrated` |
| Human approval, no Decision | `NOT_COMPILED` | no operational IR | unassessed | unassessed | unassessed | `not_compiled` |

Filesystem read/write is `REJECTED` because the permits require correlated audit. The accepted runtime substrate is not the cause. The same IR without `execution-profile.json` is `REJECTED` with `baseline_exceeds_grant` as well.

REST GET can use the network class's `revocable` lifetime while filesystem capabilities remain `establishment-bound`. The published REST permit is still unenforced because its audit strength is `correlated`.

The proxy-mediated permit fails the subset invariant. Adding a host and port does not make it deployable on this adapter. Provider attachment is not a FIP credential grant.

Exact `modelId` remains unsupported. Kind `model` is absent, `modelId` is false, and the pinned inference text leaves model selection to the workload.

## Adapter gap

| FIP requirement | OpenShell v0.1.2 mechanism | Match | When it applies | Baseline | Adapter work |
|---|---|---|---|---|---|
| Filesystem read | `read_only` path | exact | static, startup | read-only system paths do not exceed | emit the path only in `read_only`; set Landlock `hard_requirement` |
| Filesystem write | `read_write` path | exact | static, startup | `/tmp` and `/dev/null` writes exceed unless granted or pre-listed read-only | emit only granted write paths |
| Filesystem delete | no distinct operation | unsupported | static | write already covers modification | do not compile delete as write |
| REST host | endpoint `host` | exact for one hostname | dynamic | provider-added hosts are conditional | emit one exact host; do not emit a wildcard |
| REST port | endpoint `port` or `ports` | exact | dynamic | none beyond the host rule | emit the granted port |
| REST method | REST `rules` when `enforcement: enforce` | exact in that mode | dynamic | default `audit` still forwards | set `enforcement: enforce` |
| REST path | REST `path` rule when `enforcement: enforce` | exact in that mode | dynamic | same audit default | set `enforcement: enforce`; do not use `tls: skip` or `protocol: tcp` for this requirement |
| Calling executable | rule `binaries.path` | exact path or glob | dynamic | none | emit the FIP executable path; scripts match their interpreter |
| Model provider | provider profile endpoint and attachment | partial | dynamic | profile can add endpoints | attach only the intended provider; do not treat this as `modelId` |
| Exact modelId | workload-selected native request | unsupported | n/a | none | do not compile |
| Proxy credential | proxy substitution at a profile endpoint | partial, endpoint-bound | dynamic | provider rules are conditional | do not compile a serviceId-only credential as proxy-mediated |
| Correlated audit | OCSF events without FIP identifiers | unsupported | n/a | none | a future sidecar; this profile does not claim it |
| Target-native audit | OCSF v1.8.0 | exact for that strength | continuous log | none | map events to the policy key the adapter emits |
| Action approval | Policy Advisor proposal | unsupported for a FIP action | policy change | a proposal widens or replaces rules | do not compile `require-approval` |
| Revocable lifetime | live network update | exact for the network and credential classes | dynamic | filesystem and process remain establishment-bound | emit it only for those classes |
| Validity-bound lifetime | no validity clock that drops the effect in place | unsupported | n/a | none | do not compile |

## Filesystem adapter slice

The seven architectural examples above are not inputs to the policy adapter. The compilable slice is [openshell-filesystem-read-write.json](../../../../examples/fip-0.2/openshell-filesystem-read-write.json): read `/mission/input`, write `/mission/output`, lifetime `establishment-bound`, audit `target-native`. With this manifest and `execution-profile.json`, coverage is `FULL`. The adapter emits policy schema 1 with `include_workdir: false` and `landlock.compatibility: hard_requirement`. Runtime disposition stays `UNOBSERVED`.

The architectural REST example and the strict executable probe are not compiled. Provider, model, credential, action approval, correlated audit, and GPU paths are not compiled. A REST permit with no executable binding can be compiled when this profile's `targetExecutableRestrictions` lists the binary path. That path is a target-side restriction, not a FIP grant.

## REST qualification

Three REST documents stay distinct. [rest-get.json](../../../../examples/fip-0.2/rest-get.json) is the architectural probe and stays `PARTIAL` because its permit requires correlated audit. [openshell-rest-get.json](../../../../examples/fip-0.2/openshell-rest-get.json) is the strict executable-identity probe and stays `REJECTED`. [openshell-rest-target-restricted.json](../../../../examples/fip-0.2/openshell-rest-target-restricted.json) is the API-only probe and can be `FULL`. None of these results is a substitute for the others.

[openshell-rest-get.json](../../../../examples/fip-0.2/openshell-rest-get.json) is case A. Its permit is `allOf` over the API binding and `weather-curl`. Kind `executable` is an executable identity, and authorizing an action does not authorize a proper subset of that group. Pinned v0.1.2 applies a binary rule to descendant processes, which is wider than that identity. Coverage is `REJECTED` with `subset_not_demonstrated`. The adapter diagnostic is `executable_identity_not_exact`. No deployable network policy is emitted. The example is not rewritten to drop the executable binding.

`access: read-only` is not an exact `GET`. An exact endpoint would need `protocol: rest`, `enforcement: enforce`, and one allow rule for that method and path. Query-string precision is outside the initial FIP 0.2 OpenShell REST compilation profile. A locator URI with no query component can satisfy that profile. A locator URI that contains `?` fails closed with adapter diagnostic `query_precision_unsupported` and coverage `REJECTED` / `subset_not_demonstrated`. The compiler does not ignore the query, strip it, or emit a query matcher. That rejection is not FIP query authorization. The M5D runtime observation that `GET /?x=1` returned HTTP 200 is a target limitation. It prevents a claim of complete runtime monotonicity for this REST slice.

## Target-restricted REST

[openshell-rest-target-restricted.json](../../../../examples/fip-0.2/openshell-rest-target-restricted.json) authorizes one exact host, port, `GET`, and path. It has no executable ExecutionBinding. `/usr/bin/curl` is declared only in `execution-profile.json`. The compiler copies that path into `binaries` and records `executableIdentity: approximated`, `descendantInheritance: true`, and `authorityRole: target-side restriction`. Descendant inheritance is a target limitation. It is not FIP authority, and it is not an exact identity claim. The strict probe remains `REJECTED` even though the profile names the same path, because that probe requires the identity in the permit.

## REST compilation

Successful base-policy compilation is not a runtime enforcement claim. `runtimeDisposition` stays `UNOBSERVED` until a live observation. Before a runtime allow is accepted, `openshell policy get --full` must pass `verify_effective_policy` on the whole tuple: host, port, protocol, enforcement, HTTP method, HTTP path, binary scope, access preset, and TLS inspection. The same host is not enough. A provider rule whose name starts with `_provider_`, or a global policy that replaces the authored rules, fails closed.

`openshell policy get --base` shows the saved user policy. `openshell policy get --full` shows the composed effective policy, including provider rules. While a gateway global policy is active, both commands show the global policy and provider layers are suppressed. Neither view includes runtime-only paths such as the supervisor CA. A readback may add `name` on a network policy when that value is the map key. The verifier accepts that echo. A different name, or any other extra field, is rejected. The OpenShell policy-load hash is a separate native value and is not the FIP canonical policy hash.

## Remaining v0.1.2 surfaces

Pinned source for this record is NVIDIA OpenShell v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`. The files used are `docs/how-it-works/policies/schema.mdx`, `docs/how-it-works/inference.mdx`, `crates/openshell-core/src/mcp.rs`, `crates/openshell-supervisor-network/src/l7/mcp.rs`, and `crates/openshell-sandbox/src/sandbox/linux/seccomp.rs`. Where current product documentation differs, that commit is authoritative.

TCP `protocol: tcp` accepts a hostname and a port and no request fields. [openshell-tcp-connect.json](../../../../examples/fip-0.2/openshell-tcp-connect.json) is `service` plus `connect` with an exact host and port and no HTTP method or path. The compiler emits `protocol: tcp` and the profile binary restriction. It does not emit method, path, access, or TLS skip. A REST grant is not compiled as TCP. A service connect that also names an HTTP method or path is `REJECTED`. Runtime for this slice stays `UNOBSERVED`. The M5 REST run already observed connection denial. A second live TCP sandbox would not add a credential-free fact this static policy does not already show.

MCP exists in v0.1.2. A rule can name one method, and `tools/call` can name one tool. Tool arguments are not matched. Server responses are not inspected. The compiler emits only the granted method and tool. It does not add `initialize`, `notifications/initialized`, or `allow_all_known_mcp_methods`. [openshell-mcp-tool.json](../../../../examples/fip-0.2/openshell-mcp-tool.json) is `FULL` for that exact tool name. Argument acceptance is a target limitation, the same class of gap as a query on an exact REST path. Runtime stays `UNOBSERVED` because no local MCP server fixture is part of this campaign. Network reachability to the MCP host is not tool authorization.

Exact model identity stays unsupported. Re-reading `docs/how-it-works/inference.mdx` at this pin confirms the workload chooses `modelId`. Kind `inference-provider` is `REJECTED` with `subset_not_demonstrated` and diagnostic `model_identity_unsupported`. Provider routing is not recorded as model authorization.

Kind `process` stays outside `kinds`. [openshell-process-execute.json](../../../../examples/fip-0.2/openshell-process-execute.json) is `REJECTED` with `unsupported_requirement`. Seccomp, an unprivileged user, and namespace isolation remain execution substrate. Strict executable identity stays `REJECTED` because a binary rule matches the connecting process and its parent chain, which includes descendants of the listed binary.

Effective policy must be verified immediately before execution. A later policy update, provider attach or detach, global policy change, credential change, or model-provider change invalidates that verification. This adapter does not watch those changes continuously, so it does not claim continuous monotonicity.

OCSF can name a policy key, binary, host, port, method, path, and a denial reason. It does not emit FIP `traceId`, `requirementId`, `bindingId`, or `targetRuleId`. Those events stay target-native. They are not correlated audit. The log does not distinguish credential resolution, model routing, or tool-argument acceptance as FIP authority.

Substrate entries stay out of `fipGrants`. Filesystem runtime paths and the supervisor CA are read-only runtime. `/tmp` and `/dev/null` are writable runtime. Seccomp is restrictive. The curl path is a target narrowing restriction. DNS policy addresses, the gateway control plane, and provider infrastructure are infrastructure dependencies. None of them is a FIP grant.
