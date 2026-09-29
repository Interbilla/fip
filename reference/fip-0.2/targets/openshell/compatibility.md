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
- Calling binaries are a network-rule field. The `executable` kind with a path is the FIP shape for that constraint.
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

The FIP proxy-mediated examples locate a credential by `serviceId` and require disclosure `proxy-mediated`. This manifest lists that disclosure and requires `host` and `port` on the binding. The examples omit those locators, so the boundary is broader than the mechanism and coverage is `subset_not_demonstrated`. Kind `credential` is absent. That absence is not the reason: a binding that names the host and port can be enforced through `credentialBinding`.

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
| Model inference | `REJECTED` | `req-model` rejected; `req-provider` unenforced | correlated unmet on the provider requirement | model has no capability, so its `revocable` lifetime does not borrow the network class | accepted runtime substrate | `lifetime_mismatch`, `unsupported_requirement` |
| Proxy-mediated credential | `REJECTED` | permit rejected because host and port are absent; credential deny unenforced | correlated unmet, not reached | `revocable` matches the credential class | accepted runtime substrate | `subset_not_demonstrated`, `unsupported_requirement` |
| Multi-binding action | `REJECTED` | connect and GET unenforced on correlated audit; credential rejected on the missing host and port | correlated unmet for connect and GET | network `revocable` matches connect and GET | accepted runtime substrate | `unsupported_requirement`, `subset_not_demonstrated` |
| Prohibition, authorized ReadInspectionInput exchange | `PARTIAL` | permit unenforced; deny enforced | permit correlated unmet; deny target-native matches | establishment-bound matches | accepted runtime substrate | `unsupported_requirement` |
| Human approval, satisfied Decision | `REJECTED` | `require-approval` rejected | correlated not reached | establishment-bound, not reached | accepted runtime substrate | `subset_not_demonstrated` |
| Human approval, no Decision | `NOT_COMPILED` | no operational IR | unassessed | unassessed | unassessed | `not_compiled` |

Filesystem read/write is `REJECTED` because the permits require correlated audit. The accepted runtime substrate is not the cause. The same IR without `execution-profile.json` is `REJECTED` with `baseline_exceeds_grant` as well.

REST GET can use the network class's `revocable` lifetime while filesystem capabilities remain `establishment-bound`. The published REST permit is still unenforced because its audit strength is `correlated`.

The proxy-mediated permit is characterized as an endpoint binding. Disclosure matches. The example does not name a host and port, so the boundary fails the subset invariant.

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

REST, provider, model, credential, action approval, correlated audit, and GPU paths are not compiled.
