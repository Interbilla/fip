# NVIDIA Open Agent Safety Platform integration study

Non-normative M7 study. It does not change FIP 0.1, FIP 0.2, the pinned
OpenShell v0.1.2 adapter, or M6 evidence.

Pinned historical target:

- NVIDIA OpenShell v0.1.2
- commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`
- policy schema 1

M6 completion gate remains `PASS_WITH_DOCUMENTED_LIMITATIONS`. The M6
recommendation remains `READY_FOR_Q13`. Those conclusions are about that pin.
This study does not reopen them.

M7A formalizes governed runtime authority evolution in
[governed-runtime-authority-evolution.md](governed-runtime-authority-evolution.md).
That companion does not change the conclusions in this study.

## A. Executive conclusion

FIP can sit above NVIDIA enforcement as a portable semantic authority layer.
NVIDIA already supplies a software sandbox, a target-policy prover, and a
network-rule approval workflow in OpenShell v0.1.2. NVIDIA has announced an
additional hardware watchdog, Sentry on BlueField-4. That announcement does
not replace mission authority, organizational federation, or the Semantic
Micro-Firewall.

The useful stack is complementary:

- CAMEO keeps a target-neutral Security Plan.
- GOCP derives what may enter a FIP document.
- FIP records semantic authority.
- The Enforcement IR is the portable projection.
- OpenShell, and later Sentry if a public interface appears, are independent
  enforcement domains. Each must be a subset of FIP authority. Neither domain
  is the authority.

FIP 0.2 does not need a normative change before Q13. Q13 should stay the
pinned-v0.1.2 experiment. Sentry attacks wait until NVIDIA publishes an
interface that can be called.

## B. NVIDIA architecture actually verified

Availability labels used below: `ANNOUNCED`, `DOCUMENTED`,
`OPEN-SOURCE IMPLEMENTED`, `EXPERIMENTALLY ACCESSIBLE`, `HARDWARE-DEPENDENT`,
`FUTURE / NOT YET AVAILABLE`.

### What was read

- NVIDIA product page, fetched 2026-09-29:
  <https://www.nvidia.com/en-us/solutions/ai/agent-safety/>
- NVIDIA technical blog, 2026-09-28, fetched in full:
  <https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/>
- NVIDIA DOCA technical blog, 2026-05-31, fetched in full:
  <https://developer.nvidia.com/blog/advancing-ai-infrastructure-for-agentic-ai-with-nvidia-doca-in-silicon-security/>
- OpenShell research note, 2026-09-10:
  <https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/>
- Pinned OpenShell v0.1.2 source, same commit as M6:
  `docs/how-it-works/policies/prover.mdx`,
  `docs/how-it-works/policies/advisor.mdx`, and the `openshell-prover` crate.
- GitHub compare `v0.1.2...main` on 2026-09-29. Latest published release is
  still `v0.1.2`. `main` was 23 commits ahead at
  `33a8eac196a21aff3125dea46462a4591bcb5d0b`.
- The investor newsroom page was indexed as the 2026-09-28 announcement. A
  direct fetch of that page was blocked by a bot check, so wording below
  prefers the fetched product page and technical blog.

`openshell-prover` is not installed in the environment used for M4 and M5.
This study did not install it and did not run a prover check.

### Platform pieces

| Piece | What the sources support | Label |
| --- | --- | --- |
| Open Agent Safety Platform | Open reference design: OpenShell plus an optional Sentry layer. Optimized for Vera and BlueField, and described as compatible with other hardware. | `ANNOUNCED` |
| OpenShell | Apache-2.0 runtime. Sandbox, policy, kernel isolation. Usable without BlueField-4. v0.1.2 is the latest release and was executed in M4 and M5. | `OPEN-SOURCE IMPLEMENTED` and `EXPERIMENTALLY ACCESSIBLE` |
| Policy prover | SMT boundary check and proposal-risk check. Present in the v0.1.2 tree and documented there. | `OPEN-SOURCE IMPLEMENTED`. Not run in this study. |
| Policy advisor | Agent proposes a network rule. Human or automatic approval applies it. Present in v0.1.2. | `OPEN-SOURCE IMPLEMENTED`. Not run in this study. |
| Sentry | Out-of-band watchdog on BlueField-4. Telemetry, identity, policy enforcement, quarantine in milliseconds. No public policy schema or adapter API was found. | `ANNOUNCED`. `HARDWARE-DEPENDENT`. Interface `FUTURE / NOT YET AVAILABLE`. |
| BlueField zero-trust mode | Documented DPU mode that isolates the host from DPU management. This is not the Sentry product. | `DOCUMENTED` and `HARDWARE-DEPENDENT` |
| DOCA Argus, Vault, Flow | May 2026 description of in-silicon detection, file access control, and line-rate flow enforcement. Related infrastructure. Not a Sentry compiler. | `DOCUMENTED` |

Marketing sentences such as "policies are formally verified, so agent behavior
is kept in check" are stronger than the prover contract. The v0.1.2 prover
page says a pass means the candidate allows nothing beyond the boundary in
the modeled domains. It does not mean the policy is safe for a task, or that
a running sandbox enforces it.

## C. v0.1.2 versus current public OpenShell

Latest release remains v0.1.2. `main` is 23 commits ahead. In that compare,
`docs/how-it-works/policies/prover.mdx` and `advisor.mdx` are not among the
changed files. MCP implementation files are among them. That does not change
the M6 classification of MCP on the pin. Current `main` is not the M6 target.

M6 already recorded, and this study preserves:

| Surface | M6 classification on v0.1.2 |
| --- | --- |
| filesystem | `DEMONSTRATED` |
| REST/L7 | `DEMONSTRATED_WITH_LIMITATIONS` |
| credential/provider | `REJECTED_BY_DESIGN` |
| generic TCP | `SUPPORTED_UNOBSERVED` |
| process/executable | `SUBSTRATE_ONLY` |
| inference/model | `UNSUPPORTED` |
| MCP/tool | `SUPPORTED_UNOBSERVED` |

The prover and the advisor exist inside that same pin. M6 did not compile
them and did not claim they were absent. Their presence does not upgrade
credential use, exact model identity, or exact executable identity.

## D. Policy prover analysis

Pinned `prover.mdx` defines two different checks. Passing one does not imply
passing the other.

### Boundary check

`openshell-prover check candidate.yaml --boundary boundary.yaml` asks whether
`allowed(candidate)` exceeds `allowed(boundary)` inside the modeled domains.
Results are `within_boundary`, `exceeds_boundary`, `error`, `unsupported`,
and `inconclusive`. Only `within_boundary` passes. Exit code 3 covers both
`unsupported` and `inconclusive`.

Modeled domains named by the coverage line:
`filesystem`, `network_l4`, `network_rest`, `process`, `landlock`.

| Domain | What v0.1.2 says it proves | Limit |
| --- | --- | --- |
| Filesystem | Same paths. A candidate may drop a path or narrow read-write to read-only. A boundary of `/` covers every path. | Different paths, including a child of a parent path, are `unsupported` because of symlinks. Working-directory dependence is `unsupported`. |
| Network L4 | Binary, host, port, destination address, `allowed_ips`. Checked with and without binary identity enforcement. | No DNS resolution. Exact path under a glob, overlapping wildcard hosts, omitted host, mixed `port` and `ports`, and IPv6 hosts are `unsupported`. |
| REST | Method and path allow and deny rules on `protocol: rest` with `enforcement: enforce`. | Audit mode, a host/port that also has a non-request endpoint, query matchers, `?` or brackets in paths are `unsupported`. |
| Process | `run_as_user` and `run_as_group`. Non-root to root exceeds. | Any other uid or gid change is `unsupported`. This is not exact executable identity. |
| Landlock | `compatibility` setting. Moving to `hard_requirement` passes. Moving from `hard_requirement` to `best_effort` exceeds. | Compares the setting, not kernel enforcement. |
| MCP, GraphQL, WebSocket, JSON-RPC | Not modeled. | `unsupported`. The prover refuses the policy instead of ignoring those rules. |
| Credentials | Not a boundary-check domain. | Credential effects appear in the proposal-risk check, as reach, not as a FIP credential grant. |
| Model id | Not a boundary-check domain in `prover.mdx`. | A research note mentions inference containment. That note is not the v0.1.2 contract. |

Large policies, above 1,024 network rules or 4,096 endpoints across both
files, return `inconclusive` with `resource_limit`.

The boundary is an OpenShell policy, usually "the most access an environment
allows." It is target policy authority. It is not organizational or mission
authority. The prover does not read a FIP Authorization, a Purpose, a
Prohibition outside the modeled target rules, or a cross-enterprise
delegation.

### Proposal-risk check

Used by the policy advisor. It compares reach with and without one proposed
network rule, including attached provider credentials and binaries whose
traffic cannot be inspected. Findings:

| Finding | Meaning in v0.1.2 |
| --- | --- |
| `link_local_reach` | Link-local or cloud-metadata destination. |
| `l7_bypass_credentialed` | An uninspected binary such as `git`, `ssh`, or `nc` reaches a host where a provider credential is in scope. |
| `credential_reach_expansion` | A binary gains credentialed reach to a host and port it could not reach before. |
| `capability_expansion` | A new HTTP method on a host and port that already had credentialed reach. |

The advisor text says credential scope is presence of an attached provider
whose hosts cover the endpoint, including a first-label wildcard. It does
not model read versus write credential scope. That matches the M6 conclusion
that credential-use authority is not independently enforceable. The prover
can flag new credentialed reach. It does not prove a FIP credential permit.

### Relation to the FIP subset obligation

FIP 0.2 requires:

`EffectiveOperationalAuthority` is a subset of `FIPAuthorizedAuthority` union
`ExplicitlyAcceptedExecutionSubstrate`.

The NVIDIA boundary check requires:

`allowed(candidate)` is a subset of `allowed(boundary)` inside modeled
OpenShell domains.

These are complementary and composable. They are not redundant.

- FIP compares semantic authority, accepted substrate, and the compiled
  target policy, including dimensions the prover leaves `unsupported`.
- The prover compares two OpenShell policies. It can catch a candidate that
  is narrower than a boundary and still wider than the FIP grant, only if
  someone sets the boundary to the FIP-compiled policy. It cannot invent
  that boundary from mission intent.
- A prover `within_boundary` against a loose enterprise maximum can still
  violate the FIP subset.
- A FIP verifier pass does not replace a prover pass against a separately
  chosen maximum, if the operator wants that second check.
- `unsupported` and `inconclusive` must fail closed. They are not passes.

A later architecture can place both checks after compilation:

1. FIP compiler emits a target policy.
2. FIP round-trip verifier checks the FIP subset.
3. `openshell-prover` checks that policy against an operator boundary, and
   the proposal-risk findings if a provider is attached.
4. Only a policy that passes the required checks is eligible to install.

The prover can become an independent verification backend. It cannot become
the semantic authority. This study does not wire that backend in. The CLI
was not present, and installing it would have been a new runtime dependency.

## E. Permission-request and human-approval analysis

Pinned `advisor.mdx` describes a lifecycle that is implemented for network
rules only.

1. A denied network request can tell the agent how to propose access.
2. The agent, or OpenShell itself, submits a proposal. OpenShell also drafts
   proposals from blocked connections when the advisor is off.
3. The proposal is validated. The prover runs the risk check. Destinations
   such as private addresses, wildcards, high ports, and common database
   ports are flagged.
4. Default mode waits. `proposal_approval_mode=auto` approves a proposal
   with no prover finding and no flagged destination. A new public host with
   no provider credential is not treated as a risk, so automatic mode can
   grant that reach without a person.
5. Approval loads the rule without restarting the sandbox. Rejection returns
   a reason. The agent may propose something narrower.
6. If policy or providers change after submission, OpenShell rechecks and
   requires review again. A global policy blocks approval, including
   automatic approval.
7. An approved rule is added beside existing rules. If two rules share a
   host and port, a request is allowed when either allows it. Deny rules in
   either still apply. The proposal cannot remove rules or change
   filesystem, Landlock, or process settings.
8. Agents cannot propose `protocol: tcp`, `tls: skip`, GraphQL, MCP tool
   rules, query matchers, or credential settings. The API ignores those
   fields if sent.
9. Loopback, link-local, and cloud-metadata targets cannot be approved.
   A hostname that resolves to a private address stays blocked after
   approval until `allowed_ips` is set by an operator.

The local API is `http://policy.local` inside the sandbox:
`GET /v1/policy/current`, `GET /v1/denials`, `POST /v1/proposals`,
`GET /v1/proposals/{chunk_id}`, and a wait route. Status values are
`pending`, `approved`, and `rejected`. Logs can show `CONFIG:PROPOSED`,
`CONFIG:APPROVED` with `auto:true`, `CONFIG:REJECTED`, and `CONFIG:LOADED`.

### Mapping onto existing FIP objects

| OpenShell event | FIP object that can record it | What it is not |
| --- | --- | --- |
| Agent asks for a new network rule | `Request` | An Authorization |
| Pending chunk | `REVIEW` or runtime `APPROVAL_PENDING` | Authority |
| Human approve or reject | Input to a FIP `Decision` of kind approval | The Decision itself |
| Automatic approval | Evidence that a target gate opened | A FIP approval Decision |
| Narrower replacement proposal | A new Request | A mutation of the old Authorization |
| Loaded rule | A candidate for compilation and effective-policy verification | Execution authority before those checks |
| Prover finding | `Evidence` | A grant, and not provenance |

FIP already separates these states in
[decisions.md](../specification/fip-0.2/decisions.md):

- `REVIEW` means authority is unresolved.
- `require-approval` can sit on an otherwise authorized requirement and
  still withholds execution until an approval Decision exists.
- `APPROVAL_PENDING` means a target gate is waiting. It does not satisfy
  `require-approval` unless a FIP Decision is recorded.

NVIDIA approval should stay evidence and input to a FIP Decision. The
OpenShell operator who approves a chunk may be a different person from the
organizational approver named by `approverIds`. Automatic approval
specifically must not be treated as that Decision. A new public host
approved by `auto` can be inside the OpenShell risk model and outside the
FIP grant.

Replay and TOCTOU already follow from the advisor text:

- A proposal is stale if policy or providers change before approval.
- Approval applies a live network update. The previous FIP effective-policy
  verification is then invalid.
- Two overlapping allows widen by union of the rules, while denies still
  dominate. A FIP compiler that emits one exact rule can be widened later
  by an approved proposal. The subset proof has to be repeated on the
  effective policy after that load.
- A global policy suppresses provider layers and blocks proposal approval.
  That is a different composition than the base policy M6 verified.

## F. Sentry and BlueField-4 analysis

### Announced Sentry

The 2026-09-28 technical blog and the product page agree on the architecture
claim:

- Sentry is optional and independent of OpenShell.
- It runs on BlueField-4, off the host, using DOCA.
- In a Vera Rubin POD, BlueField-4 sits on the node's only path to the model.
  That position is described as the observation point and the kill switch.
- It correlates agent interactions, policy decisions, and tool and data
  access.
- It is said to verify identity and delegated authority, enforce policy, and
  quarantine in milliseconds.
- OpenShell does not require BlueField-4. On BlueField-4, Sentry is said to
  keep working if the host or workload is compromised.
- The product page says enabling this on an existing Vera system with
  BlueField-4 is a software update. That claim is about systems that already
  have the DPU. It is not a software-only deployment.

No public Sentry policy schema, gRPC service, REST API, or compiler input
was found in OpenShell v0.1.2, in the `v0.1.2...main` file list, or in the
DOCA documents fetched for this study. A production Sentry adapter is not
justified.

### Documented DPU capabilities that are not Sentry

These exist as their own products. They show what out-of-band DPU
enforcement can look like. They do not implement the announced agent-policy
API.

| Capability | Source class | Classification |
| --- | --- | --- |
| Host isolation from DPU management | BlueField zero-trust / restricted mode | `DOCUMENTED`, `HARDWARE-DEPENDENT` |
| Agentless memory inspection and alerts | DOCA Argus service guide and zero-trust reference deployment | `DOCUMENTED`, `HARDWARE-DEPENDENT`. Detection and reporting. The Argus guide does not define an agent-authority compiler. |
| File access control in silicon | DOCA Vault, May 2026 blog | `DOCUMENTED` |
| Line-rate L4 and flow policy | DOCA Flow, May 2026 blog | `DOCUMENTED` |
| Example host-driven 5-tuple firewall | Older DOCA firewall application | `DOCUMENTED` sample, not an agent policy language |
| Request and response inspection of agent tool calls | Sentry announcement | `ANNOUNCED` |
| Quarantine in milliseconds | Sentry announcement | `ANNOUNCED`. No measured interface in this study. |
| Attested telemetry bound to a FIP trace | Not specified as a field contract | `FUTURE / NOT YET AVAILABLE` |
| Public adapter API | Not found | `FUTURE / NOT YET AVAILABLE` |

Per-capability reading of the announcement, without promoting it to an API:

| Claim | Classification |
| --- | --- |
| Out-of-band monitoring | `ANNOUNCED` architecture. Related Argus monitoring is `DOCUMENTED` on BlueField. |
| DPU trust boundary | `DOCUMENTED` for BlueField zero-trust mode. Sentry's use of it is `ANNOUNCED`. |
| Agent isolation | OpenShell isolation is `OPEN-SOURCE IMPLEMENTED`. Sentry tenant isolation is `ANNOUNCED`. |
| Network observation | OpenShell OCSF is implemented. Sentry line-rate observation is `ANNOUNCED`. DOCA Flow enforcement is `DOCUMENTED`. |
| API, tool, and service access | OpenShell REST and MCP rules are implemented with the M6 limits. Sentry "granular" tool policy is `ANNOUNCED` without a schema. |
| Identity | FIP Identity is semantic. Sentry "verifiable identity" is `ANNOUNCED`. No issuer or claim format was published in the sources read here. |
| Telemetry | OpenShell logs are implemented and are not FIP-correlated. Sentry attested telemetry is `ANNOUNCED`. |
| Quarantine | `ANNOUNCED` |
| Attestation | `ANNOUNCED` for Sentry telemetry. No evidence schema. |
| Response latency | "milliseconds" is `ANNOUNCED`. No public measurement method. |
| Independence from host and agent | `ANNOUNCED` for Sentry. `DOCUMENTED` for Argus operating off-host. |

## G. Multi-enforcer model

Let `A` be FIP-authorized operational authority plus explicitly accepted
execution substrate.

Let `O` be the authority OpenShell will allow under the verified effective
policy.

Let `S` be the authority Sentry will allow, once a real policy exists.

The safety property is per enforcer, not a blend:

- `O` is a subset of `A` for every dimension OpenShell claims to enforce.
- `S` is a subset of `A` for every dimension Sentry claims to enforce.
- A dimension neither enforcer covers remains the compiler's problem. It is
  not silently enforced.
- Substrate paths stay out of `A`.

Composition depends on how the packets and calls actually flow.

| Arrangement | Runtime authority | Required FIP reading |
| --- | --- | --- |
| Sequential, both fail closed, both on the path | Intersection of `O` and `S`, and that intersection must stay inside `A` | An allow needs both layers. A deny from either layer stops the action. |
| Parallel observation, one layer does not block | The blocking layer's authority | The observer is evidence. It is not an enforcer. |
| One layer fail-open | The fail-closed layer only | A fail-open layer must not be counted in the subset proof. |
| Enforcer unavailable | No authority from the missing layer | Missing enforcement is not permission. If the deployment required that layer, execution stops. |
| Policies disagree | No execution on the disputed action until both verified policies allow it and the allow is inside `A` | Disagreement is `REVIEW` or a failed verification, not a union. |
| Stale policy or version mismatch | Prior verification is void | Re-read and re-verify before execution. |
| Partial coverage | Only the covered dimensions are enforced by that layer | Uncovered dimensions stay `unsupported` for that layer. |

Union is the wrong safety property. Union would let Sentry allow what
OpenShell denies, or the reverse. Intersection is the right property only
when both layers are required, fail closed, and actually on the path.
Independent observation does not shrink or enlarge `A`.

## H. Proposed proof chain

| Link | Today | Later |
| --- | --- | --- |
| Mission Blueprint version | Outside this repository. CAMEO concept. | Bind as provenance input. |
| GOCP version | Profile identity exists as architecture. Active profile is immutable during a run. | Hash the profile that fed the FIP document. |
| FIP AuthorityPolicy version | `policyId`, `traceId`, validity, provenance. | Keep. |
| Exchange | FIP document. | Keep. |
| Enforcement IR hash | IR is produced. A deployment can hash it. | Store beside the policy hash. |
| OpenShell policy hash | M4 and M5 already store the FIP canonical hash and the distinct native load hash. | Keep those hashes distinct. |
| NVIDIA prover result | CLI exists in the pin. Not attached to FIP evidence. | Record `within_boundary` or the failing result as Evidence. `unsupported` is not a pass. |
| Effective policy hash | M5 read back `--base` and `--full`. | Repeat after any advisor approval or provider change. |
| Sentry policy hash | No public object to hash. | Future, after an interface exists. |
| Runtime observations | M4 and M5 FIP-side records. Target logs lack FIP identifiers. | Correlation still requires those identifiers. A Sentry attestation would be another evidence source, not an automatic upgrade to correlated audit. |

Today's chain can close through the OpenShell policy hash, the effective
policy hash, and FIP-side observations. It cannot yet close through a prover
artifact or a Sentry configuration hash.

## I. CAMEO impact

The NVIDIA platform does not justify merging authority into the Security
Plan.

Recommended split:

- The Mission Blueprint still yields an Execution Plan and an Authority Plan.
- The Authority Plan is realized by GOCP and then FIP. That is the semantic
  grant.
- The Security Plan stays target-neutral. It names enforcement domains,
  required verifiers, and fail-closed rules. It does not grant authority.
- OpenShell policy and a future Sentry policy are compilations from the
  Enforcement IR, selected by the Security Plan. They are not a second
  authority language.

NVIDIA provides both a prover and an enforcer. That is a reason to list
them as realization mechanisms inside the Security Plan. It is not a reason
for the Security Plan to become the Authorization.

## J. BILLA OS impact

NVIDIA infrastructure, on the sources above:

- sandbox and software policy enforcement
- target-policy containment proofs for modeled domains
- a human or automatic workflow for network-rule proposals
- an announced out-of-band monitor and enforcer on BlueField-4

Interbilla governance and orchestration still has the work NVIDIA does not
claim:

- multi-agent mission orchestration and who is assigned which mission
- mission context and recompilation when the mission changes
- UDG semantic federation across domains that do not share an OpenShell
  policy file
- law, policy, and organizational authority, including purpose and
  prohibition
- cross-agency and cross-enterprise governance
- GOCP derivation of what may enter FIP
- FIP semantic authority as the portable grant
- human roles in the organization, distinct from an OpenShell operator
- runtime observations fed back into the mission
- choice among enforcement backends, including non-NVIDIA ones

OpenShell can host several sandboxes. That is process isolation, not mission
orchestration. The prover can check a parent policy against a subagent
policy. That is target containment, not a federated authority decision.
The advisor can collect a human click. That click is local evidence, not an
organizational role.

## K. FIP impact

Outcome: `NO_CHANGE` for FIP 0.2.

FIP 0.2 already has 28 primitives and 26 relationships. Evidence, Decision,
Provenance, Validity, Scope, Condition, Request, and the states `REVIEW`,
`require-approval`, and `APPROVAL_PENDING` cover the NVIDIA workflow without
a new primitive.

Future items, if a deployment needs them, should be evidence or metadata
first:

| Need | Existing home | Not required now |
| --- | --- | --- |
| Prover result | Evidence attached to the compilation or execution record | A Proof primitive |
| NVIDIA approval | Evidence consumed by a Decision | Treating the chunk id as an Authorization |
| Which enforcer | Adapter and target identity on the IR | An Enforcer primitive |
| Attestation or quarantine | Evidence and a runtime disposition | A Quarantine primitive |
| Policy-version binding | Provenance plus the hashes already stored | A new binding kind |
| Hardware enforcement | A future adapter, still fail closed | A hardware primitive |

`FIP_0.3_CANDIDATE` is not justified. `OPTIONAL_EXTENSION` of evidence
schemas can wait until a prover backend or a Sentry interface is actually
integrated.

## L. SMF impact

The Semantic Micro-Firewall remains the semantic decision point. Its
decisions stay `PERMITTED`, `DENIED`, `INCOMPLETE`, and `ESCALATE`, mapped
into FIP 0.2 as specified in
[compatibility.md](../specification/fip-0.2/compatibility.md).

OpenShell remains the software execution enforcer for the dimensions M6
accepted. Sentry, if it ships with a real policy interface, would be an
independent infrastructure enforcer.

The SMF is not redundant. OpenShell and the announced Sentry express
filesystem paths, hosts, ports, methods, binaries, and, in the announcement,
tool and data access. They do not express purpose, prohibition dominance,
delegation bounds, validity, or cross-enterprise authority. A lower-level
allow is not a semantic permit.

## M. Cross-enterprise implications

Scenario: a fire department holds a mission authority, and a law-enforcement
agency must act under a federated grant.

NVIDIA can enforce the local consequence after the local agency accepts the
grant:

- local OpenShell policy for files, REST, and TCP that the local compiler
  can represent
- local prover check against that agency's own maximum policy
- local human approval of a network proposal, as evidence
- local credential attachment, still not a portable credential authority
- local Sentry, later, on that agency's own BlueField path

FIP and UDG still have to carry, across the boundary:

- the foreign authority and its scope, purpose, and validity
- the local re-evaluation. The receiving agency does not inherit the
  sender's OpenShell YAML as authority
- the local Decision, including any human organizational approval
- provenance of the exchange
- the rule that a local target restriction may narrow the grant and must
  not enlarge it

An OpenShell policy file is not portable organizational authority. A Sentry
configuration on one agency's DPU is not a grant the other agency can rely
on.

## N. Strategic overlap matrix

`PRIMARY` means the layer owns the decision or artifact.
`SUPPORTING` means it supplies a mechanism the owner uses.
`POSSIBLE` means a later or partial role, not a current contract.
`NOT RESPONSIBLE` means this layer should not own it.

| Concern | NVIDIA | BILLA OS | CAMEO | UDG/GOCP | FIP/SMF |
| --- | --- | --- | --- | --- | --- |
| Mission definition | NOT RESPONSIBLE | PRIMARY | SUPPORTING | SUPPORTING | NOT RESPONSIBLE |
| Agent orchestration | POSSIBLE | PRIMARY | SUPPORTING | NOT RESPONSIBLE | NOT RESPONSIBLE |
| Semantic context | NOT RESPONSIBLE | SUPPORTING | SUPPORTING | PRIMARY | SUPPORTING |
| Organizational authority | NOT RESPONSIBLE | PRIMARY | SUPPORTING | SUPPORTING | PRIMARY |
| Policy derivation | NOT RESPONSIBLE | SUPPORTING | SUPPORTING | PRIMARY | SUPPORTING |
| Semantic authorization | NOT RESPONSIBLE | SUPPORTING | NOT RESPONSIBLE | SUPPORTING | PRIMARY |
| Policy verification | PRIMARY for target policy | SUPPORTING | POSSIBLE | NOT RESPONSIBLE | PRIMARY for the FIP subset |
| Human approval | SUPPORTING for network chunks | PRIMARY for organizational roles | NOT RESPONSIBLE | NOT RESPONSIBLE | PRIMARY for the Decision |
| Filesystem enforcement | PRIMARY | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | SUPPORTING |
| Network and API enforcement | PRIMARY | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | SUPPORTING |
| Credential mediation | SUPPORTING | SUPPORTING | NOT RESPONSIBLE | NOT RESPONSIBLE | PRIMARY for use authority |
| Tool enforcement | POSSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | SUPPORTING |
| Process isolation | PRIMARY as substrate | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE for exact identity |
| Hardware monitoring | PRIMARY where the DPU exists | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE | NOT RESPONSIBLE |
| Quarantine | POSSIBLE | SUPPORTING | NOT RESPONSIBLE | NOT RESPONSIBLE | POSSIBLE as evidence |
| Audit | SUPPORTING target logs | SUPPORTING | NOT RESPONSIBLE | SUPPORTING | PRIMARY for correlation rules |
| Runtime feedback | SUPPORTING | PRIMARY | SUPPORTING | SUPPORTING | SUPPORTING |
| Mission recompilation | NOT RESPONSIBLE | PRIMARY | PRIMARY | SUPPORTING | NOT RESPONSIBLE |

NVIDIA is `PRIMARY` for target-policy verification of OpenShell policies, and
FIP is `PRIMARY` for the subset against semantic authority. Those are
different proofs.

## O. Gap analysis

### A. NVIDIA capabilities FIP does not try to express

- SMT containment of one OpenShell policy inside another
- Kernel sandbox, seccomp, and Landlock ABI behavior
- Live network-rule chunks and `policy.local`
- DPU placement on the path to a model
- Line-rate DOCA flow enforcement and Argus memory inspection
- Announced millisecond quarantine

These belong in adapters and evidence, not in new primitives.

### B. FIP semantics NVIDIA enforcement does not enforce

On v0.1.2, from M6 plus the prover and advisor pages:

- credential-use authority separate from network reach
- exact model identity
- exact executable identity
- MCP arguments, and any MCP rule inside the prover
- query-bearing REST
- purpose, prohibition dominance, delegation, validity, and scope as
  organizational bounds
- correlated audit with FIP identifiers
- cross-enterprise re-authorization

Sentry's announcement names identity, tools, and data access. Until a schema
exists, those remain announcements.

### C. CAMEO capabilities NVIDIA does not attempt

Mission blueprints, paired execution and authority plans, and a
target-neutral security plan. NVIDIA policies are target policies.

### D. Duplicates

- Human approval of a network change, if a deployment treats the OpenShell
  click as the FIP Decision
- Two subset proofs, if the FIP boundary and the prover boundary are copies
  of the same policy and nobody records which question each answered
- Audit logs, if target OCSF is upgraded to correlated audit without FIP
  identifiers

### E. Complementary capabilities

- FIP says what is authorized. OpenShell enforces a modeled slice.
- The prover checks target containment the FIP verifier does not encode as
  SMT, including some glob and L4-versus-REST cases inside its model.
- The advisor collects a local approval. FIP records whether that event
  satisfies `require-approval`.
- A future Sentry can watch the path to the model from outside the host.
  FIP still decides whether that observation is evidence or an enforcement
  requirement.

### F. Integration opportunities

- Record prover JSON (`result`, `reason_code`, `coverage.domains`) as
  Evidence next to a compiled policy. Fail closed on every result other
  than `within_boundary`.
- Treat advisor chunk status as `APPROVAL_PENDING` until a FIP Decision
  exists, then re-verify the effective policy.
- Keep Sentry as a named future domain with no compiler.

### G. Dependency and portability risks

- FIP must compile to more than one backend. Intel, Arm hosts without
  BlueField, cloud runtimes, robots, drones, and disconnected sites need a
  path that does not require Vera or BlueField-4.
- The product page says OpenShell runs without BlueField-4 and is compatible
  with other hardware. Sentry does not. A deployment that requires Sentry
  is hardware-specific. The FIP grant must still be expressible where Sentry
  is absent, with that absence recorded as a missing enforcer rather than
  as an allow.
- Automatic approval can widen public-network reach inside NVIDIA's risk
  model. Binding mission safety to that default would import a
  NVIDIA-specific widening rule.
- The prover's `unsupported` domains are a moving target on `main`. An
  integration must pin the prover the same way M6 pins the runtime.

## P. Integration roadmap

| Stage | Content | Classification |
| --- | --- | --- |
| 1 | Pinned v0.1.2 adapter, M4 through M6 | `NOW` |
| 2 | Call `openshell-prover` on a compiled policy and a declared boundary. Store the JSON. Do not treat it as the FIP subset proof. | `PROTOTYPE` |
| 3 | Map advisor pending, approve, and reject into Evidence and a FIP Decision. Re-verify after `CONFIG:LOADED`. | `PROTOTYPE` |
| 4 | Ingest Sentry observations if NVIDIA publishes a schema. | `WAIT_FOR_NVIDIA_API` |
| 5 | Compile an Enforcement IR slice to Sentry. | `WAIT_FOR_NVIDIA_API` |
| 6 | One proof chain across blueprint, GOCP, FIP, IR, OpenShell, prover, effective policy, and Sentry. | `RESEARCH` |

Stages 2 and 3 are optional prototypes after Q13. They are not required to
make the M6 gate true.

## Q. Effect on Q13

Q13 stays the experimental campaign against FIP 0.2 and the pinned v0.1.2
adapter. The announcement does not change that plan and does not reopen
FIP 0.1 results.

- Prover-targeted attacks and approval-escalation attacks are useful later.
  They need the prover CLI and a live advisor, which this study did not run.
  They are not a reason to hold Q13.
- Multi-enforcer attacks belong with stage 6.
- Sentry attacks wait until an implementation and an interface exist.

## R. Files added

- `docs/research/nvidia-open-agent-safety-platform-integration-study.md`
- `docs/research/nvidia-open-agent-safety-platform-capabilities.json`

No executable FIP artifact, M4 artifact, M5 artifact, or M6 conformance
artifact was edited. FIP 0.2 provenance was not regenerated.
`docs/research/` is outside that provenance root.

## S. Checks

`python tests/check_links.py` passed. `python tools/public_release_audit.py`
passed with 0 findings. `git diff --check` on `docs/research` produced no
whitespace errors. FIP 0.2 provenance was not regenerated.

## T. Git status

HEAD remains `affa5fc2ae1e9b18e141c7e16b09d83debcdfdbf` on
`feature/openshell-integration`. This study adds untracked files under
`docs/research/`. The uncommitted M6 tree is otherwise unchanged. No commit,
push, tag, or merge.

## U. Recommendation

`KEEP_M6_AND_PROCEED_TO_Q13`

Do not implement prover or advisor integration before Q13. Do not wait for
a Sentry interface before Q13. Do not revise FIP 0.2 before Q13.
