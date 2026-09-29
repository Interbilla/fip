# Adapters, coverage, and substrate

## Capability Manifest

Every target adapter MUST publish a Capability Manifest. The shape is
[schema/capability-manifest.schema.json](schema/capability-manifest.schema.json).

The manifest is an adapter artifact. It is not an AuthorityPolicy. Its
`adapterId` MAY be any non-empty string, including a product name. That string
is not a FIP primitive.

A manifest MUST state:

| Field | Content |
| --- | --- |
| `acceptsFipVersions` | MUST include `0.2` for an adapter that claims to compile this specification. |
| `kinds`, `operations`, `protocolFamilies` | The closed sets the adapter can enforce. |
| `capabilities` | Each capability class names the kinds it covers and the lifetimes it can enforce for those kinds. A lifetime on one class does not apply to another class. |
| `effects`, `auditStrengths` | The effects and audit strengths it can enforce. |
| `substrate` | Controls the target applies around the execution context. Each entry MUST set `authorityBearing` to false. `substrateClass` classifies the entry. |
| `dangerousDefaults` | Defaults that are weaker than a stated FIP effect, such as a log-only mode that still forwards traffic. |

An adapter MUST refuse to compile a requirement whose kind, operation,
protocol family, effect, or audit strength is outside the manifest. Lifetime
is scoped to the capability class whose `kinds` include the binding kind. The
named lifetime MUST appear on that class. A lifetime listed for another class
does not satisfy it. Coverage does not substitute one lifetime for another.

## Subset invariant

Emitted target authority MUST be a subset of FIP-authorized authority.

FIP-authorized authority is the set of operations that remain after:

- non-`AUTHORIZED` acts are removed,
- prohibitions dominate overlapping permits,
- unsatisfied approvals and obligations are removed,
- and only requirements the manifest can enforce without widening remain.

If an adapter cannot demonstrate the subset relation for a rule it would
emit, compilation is `REJECTED` with `subset_not_demonstrated`. The adapter
MUST NOT emit that rule as deployable.

The following are widenings and MUST be rejected rather than approximated:

- a method or path constraint compiled as bare connectivity,
- a tool constraint compiled as a host grant,
- a single permitted operation compiled as every operation on that locator,
- a deny or a narrow permit compiled as a log-only control that still allows
  the operation,
- a locator pattern replaced by a broader locator,
- a proxy-mediated credential compiled as process-visible secret material,
- a model invocation compiled as general reachability to the provider,
- a device command compiled as a network request.

A target control that is strictly narrower than the FIP permit MAY be emitted.
Coverage MUST identify the narrowing. Narrowing does not authorize a second
operation that FIP did not name.

## Coverage

Coverage is reported per requirement and summarized on the IR. The summary
MUST separate three accounts. They MUST NOT be collapsed into one allow list.

| Account | Contents |
| --- | --- |
| `fipGrants` | Undominated permit requirements that constitute FIP-authorized operations. |
| `targetEnforcement` | Requirements actually enforced, unenforced, or rejected by this target. |
| `targetBaseline` | Substrate the target applies. Each entry is not a FIP grant. |

Per-requirement status is exactly one of:

| Status | Meaning |
| --- | --- |
| `unassessed` | No Capability Manifest has been applied. This is the only status a target-neutral projection may use. It is not `enforced`, `unenforced`, or `rejected`. |
| `enforced` | The target control is as tight as the requirement, or strictly tighter, including lifetime and audit strength. |
| `unenforced` | The target has no faithful control. No compensating allow was invented. |
| `rejected` | Emitting a control would widen, weaken, or outlive the requirement. |

`enforced`, `unenforced`, and `rejected` are coverage outcomes. A
target-neutral projection MUST leave every requirement `unassessed` and MUST
leave `targetBaseline` empty. Coverage evaluation is a separate assessment.
It does not emit a target policy.

`baseline` is a status of substrate entries only. A baseline entry is not a
requirement status and it is not added to `fipGrants`.

## Coverage disposition

| Disposition | When | `deployable` |
| --- | --- | --- |
| `FULL` | Every required `allOf` group is enforced, every `anyOf` group has one exact enforced alternative, every prohibition is enforced, and baseline does not exceed the grants. | `true`. Eligible for a later compilation. No target policy has been produced. |
| `PARTIAL` | At least one requirement is enforced and a required group is only unenforced, with no widening and no baseline excess. | `false`. Diagnostic. Not installable. |
| `REJECTED` | A required requirement would widen, weaken, or outlive the grant, a prohibition cannot be enforced, or baseline exceeds the grants. | `false`. |
| `NOT_COMPILED` | The input is not an operational IR, or the manifest cannot be assessed. | `false`. |

An unselected `anyOf` alternative keeps its own status. It does not remove
`FULL` when another listed alternative is enforced exactly.

`deployable` true does not mean runtime execution is allowed. `AUTHORIZED`,
`FULL`, and `ENFORCED_ALLOW` remain different facts.

M0 does not define a total order among `establishment-bound`, `revocable`,
and `validity-bound` beyond this: a control that lasts for the whole
execution context does not satisfy `revocable` or `validity-bound`. Coverage
requires the named lifetime. It does not substitute one lifetime for another.

M0 does not define `correlated` as a superset of `target-native`. Coverage
requires the named audit strength. `target-native` does not satisfy
`correlated`. `correlated` does not satisfy `target-native`. `none` attaches
no audit duty.

`compilationDisposition` `FULL` requires every requirement in the slice to be
`enforced` and none `rejected`, and requires `targetBaseline` not to grant
authority beyond `fipGrants`.

`PARTIAL` MUST set `deployable` to false. It MAY include diagnostics, a
candidate, and this coverage object. The candidate is not a policy.

## Credential precision

Disclosure and binding precision are separate.

| Dimension | What it decides |
| --- | --- |
| `credentialDisclosures` | Whether the target can keep the secret out of the process (`none`, `proxy-mediated`) or must hand the secret to the process (`process-visible`). |
| `credentialBinding.dimensions` | The locator dimensions the target can constrain: `provider` (the binding `serviceId`), `host`, `port`, `path`, and `protocol`. |
| `credentialBinding.required` | Dimensions that MUST be present on the binding. A missing required dimension is a broader boundary. |

A disclosure match does not enforce a credential binding whose required
dimensions are absent. A precise locator does not enforce a disclosure the
manifest does not list. Either failure is `subset_not_demonstrated`.

A target MAY enforce an exact proxy-mediated boundary without listing kind
`credential`, when `credentialBinding` matches the binding. Absence of the
kind is not, by itself, a rejection. A boundary wider than `required` is
rejected. Compiling `proxy-mediated` as `process-visible` remains a widening.

## Target baseline

Substrate is the set of controls a target applies so an execution context can
exist. It is not a FIP grant. Coverage repeats each entry under
`targetBaseline` with `authorityBearing` false, `status` `baseline`, the
manifest `adapterId` in `declaredBy`, and `acceptance` `accepted` or
`unaccepted`.

| Class | Meaning | May be execution substrate |
| --- | --- | --- |
| `restrictive` | A control that narrows the execution context, such as a syscall filter. | Yes. |
| `read-only-runtime` | Read access the runtime needs, such as libraries or CA material. | Yes. |
| `writable-runtime` | A writable runtime facility, such as a temporary workspace or a null device. | Yes, only when a compilation profile accepts that class or that exact item. |
| `operational-authority` | Authority the target adds, such as an unrelated writable directory or unrestricted network. | No. |

An entry with no `substrateClass` is `operational-authority`. A class that
does not match the operation is not execution substrate: a write labeled
`read-only-runtime` or `restrictive`, or a network connect labeled
`writable-runtime`, stays subject to the excess-grant rule.

### Acceptance

A substrate entry is `accepted` only when all of the following hold:

1. The Capability Manifest declares it.
2. Its class is `restrictive`, `read-only-runtime`, or `writable-runtime`.
3. The FIP compilation profile permits that class, or the exact item, in `acceptedExecutionSubstrate`. The profile is not part of the target manifest. The target cannot satisfy this condition by labeling the entry.
4. The entry does not cover a locator or kind named by an explicit prohibition or deny requirement.
5. Coverage still lists the entry under `targetBaseline`.

Accepted substrate MUST NOT be copied into `fipGrants` and MUST NOT enlarge
the authorized operations. If any condition fails, and the entry gives the
actor an operation the grants do not include, compilation is `REJECTED` with
`baseline_exceeds_grant`. There is no implicit exemption for a path, a device,
an operating system, or a product.

A compilation profile MAY list `targetExecutableRestrictions`. Each entry is
a path the deployment configures for a target that needs a non-empty binary
list. That path is deployment configuration. It is not an ExecutionBinding,
it is not copied into `fipGrants`, and it does not make executable identity
part of the semantic grant. A compiler that needs such a path MUST read it
from this list. It MUST NOT infer the path from a FIP document. On a target
whose binary rule also applies to descendant processes, the restriction
narrows which program may start the operation and does not prove exact
process identity.

The initial OpenShell REST compilation profile does not support a query
component. A locator URI that contains `?` MUST fail closed. Coverage is
`REJECTED` with `subset_not_demonstrated`. The adapter diagnostic is
`query_precision_unsupported`. The compiler MUST NOT ignore the query, strip
it, or emit a query matcher. That rejection is not FIP query authorization.
A target that accepts a query-bearing request on an otherwise exact path,
such as `GET /?x=1`, does not authorize a FIP query. That observation
prevents a claim of complete runtime monotonicity for this REST slice.

A successful base-policy compilation leaves `runtimeDisposition` at
`UNOBSERVED`. It is not a runtime enforcement claim. Before a runtime allow is
accepted, the live `policy get --full` document MUST pass effective-policy
verification on host, port, protocol, enforcement, HTTP method, HTTP path,
binary restriction, access preset, and TLS inspection. Provider or global
widening fails closed.

An undisclosed dangerous default is treated as an inability to demonstrate the
subset invariant. Compilation is `REJECTED`.

## M2C and existing coverage expectations

The 25 M2B situations keep their dispositions.

| Situation | Expectation after M2C |
| --- | --- |
| Exact filesystem, REST, model, proxy credential, prohibition, and correlated audit on the full-capability fixture | Still `FULL`. The fixture's credential binding requires `provider`, which the proxy example's `serviceId` supplies. |
| Read/write bundle, host-only REST, provider-only model, process-visible credential, widened allOf, audit-only effect, static lifetime, dangerous any-host | Still `REJECTED` for the same reason codes. |
| allOf with the credential mechanism removed | Still `PARTIAL`. Removing only kind `credential` is no longer enough when `credentialBinding` still matches the binding. The M2B fixture clears the disclosure list and the binding precision as well. |
| Writable `/tmp` on the broad-baseline fixture | Still `REJECTED` with `baseline_exceeds_grant`. The entry is `writable-runtime`. No compilation profile accepts it, so the class label does not accept it. The row now also reports `substrateClass`, `acceptance` `unaccepted`, and `declaredBy`. |
| Revocable REST on the non-revocable fixture | Still `lifetime_mismatch`. That fixture's network capability lists only `establishment-bound`. |
