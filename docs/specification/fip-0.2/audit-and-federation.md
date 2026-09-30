# Audit correlation and cross-enterprise behavior

## Audit correlation

An audit correlation record is an observability object. It is not a primitive
and it is not an authorization. The shape is
[schema/audit-correlation.schema.json](schema/audit-correlation.schema.json).

A record that claims `runtimeDisposition` other than `UNOBSERVED` MUST include
`traceId`, `requirementId`, and enough target identity to find the event
(`targetRuleId` or `targetEventId`). It SHOULD include `policyId`,
`exchangeId` when an exchange was evaluated, `authorizationId`, `bindingId`,
`irNodeId`, `adapterId`, and `observedAt`.

`adapterId` names the adapter that observed the event. It is allowed on this
record and on a Capability Manifest. It is not allowed as a FIP primitive,
relationship, kind, or protocol family.

Correlation records are append-only. A later Decision MAY reference an earlier
`traceId`. It MUST NOT rewrite the earlier record.

`audit` `correlated` on a requirement is satisfied only when a correlation
record of this form can be produced for the enforced effect. A target log that
names only the target's own policy key does not by itself satisfy the duty.
An adapter MAY keep a sidecar from the target key to `requirementId` and
`traceId`. If the sidecar is missing, the duty is unmet and a compilation that
required it MUST NOT be `FULL`.

`audit` `target-native` is satisfied by the target channel named in the
manifest, without FIP identifiers. Coverage MUST say which strength was
achieved. A native event does not upgrade the strength to `correlated`.

## Runtime observation

A runtime observation is a FIP-side record of one observed outcome. Its shape
is [schema/runtime-observation.schema.json](schema/runtime-observation.schema.json).
`correlationSource` is `fip-side`. The target-native evidence sits in
`targetNativeEvidence` and is not itself this record.

A runtime observation is not an audit-correlation record. A FIP-side runtime
observation MUST NOT be used to claim that the target provides correlated
audit. `openshellEventId` and `targetEventId` may be null. A null event id
does not satisfy `audit` `correlated`.

The record has three categories:

| Category | `authorityClass` | `fipGrant` | What identifies it |
| --- | --- | --- | --- |
| FIP grant observation | `fip-grant` | `true` | `requirementId` and `bindingId` name the grant. `runtimeDisposition` is `ENFORCED_ALLOW`. |
| Unauthorized-operation observation | `unauthorized` or `implicit-workdir` | `false` | `requirementId` may be null. `ENFORCED_DENY` does not make the operation a FIP grant. |
| Execution-substrate observation | `execution-substrate` | `false` | `substrateId` names the accepted execution substrate. The observation is not a `fipGrant`. |

## Cross-enterprise behavior

The portable object across an enterprise boundary is the semantic authority
plus the enforcement requirements. Execution bindings are local and MAY be
replaced by the receiver's own bindings. A sender's locators are hints unless
the receiver adopts them.

A sender's `authorityDecision` is Evidence in the receiver's provenance. It is
not an Authorization. The receiver's Semantic Micro-Firewall MUST
re-evaluate the exchange under the receiver's policy. A foreign decision MUST
NOT manufacture authority.

A received foreign Enforcement IR is not a local Authorization. It MAY be
treated as Evidence, as a proposal, or as a requested enforcement shape. The
receiver MUST derive any locally deployable projection from its own applicable
AuthorityPolicy, Exchange, Decisions, governed context, and local bindings, as
specified in [enforcement-ir.md](enforcement-ir.md).

The receiver compiles with its own adapter and its own Capability Manifest.
Coverage is not transitive. One enterprise's `ENFORCED_ALLOW` does not satisfy
another enterprise's obligation and does not establish the other enterprise's
`FULL` compilation.

A receiver that drops an enforcement requirement and still reports `FULL` has
violated the subset and coverage rules. The receiver MUST report `PARTIAL` or
`REJECTED`, and MUST NOT report a deployable artifact that omits the
requirement, unless that requirement was not in the received policy.

Bindings MAY be stripped at the boundary. Requirements MUST NOT be stripped.
If the receiver cannot express a received requirement, the requirement stays
in the IR as `unenforced` or `rejected`, and disposition follows
[decisions.md](decisions.md).

Delegation across enterprises uses `delegatesTo` and `delegatesAuthority`.
There is no implicit trust of a foreign compiler.
