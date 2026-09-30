# Enforcement IR

The Enforcement IR is a compilation contract. It is not an AuthorityPolicy, not
an Exchange, and not a primitive. A target adapter consumes the IR. It does
not consume vendor fields inside an authoring document, because those fields
are not part of FIP.

The shape is [schema/enforcement-ir.schema.json](schema/enforcement-ir.schema.json).

## Producer and consumers

A future compiler produces an IR only after it has an `authorityDecision`.
Adapters MUST NOT produce an IR that upgrades `DENIED`, `INCOMPLETE`, or
`REVIEW` into `AUTHORIZED`.

The IR MUST include:

| Field | Rule |
| --- | --- |
| `irVersion` | The string `0`. |
| `fipVersion` | The string `0.2`. |
| `policyId` | The source policy. |
| `traceId` | Copied from the policy or exchange. |
| `authorityDecision` | One of the four authority values. |
| `compilationDisposition` | One of the four compilation values. |
| `deployable` | `true` only when `compilationDisposition` is `FULL`. Otherwise `false`. |
| `codes` | Reason codes from [decisions.md](decisions.md). |
| `requirements` | One node per EnforcementRequirement in the projected slice. Each node carries its effect, binding identifiers, resolved constraints and conditions, lifetime, audit strength, composition, group, authority or prohibition reference, trace id, and a coverage status. |
| `groups` | Every composition group that contributed a requirement, with the full member list. An `allOf` group is not reduced to one member. |
| `prohibitions` | Applicable prohibitions. A prohibition stays in the IR when another action in the same policy was authorized. |
| `bindings` | Snapshots of the ExecutionBindings that the slice references, still in FIP vocabulary. |
| `coverage` | The coverage object defined in [adapters.md](adapters.md). |

`exchangeId` MUST be present when the compilation was requested for one
exchange, and MUST be omitted when the compilation is of a standing policy
with no exchange.

## Target-neutral projection

A projection that has not been matched to a Capability Manifest is not a
compilation. Its `compilationDisposition` is `NOT_COMPILED` and `deployable`
is false. It MUST NOT use `FULL`, `PARTIAL`, or `REJECTED`. Those values
require a Capability Manifest.

Only an `AUTHORIZED` operational slice is projected. `DENIED`, `INCOMPLETE`,
and `REVIEW` produce no operational IR. A semantic-only `AUTHORIZED` document
may produce a semantic trace. It produces no execution bindings. An
outstanding `require-approval` produces no operational IR. A satisfied
approval is recorded with its Decision and provenance, and the requirement
effect remains `require-approval`.

Every requirement `coverage` value in this projection is `unassessed`.
`coverage.auditCoverage` is `unassessed`. `targetBaseline` is empty. The
requirement's own `audit` value is preserved and is not a claim that an
audit event was produced.

The projection copies locators and protocol parameters that the author wrote
on a binding. It does not invent a path from a resource identifier, a method
from an action name, or a hostname from a service name. Unknown or `custom`
kinds and operations produce no operational IR. The IR contains no vendor
policy fields.

## No independent authority

An Enforcement IR is a derived projection of a semantic authorization
evaluation. It is not an Authority, an Authorization, a Permission, a
Decision, or an independent grant. Internal validity of an IR, and the fact
that a target adapter can enforce the requirements written in it, do not make
that IR deployable.

Coverage and an adapter MUST NOT treat the supplied IR as a second source of
authority. This rule adds no primitive and no relationship. It does not add
an authority-state primitive. It completes the existing projection and subset
rules.

## Derivation

Before coverage can produce a deployable `FULL` result, and before an adapter
can produce a deployable target policy, the implementation MUST establish that
the security-relevant content of the consumed Enforcement IR equals a fresh
projection of the applicable semantic evaluation:

```text
IR_consumed == Project(Eval(
    AuthorityPolicy,
    Exchange,
    applicable Decisions,
    current governed context))
```

`Exchange` is omitted when the compilation is of a standing policy with no
exchange. The specification requires the equality. It does not require a
particular mechanism such as a hash, a signature, or an in-memory seal.

If that equality cannot be demonstrated, or the security-relevant content
differs, `compilationDisposition` is `REJECTED` with `subset_not_demonstrated`.
The result MUST NOT be `FULL` or `PARTIAL`. No deployable target policy is
produced. A failed derivation check occurs before a deployable `FULL`.

When the current evaluation itself yields no operational IR, there is nothing
to deploy. A supplied IR that does not equal that absence is `REJECTED` under
the same code. The source document's own authority decision is unchanged.

Integrity and freshness are different duties. Integrity means the IR matches
the projection of an identified semantic authority state. Freshness means that
state is still the applicable state at deployment. A projection verified under
an older state MUST NOT remain deployable after the applicable authority or
context changes. Deployability requires a new current evaluation and
projection. If that new state produces identical security-relevant content,
the content may qualify again only through the new verification.

## Security-relevant content

The derivation comparison covers the content that can change what is
authorized or what a target may enforce. It includes:

- the semantic decision that deployment would rely on
- requirements, including effect, audit strength, and lifetime
- requirement composition and group membership
- prohibitions
- binding identifiers
- the bound Resource and the bound Action
- binding kind, operation, locator, and protocol
- approval records represented in the projection
- any classification that would move accepted execution substrate into the
  grant set used for the subset proof

Informational metadata is not authority merely because it appears in the
artifact. Trace metadata MAY be excluded from the equality when it does not
change authority. A target-specific annotation MAY be excluded only when it
cannot change effective target authority. An annotation that changes the
emitted allow is security-relevant.

## Derivation obligations

These obligations are the derivation check. They do not add a second
evaluator.

| Id | Obligation |
| --- | --- |
| P1 | Every permit in a deployable IR corresponds to a current semantic Authorization. |
| P2 | Every binding snapshot matches the selected binding, including Resource and Action. |
| P3 | No operation is wider than the selected binding. |
| P4 | No locator is wider than the selected binding. |
| P5 | Required composition is not weakened, including `allOf` replaced by `anyOf` or a required member dropped. |
| P6 | Applicable prohibitions from the fresh projection are preserved. |
| P7 | No lifetime is longer than the selected requirement. |
| P8 | Accepted execution substrate stays distinct from `fipGrants`. |
| P9 | The policy, exchange, Decisions, and governed context used for the check are the current ones. |
| P10 | Any security-content mismatch is `REJECTED`, not `PARTIAL` or `FULL`. |

P1 through P9 hold when the security-relevant content equals the fresh
projection of the current evaluation. A mismatch such as a locator replaced by
an ancestor path, an operation replaced by a broader operation, a binding
identifier kept while its locator or operation changes, a requirement added or
removed, composition weakened, a lifetime lengthened, or substrate promoted
into `fipGrants` is P10. A change confined to trace metadata, or to a
target annotation that cannot change effective authority, is not by itself a
mismatch. An exact regenerated security projection satisfies the check. After
the applicable authority or context changes, the previous projection is stale
until a new check passes.

## Deployable bit

`deployable` MUST be `true` if and only if `compilationDisposition` is `FULL`.
A `PARTIAL` IR MAY include `candidate`, which is diagnostic. `candidate` MUST
NOT be installed. A conforming implementation MUST NOT treat `candidate` as a
policy source.

A `REJECTED` or `NOT_COMPILED` IR MUST NOT include an installable rule set.
`candidate` on those dispositions, if present, MUST be limited to diagnostics
and MUST have no allow rules.

## Adapter annotations

`adapterAnnotations` is an object whose keys are adapter identifiers and whose
values are opaque. Core evaluation MUST ignore them. They MUST NOT be required
to decide authority. They MUST NOT introduce a primitive, relationship, kind,
or effect.

An annotation MAY record a target rule identifier so audit correlation can
point at it. That identifier is not FIP vocabulary.

## What the IR must not contain

The IR schema is closed. A conforming IR MUST NOT contain a vendor policy
document as a normative field. A future adapter writes its target document
beside the IR, not inside the FIP vocabulary. If an implementation embeds a
target document, it does so only inside `adapterAnnotations`, and coverage
remains the FIP account of what was enforced.
