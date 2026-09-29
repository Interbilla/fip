# EnforcementRequirement

EnforcementRequirement is the primitive that states a required security
outcome. It does not state how a product implements that outcome.

A requirement MUST include `requirementId`, `effect`, and `composition`. It
MUST reference one or more bindings through `bindingIds` or a
`bindingPattern`, unless its effect is `audit-only` and it references other
requirements through an Obligation. A permit, deny, or require-approval
requirement MUST reference bindings or a binding pattern.

There is no `failClosed` field. Operational FIP 0.2 is fail-closed by
definition. A document that contains `failClosed` is not conforming. An
adapter MUST NOT silently weaken a requirement it cannot enforce.

## Effects

| Effect | Meaning |
| --- | --- |
| `permit` | The named operation may be compiled when authority and the rest of its group succeed. |
| `deny` | The named operation is forbidden. Used by prohibitions. |
| `require-approval` | The operation is not execution-authorized until an approval Decision exists. |
| `audit-only` | Evidence must be produced. This effect does not allow the operation. |

## Composition

Requirements that share a `groupId` form one group. Every member of a group
MUST use the same `composition` value.

| Value | Rule |
| --- | --- |
| `allOf` | The default. Every member must be enforced before the group is enforced. If any member is unenforced or rejected, a compiler MUST NOT emit a deployable allow for any member of the group. |
| `anyOf` | Each member is an authorized alternative. A compiler MAY emit one or more listed alternatives that are each wholly enforced. It MUST NOT emit an alternative that is not listed. Emitting every listed alternative is still within the subset invariant, because each was authorized. |

`anyOf` is explicit. Omitting `composition` is not allowed by the schema. The
normative default for a future shorthand, if one is ever defined, is `allOf`.

## Binding patterns

A `bindingPattern` MAY name `kinds`, `operations`, and `exceptBindingIds`.
It matches bindings of those kinds and operations, excluding the listed
binding identifiers. Patterns are how a prohibition can forbid every
destination except the ones a permit names.

If a compiler cannot decide whether a pattern overlaps a permit, it MUST fail
closed: the overlapping permit is dominated, and compilation of that permit is
`REJECTED` rather than `FULL`.

## Lifetime

`lifetime` is the authority lifetime the author requires. It is not a
product's reload mechanism.

| Value | Meaning |
| --- | --- |
| `establishment-bound` | The control must hold before the execution context starts. Changing it ends that context. |
| `revocable` | The control may be replaced during the context by a new authorized compilation. The running context MUST NOT keep the old wider effect after the new compilation is in force. |
| `validity-bound` | The effect ends when the attached Validity is no longer `valid`, even if the process is still running. |

A target that can only install a control for the whole life of an execution
context does not satisfy `revocable` or `validity-bound` if the author
required the effect to change without ending that context. The compiler MUST
report `lifetime_mismatch` and MUST NOT claim the running context was updated.
A target lifetime that is strictly shorter than the FIP lifetime MAY be
treated as enforced, because it is a subset, and coverage MUST say so. A
target lifetime that is longer is not a subset and is `REJECTED`.

## Approval

`require-approval` does not grant execution authority.

An approval is an Exchange with `exchangeType` `Decision` and a `decision`
object whose `kind` is `approval`, whose `value` is `approved`, whose
`requirementId` is the requirement, whose Validity is `valid`, and whose
provenance is present. The exchange actor MUST be one of the requirement's
`approverIds`.

A requirement with effect `require-approval` MUST include `approverIds` with
at least one actor. If it does not, evaluation is `INCOMPLETE`.

An approval Decision whose actor is not in `approverIds` MUST be ignored for
satisfaction of the requirement. Self-approval is valid only when that actor
is listed in `approverIds`. Listing the benefiting actor is an explicit policy
choice, not an implicit default.

Until such a Decision is in the evaluation context, the compiler MUST NOT emit
a deployable allow for that requirement. The approval Decision itself is not a
deployable artifact. After it exists, the requirement is eligible to be
compiled as a permit, and compilation still follows
[decisions.md](decisions.md). `value` `rejected` means the requirement is
`DENIED`.

Approval of an action is not approval of an arbitrary policy change. An
adapter MUST NOT implement `require-approval` by accepting a target-side rule
proposal that widens the policy beyond the requirement.

## Audit

The `audit` field is `none`, `target-native`, or `correlated`.

| Value | Satisfied when |
| --- | --- |
| `none` | No audit duty is attached. |
| `target-native` | The target's own event channel records the effect, and the Capability Manifest says that channel covers this kind of effect. |
| `correlated` | A conforming audit-correlation record can be produced that links the requirement and `traceId` to the target rule and a runtime event. Target logs that lack FIP identifiers do not by themselves satisfy `correlated`. |

`audit-only` and `audit` `correlated` on a permit are obligations about
evidence. They do not relax the effect. If the manifest cannot provide the
requested audit strength, that requirement is unenforced. An `allOf` group
that contains it MUST NOT be deployed.

## Obligation

An Obligation object references one or more requirements through
`requiresEnforcement`. It does not have an effect of `permit`. Satisfying the
obligation is a precondition of `compilationDisposition` `FULL` for the
authorizations that cite it. The obligation does not itself authorize the
action.

## Prohibition

A Prohibition references the actions, resources, bindings, or deny
requirements it forbids. Where a prohibition and a permission overlap, the
prohibition dominates. Overlap for filesystem bindings means the same
operation and equal paths, or one path is a segment-prefix of the other. The
prohibition covers the overlapping portion. If two locators cannot be ordered,
the entire permit is dominated.

A dominated permit MUST NOT be compiled to a deployable allow.
