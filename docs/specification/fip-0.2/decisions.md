# Decisions

FIP 0.2 separates three records so that a semantic success cannot be mistaken
for a runtime allow.

## authorityDecision

Produced by the Semantic Micro-Firewall. It is not an author-supplied field.

| Value | When it is required |
| --- | --- |
| `AUTHORIZED` | The actor, action, resource, purpose, authority, authorization, scope, validity, and delegation are consistent; every applicable condition that can be evaluated holds; no applicable prohibition dominates; and, in operational mode, every required binding and requirement reference is present. |
| `DENIED` | A prohibition applies, validity is not `valid`, a credential is treated as authorization, delegation is not explicit, a forbidden act change is attempted, or a condition evaluates to false. |
| `INCOMPLETE` | A required semantic field, binding, approver list, condition input, or edge agreement is missing or unevaluable. |
| `REVIEW` | The policy requires a higher-assurance review before authority exists, applicable policies conflict, or trusted evidence contradicts the requested action. |

`AUTHORIZED` does not mean runtime execution is allowed.

`REVIEW` is not `require-approval`. Review means authority is unresolved. A
require-approval requirement can sit on an authorization that is otherwise
`AUTHORIZED`, and still withhold execution until an approval Decision exists.

0.1 `ESCALATE` corresponds to `REVIEW` or `INCOMPLETE`, as specified in
[compatibility.md](compatibility.md). It does not correspond to `AUTHORIZED`.

## compilationDisposition

Produced by a compiler. It is not an author-supplied field. It is produced
only for a document the compiler was asked to compile. Semantic-only documents
and documents that were not compiled have `NOT_COMPILED`.

| Value | Deployable artifact | Other output |
| --- | --- | --- |
| `FULL` | Yes. This is the only disposition that produces one. | Coverage report. |
| `PARTIAL` | No. | Diagnostics, non-deployable candidate output, and a coverage report. |
| `REJECTED` | No. | Diagnostics and a coverage report. No candidate allow that could be installed. |
| `NOT_COMPILED` | No. | None required. |

A conforming initial implementation MUST NOT provide an override that turns
`PARTIAL` or `REJECTED` output into a deployable artifact. An expert override
is outside initial FIP 0.2.

Coverage may report `FULL` before any target policy exists. At that stage
`deployable` means the slice is eligible for compilation. A generated target
policy is a later artifact. Until a runtime event is correlated, its
`runtimeDisposition` is `UNOBSERVED`. `AUTHORIZED`, `FULL`, a generated
policy, and `ENFORCED_ALLOW` are different facts.

`FULL` requires every requirement in the compiled slice to be `enforced`,
none `rejected`, the subset invariant in [adapters.md](adapters.md) to be
demonstrated, and every obligation in the slice to be covered. Approval
requirements in the slice must already be satisfied.

If a group is `allOf` and any member is not enforced, the compiler MUST NOT
emit a deployable allow for that group, and the disposition cannot be `FULL`.

## runtimeDisposition

Produced by mapping a target event. It is an observation. It MUST NOT create
or upgrade authority.

| Value | Meaning |
| --- | --- |
| `ENFORCED_ALLOW` | The target enforced an allow that corresponds to a compiled FIP permit. |
| `ENFORCED_DENY` | The target enforced a deny. |
| `AUDIT_ONLY` | The target recorded the event and did not block. This does not satisfy a permit or a deny requirement. |
| `APPROVAL_PENDING` | A target or operator gate is waiting. This does not satisfy `require-approval` unless a FIP approval Decision is recorded. |
| `UNOBSERVED` | No correlated event is available. |

An observed allow does not rewrite `DENIED`, `INCOMPLETE`, or `REVIEW`.

## Fail-closed

The following are normative and have no author switch:

- Missing authority is not permission (`missing_authority`, `INCOMPLETE`).
- Missing execution binding is not execution authorization
  (`missing_execution_binding`, `INCOMPLETE` in operational mode).
- Absence of a prohibition is not permission (`absence_is_not_permission`).
- A prohibition dominates an overlapping permission (`prohibition_dominates`).
- An obligation does not grant execution authority
  (`obligation_is_not_authority`).
- `require-approval` does not grant execution authority until a valid approval
  Decision exists (`approval_required`).
- An unsupported requirement MUST NOT be weakened into a broader allow.
- If the subset invariant cannot be demonstrated, compilation is `REJECTED`
  (`subset_not_demonstrated`).
- An unknown `fipVersion` produces no allow (`unknown_fip_version`).

## Initial reason codes

A conforming evaluator and compiler MUST use these codes for the cases named
elsewhere in this specification. Additional codes require a revision of this
specification. Implementations MUST NOT invent a code that authorizes more
than these rules.

`missing_authority`, `missing_execution_binding`, `prohibition_dominates`,
`explicit_prohibition`, `absence_is_not_permission`,
`obligation_is_not_authority`, `approval_required`, `semantic_only`,
`not_compiled`, `compilation_rejected`, `subset_not_demonstrated`,
`unsupported_requirement`, `baseline_exceeds_grant`, `lifetime_mismatch`,
`validity_expired`, `validity_revoked`, `validity_superseded`,
`validity_not_yet_valid`, `credential_is_not_authorization`,
`silent_semantic_escalation`, `delegation_requires_explicit_authority`,
`coordination_is_not_enterprise_delegation`,
`free_text_cannot_manufacture_authority`, `authority_source_free_text`,
`memory_cannot_manufacture_authority`, `unknown_fip_version`,
`extension_cannot_grant_authority`.

## Propagation summary

| Input | authorityDecision | compilationDisposition | Deployable allow |
| --- | --- | --- | --- |
| Prohibition applies | `DENIED` | Not compiled to a permit | No |
| Required field or binding missing | `INCOMPLETE` | `NOT_COMPILED` | No |
| Review or evidence conflict | `REVIEW` | `NOT_COMPILED` | No |
| Semantic-only, semantically consistent | `AUTHORIZED` or as the semantic rules require | `NOT_COMPILED` | No |
| Operational, authorized, every requirement enforced, subset shown | `AUTHORIZED` | `FULL` | Yes |
| Operational, authorized, some requirements unenforced | `AUTHORIZED` | `PARTIAL` | No |
| Subset cannot be shown, or a constraint would be widened | `AUTHORIZED` may still hold | `REJECTED` | No |
| Approval not yet decided | `AUTHORIZED` may hold for the surrounding grant | not `FULL` for that requirement | No |
