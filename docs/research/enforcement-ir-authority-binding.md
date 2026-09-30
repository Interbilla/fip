# Enforcement IR authority binding

This note is research. It does not change the FIP 0.2 specification, schemas,
primitives, relationships, or the reference implementation.

It records the architectural defect preserved in Q13B run
[q13b-run-1](../evidence/fip-0.2/q13/q13b-static-enforcement/q13b-run-1/report.md).
That run is historical evidence. This note does not reinterpret it.

Campaign baseline: `6435895898dd089ad545941fa226eb1c0a6860a9`.

The accepted Q13A prospective evaluator fix remains outside this note.
Q13A run `q13-run-3` passed 30 / 30. Q13B was not continued. Q13C and Q13D
were not started.

## Problem statement

Coverage and compilation currently treat a supplied Enforcement IR as
authoritative. An IR is a projection of an evaluation. It is not a second
authority document. A later edit of that projection must not become a
deployable target grant.

The intended chain is:

```text
AuthorityPolicy + Exchange
    -> semantic evaluation
    -> authorized projection
    -> Enforcement IR
    -> target enforcement
```

The required derivation invariant is:

```text
IR_consumed
    ==
Project(
    Eval(
        AuthorityPolicy,
        Exchange,
        applicable Decisions,
        applicable governed context
    )
)
```

Then:

```text
TargetEffectiveAuthority
    SUBSET OF
VerifiedIRAuthority
    SUBSET OF
EffectiveFIPAuthorizedAuthority
        UNION
ExplicitlyAcceptedExecutionSubstrate
```

Accepted substrate does not override a FIP prohibition.

A proof that the target policy is a subset of the supplied IR is not enough
when that IR is no longer the projection of the evaluation.

## Failing case

Attack `filesystem-ir-ancestor-after-decision` in `q13b-run-1`.

The source AuthorityPolicy authorized a filesystem read of `/mission/input`.
Projection copied that locator into the IR. After projection, the IR locator
was replaced with `/mission`. The source policy was not changed and did not
authorize `/mission`.

Observed:

| Stage | Result |
| --- | --- |
| Semantic evaluation of the source policy | `AUTHORIZED` for read `/mission/input` |
| Original IR | read `/mission/input` |
| Coverage of the mutated IR | `FULL` |
| Adapter | deployable OpenShell filesystem policy |
| Target policy | read `/mission`, plus accepted substrate paths |

The emission is an unauthorized deployable target authority. Preserved inputs,
both IR documents, coverage, the generated policy, and hashes are in that run
directory.

## Trust boundaries

These components are not assumed to share one trusted process. FIP is meant
to be implemented more than once and to cross enterprise boundaries. Integrity
cannot rest on an in-memory object staying unmodified.

| Component | What it is trusted to do today | What it treats as authoritative | Where a mutation can enter |
| --- | --- | --- | --- |
| Semantic evaluator | Decide `AUTHORIZED`, `DENIED`, `INCOMPLETE`, or `REVIEW` from the policy, exchange, and Decisions | AuthorityPolicy, Exchange, Decisions | Before evaluation. A later edit of those inputs is a new evaluation. |
| Projection / IR builder | Copy the authorized operational slice into an IR | The evaluation result and the source bindings it selected | Between evaluation and the bytes that are stored as the IR |
| Enforcement IR artifact | None. It is data. | Today, coverage and the adapter treat its bytes as the grant | Any holder of the artifact can edit locators, operations, requirements, groups, or prohibitions |
| Coverage evaluator | Say whether this target can enforce the requirements it was shown | The supplied IR plus the Capability Manifest and profile | A substituted IR is assessed as if it were the projection |
| Target adapter | Compile a target policy inside the subset of the grants it extracted | The supplied IR and the coverage assessment | The same substituted IR is compiled |
| Target-policy verifier | Compare a target policy with the grants it is given | Those grants, which today are taken from the IR that was compiled | A policy edit after compile is detectable only if verification uses the pre-edit grants |
| Runtime target | Enforce the policy it loaded | The loaded target policy | A policy can change after compilation and after verification |

The missing boundary is between the IR artifact and coverage. Nothing checks
that the IR bytes are still `Project(Eval(...))` for identified sources.

## Current specification support

Already normative:

| Statement | Where |
| --- | --- |
| Emitted target authority must be a subset of FIP-authorized authority. Widenings are `REJECTED`, not approximated. | [adapters.md](../specification/fip-0.2/adapters.md), subset invariant |
| FIP-authorized authority is what remains after non-authorized acts, prohibitions, unsatisfied approvals and obligations, and manifest limits are applied. | Same section |
| The IR is a compilation contract. It is not an AuthorityPolicy, not an Exchange, and not a primitive. | [enforcement-ir.md](../specification/fip-0.2/enforcement-ir.md) |
| Compiler outputs are contracts. They are not authoring documents and they are not primitives. | [architecture.md](../specification/fip-0.2/architecture.md) |
| Adapters consume the IR and must not re-decide authority. They must not upgrade `DENIED`, `INCOMPLETE`, or `REVIEW` into `AUTHORIZED`. | [architecture.md](../specification/fip-0.2/architecture.md), [enforcement-ir.md](../specification/fip-0.2/enforcement-ir.md) |
| A target-neutral projection copies author-written locators. It does not invent a path from a resource identifier. | [enforcement-ir.md](../specification/fip-0.2/enforcement-ir.md) |
| Bindings in the IR are snapshots of the ExecutionBindings the slice references. | Same document |
| `policyId` and `traceId` are copied. `exchangeId` is present only when one exchange was compiled. | Same document |
| Coverage separates `fipGrants`, `targetEnforcement`, and `targetBaseline`. Baseline is not a FIP grant. Coverage does not emit a target policy. | [adapters.md](../specification/fip-0.2/adapters.md) |
| `FULL` means the presented requirements are enforced, with no widening and no baseline excess. `deployable` true means eligible for a later compilation. It is not `ENFORCED_ALLOW`. | Same document, and [decisions.md](../specification/fip-0.2/decisions.md) |
| A sender's `authorityDecision` is Evidence. The receiver re-evaluates. There is no implicit trust of a foreign compiler. | [audit-and-federation.md](../specification/fip-0.2/audit-and-federation.md) |
| Substrate does not override a prohibition. A baseline that exceeds the grants is `REJECTED`. | [adapters.md](../specification/fip-0.2/adapters.md) |

Not yet normative:

| Gap | Why the current text does not close it |
| --- | --- |
| The consumed IR must be byte-for-semantic-content equal to a fresh projection of identified sources | The IR is described as produced from an authorized slice. No check is required before coverage or compile. |
| `policyId`, `exchangeId`, and `traceId` are integrity bindings | They are copied identifiers. They do not authenticate the binding snapshots. |
| Coverage `FULL` is only an enforceability result over a verified projection | `fipGrants` is defined as the undominated permits in the account coverage was given. A substituted IR supplies that account. |
| "Adapters must not re-decide authority" includes "do not trust a substituted IR" | The sentence can be read as forbidding a comparison with the source evaluation. The Q13B pipeline followed that reading: it compiled the IR it was given. |
| An IR remains deployable only for the current authority snapshot | [governed-runtime-authority-evolution.md](governed-runtime-authority-evolution.md) labels an explicit snapshot identifier as a candidate runtime requirement, not a FIP 0.2 schema field. |

Equivalent wording for "an Enforcement IR has no independent grant semantics" is partly present: the IR is not an AuthorityPolicy, not an Exchange, and not a primitive, and compiler outputs are not authoring documents. The documents do not say that deployability depends on verified derivation from the identified evaluation, or that coverage and compilation must refuse an IR that fails that derivation.

## Defect classification

`filesystem-ir-ancestor-after-decision` is all three of the following.

`IMPLEMENTATION_NONCONFORMANCE`. The subset invariant already requires emitted target authority to be a subset of FIP-authorized authority. The evaluated authority was read `/mission/input`. The deployable policy authorized read `/mission`.

`SPECIFICATION_CLARIFICATION_REQUIRED`. The derivation check is not stated as a duty on coverage and adapters. "Must not re-decide authority" needs to be read as "must not grant anything the evaluation did not grant," including "must not accept a different IR."

`ARCHITECTURAL_MECHANISM_MISSING`. No specified recompute, digest, or sealed evaluation artifact binds the IR artifact to `Project(Eval(...))` once the artifact leaves the projecting process.

It is not `SPECIFICATION_EXTENSION_REQUIRED` for a new primitive, relationship, or authority state. The repair completes the existing subset and projection rules.

Layer reading, matching the preserved artifacts:

| Layer | Reading |
| --- | --- |
| Semantic evaluation | Correct for the source policy |
| Original IR | Correct projection of that evaluation |
| IR integrity | Missing. The mutated artifact was accepted |
| Coverage | Correct as a description of the supplied IR, and incorrect as a treatment of that IR as authority-bearing input |
| Adapter | Faithful to the supplied IR, with no derivation gate |
| Target policy | Faithful to the mutated IR |

## Integrity options

### A. Recompute and compare

Before coverage and again before compilation, evaluate the identified
AuthorityPolicy, Exchange, Decisions, and governed context, project that
result, and compare the security content of the regenerated IR with the
supplied IR.

Advantage: the attacker who edits the IR cannot make the edited IR equal the
projection of sources they do not control. No digest field is required. The
reference implementation can do this with the evaluator and projector it
already has. Canonical recomputation is content integrity. It does not require
signatures.

Disadvantage: the verifier must hold the same sources. A bare IR file is not
self-authorizing, which is the desired property and also means a detached IR
cannot be compiled. Recomputation cost is the cost of one evaluation and one
projection.

### B. Canonical digest binding

At projection time, canonicalize the policy, the exchange, the Decisions and
context, and the security content of the IR. Record:

```text
authorityPolicyDigest
exchangeDigest
authorityStateDigest
decisionDigest
enforcementIrDigest
```

Coverage and the adapter accept the IR only when those digests match a fresh
canonicalization of the sources and of `Project(Eval(sources))`.

A digest stored only inside the IR is not an anchor. An editor can change the
IR and recompute that field. The anchor is the digest of the sources, or a
recomputed projection digest that the editor cannot force by editing the IR
alone.

Digest fields belong beside the IR, in an evaluation artifact that is not a
FIP primitive. Copying the same digests into the IR is optional and still
untrusted until recomputed. They do not belong in the closed IR schema as
authority fields.

### C. Immutable evaluation artifact

A derived container, not a primitive, can hold the semantic decision, the
policy, exchange, context, and Decision digests, the canonical IR digest, and
`traceId`. The compiler accepts that container after the digests verify. It
does not accept an arbitrary IR object.

This is option B with an explicit envelope. The envelope is an implementation
artifact. `VerifiedIR`, `ProjectionProof`, `IntegrityToken`, and
`EnforcementEnvelope` are not proposed as primitives. The existing 28
primitives already name the semantic objects. The container only binds
artifacts derived from them.

### D. Signed or attested artifact

Content integrity and provenance authenticity are different.

Content integrity answers: "Is this IR the projection of these sources?"
Canonical recomputation answers that. Signatures are not required for that
answer in the reference implementation, including when the check runs in
another process on the same host, as long as the checker has the sources.

Provenance authenticity answers: "Who asserted this evaluation?" A signature
or attestation is relevant when the evaluation result is carried across hosts
or enterprises and the receiver does not re-evaluate. FIP already requires the
receiver to re-evaluate. A signature on a foreign IR would not make it a local
Authorization.

Same-process use: recomputation is sufficient.

Separate-process use: recomputation is sufficient if the sources are available
to the compiler process.

Cross-host use: recomputation remains the authority check. A signature can
authenticate who produced a proposal. It does not replace local evaluation.

Cross-enterprise use: local re-evaluation remains mandatory. See below.

### E. Object-capability or sealed pipeline

The reference implementation can refuse to compile an IR object that was not
returned by the projector in the same process. That reduces accidental
mutation inside one Python process. It is not a portable FIP mechanism.
Another implementation, another process, or a serialized IR crosses that seal.
The architectural rule has to be checkable from artifacts, which is
recompute-and-compare or a digest anchored to sources.

## Recommended architecture

Use A as the normative check and as the reference-implementation check.

```text
sources = AuthorityPolicy, Exchange if any, Decisions, governed context
decision = Eval(sources)
regenerated = Project(decision)
accept the supplied IR only when its security content equals regenerated
```

If the decision is not `AUTHORIZED`, or approval is still outstanding, there
is no operational IR to compile. Compilation stays `NOT_COMPILED`.

If the supplied IR differs in security content, compilation is `REJECTED`
with `subset_not_demonstrated`. It is not `PARTIAL` and it is not `FULL`.

B and C are allowed sidecars for separate processes. They are hints to find
the sources. The accept decision still recomputes. D is not required for the
reference repair. E may be added inside one process and does not replace A.

"Adapters must not re-decide authority" stays. Verification does not invent a
grant, ignore a prohibition, or treat a target approval as a Decision. It
accepts only the projection of the evaluation, or it refuses.

## Fields and canonicalization

Comparison uses security content, not an accidental total order of harmless
metadata.

`SECURITY_BINDING`, included in the comparison:

- `authorityDecision`
- `policyId`, `exchangeId` when present, `authorizationIds`, `authorityIds`
- each requirement: `requirementId`, `effect`, `bindingIds`, `constraints`, `conditions`, `composition`, `groupId`, `lifetime`, `audit`
- each group: composition and the full member list
- each prohibition, including binding patterns and exceptions
- each binding snapshot: `bindingId`, `resourceId`, `actionId`, `kind`, `operation`, `locator`, `protocol`, `lifetime`, constraints
- approval records that the projection stored so a requirement could leave `require-approval` eligible for compilation: Decision identity, `requirementId`, validity state, approver identity

`INFORMATIONAL`, excluded from the security comparison:

- `traceId` as a correlation handle
- `codes` that only repeat `not_compiled`
- `irVersion` and `fipVersion` are still required to be the specified constants; a wrong constant is a malformed IR, not a grant

`TARGET_ANNOTATION`, excluded from the security comparison:

- `adapterAnnotations`
- coverage statuses `enforced`, `unenforced`, `rejected`, and `targetBaseline` acceptance rows

Annotations and coverage results must not be read as grants. A change to them
does not by itself reject the security comparison. A change that causes the
compiler to emit a wider target rule still fails the existing target-policy
subset check.

Canonical form for the security content:

- JSON object
- object keys sorted at every depth
- arrays of requirements, groups, prohibitions, and bindings sorted by their identifier fields, not by source-file order
- member lists inside a group sorted by `requirementId`
- UTF-8
- no insignificant whitespace: separators are a comma and a colon
- no trailing newline
- no timestamps
- coverage disposition, target enforcement status, and substrate rows are omitted
- adapter annotations are omitted

This is the same JSON canonicalization already used for OpenShell policy
bytes in the reference runtime helper: sorted keys, compact separators, UTF-8.
The provenance text hash, which only rewrites CRLF to LF, is a different
operation and is not this digest.

Ordering of security arrays is normalized by identifier, so a reorder that
does not change membership matches. A reorder that drops or adds a member
does not.

Identifiers are included. They are how substitution of one binding for
another is seen.

Generated timestamps are not included. The IR schema does not put a generation
time in the projection. Freshness comes from recomputing against current
sources, not from a timestamp inside the IR.

An attacker who edits the IR and recomputes a hash of the IR still fails,
because the accept rule compares that content with `Project(Eval(sources))`.
The attacker does not get to replace `Eval`.

## Freshness and M7A

Integrity and freshness are both required.

Integrity: the IR matches the projection of a stated snapshot.

Freshness: that snapshot is the current one for this deployment.

M7A names the snapshot `AuthorityState` and says it is not a primitive. The
chain is:

```text
AuthorityState v17
    -> Decision D17
    -> IR H17
```

When the snapshot becomes v18, H17 does not stay deployable. The compiler
recomputes `Project(Eval(v18))`. Equality with H17 fails unless v18 still
projects the same security content. A stored digest of v17 does not satisfy
the check for v18.

Validity, Purpose, Scope, Conditions, and Delegation already change the
evaluation when the source documents change. The Q13A repair makes a non-valid
Validity on the policy and on a Delegation exchange fail closed at evaluation.
Freshness is that same evaluation, run again on the current documents. It is
not a second authority model.

## Coverage contract

Coverage answers: can this target and profile enforce requirement Y as
stated?

Coverage does not answer: is requirement Y authorized?

`FULL` means every verified authorized requirement presented to the adapter
can be enforced by this target and profile, including lifetime and audit, with
baseline not exceeding the grants and no prohibition dropped.

`FULL` does not mean that whatever is in the IR is authorized.

The current coverage disposition table is written as a function of the
requirements in the IR. That is the right enforceability test after derivation
has been verified. It is not, by itself, explicit enough. The clarification
to add is that coverage runs on an IR that has already passed the derivation
check, and a failed derivation check does not enter coverage as `FULL`.

## Adapter contract

The portable contract should be conceptual:

```text
compile(VerifiedEnforcementArtifact, CapabilityManifest, profile)
```

rather than:

```text
compile(arbitrary EnforcementIR, CapabilityManifest)
```

`VerifiedEnforcementArtifact` is the pair of sources-plus-IR that passed the
derivation check, or the recomputed projection itself. It is not a new
primitive.

Every adapter, including a later OpenShell, Sentry, Kubernetes, cloud IAM, or
MCP gateway adapter, refuses `FULL` and refuses a deployable policy unless
that check has passed for this deployment step. The adapter still must not
widen a verified grant. Sentry remains a future target candidate. This note
does not define a Sentry schema or adapter.

The minimal rule that travels to every adapter: no deployable target authority
unless the IR's security content equals the current projection of the
identified semantic evaluation, and the emitted policy is a subset of that
projection plus explicitly accepted substrate.

## Round-trip proof obligations

Q13B shows that a round-trip check is required before a target policy may be
deployable. It is not optional future hardening. The NVIDIA Policy Prover does
not perform this check.

| Id | Obligation | On failure |
| --- | --- | --- |
| P1 | Every permit in the IR corresponds to an Authorization selected by the current evaluation | `REJECTED` |
| P2 | Every binding snapshot matches the binding the evaluation selected, including `bindingId`, resource, and action | `REJECTED` |
| P3 | No operation is wider than the selected binding | `REJECTED` |
| P4 | No locator is wider than the selected binding, including an ancestor path | `REJECTED` |
| P5 | `allOf` is not weakened to `anyOf`, and no required member is dropped or replaced | `REJECTED` |
| P6 | Every applicable prohibition in the projection is still present | `REJECTED` |
| P7 | No lifetime is longer than the selected requirement | `REJECTED` |
| P8 | Accepted substrate is labeled substrate and is absent from `fipGrants` | `REJECTED` |
| P9 | The sources used for P1–P8 are the current snapshot, not an older matching projection | `REJECTED` |
| P10 | Any security-content mismatch is `REJECTED`, never `PARTIAL` or `FULL` | `REJECTED` |

When evaluation itself produces no operational IR, the disposition is
`NOT_COMPILED` rather than a deployable artifact. That is already the
projection rule.

P1–P8 are discharged by security-content equality with `Project(Eval(current sources))`. P9 is discharged by using the current sources for that `Eval`. P10 is the disposition rule.

## TOCTOU

```text
semantic-source verification
    -> IR integrity verification
    -> compilation
    -> target-policy verification
    -> deployment
```

| Change | Required repeat |
| --- | --- |
| Source authority, Decision, Validity, Purpose, Scope, or context changes after evaluation | The previous projection is stale. Eval and Project run again. The old IR is not deployable. |
| IR changes after integrity verification | Compilation uses the verified security content, or it runs the comparison again on the bytes it will compile. A match against an earlier copy does not cover a later edit. |
| Target policy changes after compilation | The existing effective-policy verification runs against the verified grants immediately before deployment. A prior verification does not cover the new policy. |

The reference repair can recompute immediately before `compile` and verify the
generated policy against the grants of that same recomputed projection before
anything is treated as deployable. A later load repeats target-policy
verification. This note does not implement that sequence.

## Policy Prover

The NVIDIA Policy Prover can address a different question: whether a candidate
OpenShell policy stays inside an operator technical boundary. It cannot show
that a mutated IR was authorized by a FIP evaluation. A prover pass is not a
FIP authorization. That distinction is already the M7 result.

A later pipeline can be:

```text
FIP semantic evaluation
    -> FIP projection-integrity check
    -> Enforcement IR
    -> adapter
    -> NVIDIA Policy Prover, when a boundary is configured
    -> effective-policy verification against the verified FIP grants
    -> deployment
```

The prover stays after the adapter because its input is a target policy. It
stays before deployment and does not replace effective-policy verification.
Effective-policy verification uses the verified FIP grants, not the prover's
boundary, as the authority subset.

## Cross-enterprise implication

The receiver's risk is the same defect with a remote author of the IR. A
sender-generated IR that says `AUTHORIZED` and names a local path is evidence
of a requested shape, or a proposal, not a local grant.

Already normative: the portable object is semantic authority plus enforcement
requirements; bindings are local; a foreign `authorityDecision` is Evidence;
the receiver re-evaluates; coverage is not transitive; there is no implicit
trust of a foreign compiler.

A foreign IR can safely represent:

- evidence that the sender projected some slice
- a proposal of requirement identifiers and effects
- a requested enforcement shape the receiver may compare with its own projection

It cannot represent local deployable authority. The locally deployable IR is
`Project(Eval(receiver policy, exchange, receiver Decisions, receiver context))`.
If the sender's locators differ, the receiver's bindings are the ones that
enter that projection.

## FIP version impact

The repair belongs in the FIP 0.2 Enforcement Candidate.

It completes the subset invariant and the statement that the IR is a
projection. It does not add a primitive or a relationship. It does not need a
new authority state. Opening FIP 0.3 is not required.

Normative prose should gain a clarification before implementation code is
treated as the contract: derivation is verified; a mismatched IR is
`REJECTED`; coverage `FULL` is enforceability of a verified projection;
adapters must not re-decide, and must not treat an unverified IR as the
decision.

## Primitive, relation, and schema impact

| Item | Impact |
| --- | --- |
| Primitives | None. The count stays 28. |
| Relationships | None. The count stays 26. |
| IR schema | None required for recomputation. Digest fields are not added to the closed schema by this recommendation. |
| Other schemas | None. |
| Normative prose | Clarification in the IR, adapter, and architecture documents. Not done in this note. |
| Reference implementation | Later. Not in this note. |
| Conformance vectors | Later tests listed below. Not executed here. |

## Prospective repair plan

1. Accept the FIP 0.2 clarification described above. Do not add a primitive.
2. In the reference pipeline, recompute `Project(Eval(sources))` immediately before coverage and compile.
3. Compare security content. On mismatch, return `REJECTED` and `subset_not_demonstrated`, with no deployable policy.
4. Verify the generated target policy against the grants of the recomputed projection, not against grants read from a caller-supplied IR that skipped the comparison.
5. Keep substrate rows out of `fipGrants`.
6. Leave Q13B run-1 unchanged. Re-run the static campaign as a new run id after the repair. Do not start that run in this note.

## Prospective Q13B tests

Not executed.

| Case | Expected |
| --- | --- |
| Original IR from the current evaluation | Verification passes, and the exact filesystem read remains `FULL` |
| Path `/mission/input` replaced by `/mission` | `REJECTED` |
| Operation `read` replaced by `write` | `REJECTED` |
| Same `bindingId`, locator changed | `REJECTED` |
| Same `requirementId`, operation changed | `REJECTED` |
| Requirement removed | `REJECTED` |
| Requirement added that the current evaluation did not select | `REJECTED` |
| Requirement added that a separate current Authorization does select | Accepted only as the new projection, not as a silent edit of the old IR |
| `allOf` replaced by `anyOf` | `REJECTED` |
| Lifetime widened | `REJECTED` |
| Substrate path placed in `fipGrants` | `REJECTED` |
| Non-security `adapterAnnotations` change | Security comparison still holds; annotations are not grants |
| Authority snapshot changes after a passing proof | The old proof is rejected on the next check |
| Target policy mutated after compile | Existing target-policy verification rejects it |

Positive controls from q13b-run-1 that passed, including the exact filesystem
read, the REST GET, the TCP connect, and the MCP tool, are repeated in that
new run. Runtime remains unobserved unless a later phase actually runs it.
