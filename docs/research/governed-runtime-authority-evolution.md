# Governed runtime authority evolution

Non-normative M7A clarification. It does not change FIP 0.1, the FIP 0.2
specification, schemas, primitives, relationships, the pinned OpenShell
adapter, or M4, M5, or M6 evidence.

It follows
[nvidia-open-agent-safety-platform-integration-study.md](nvidia-open-agent-safety-platform-integration-study.md).
Those M7 conclusions stay in force: FIP sits above NVIDIA enforcement, the
FIP 0.2 vocabulary is unchanged, the Semantic Micro-Firewall is the semantic
decision point, OpenShell is a software execution enforcer, the Policy Prover
is a target-policy verifier, Advisor approval is evidence for a FIP Decision,
and Sentry remains a future target candidate.

Labels used below:

- **Already normative.** Stated in FIP 0.2. This note only points at it.
- **Clarification.** A name for behavior the existing semantics already
  require. It is not a new rule.
- **Candidate runtime requirement.** A deployment duty this study recommends
  for later work. It is not part of FIP 0.2 until a specification revision
  says so.
- **Governance recommendation.** A useful operating practice. It is not a
  conformance rule.

## A. Executive conclusion

FIP 0.2 already supports governed runtime authority evolution. Legitimate
authority can expand, contract, or change scope when governed facts change.
The policy is reevaluated. It is not bypassed.

The specification already denies use when Validity is not `valid`, lets a
prohibition dominate an overlapping permission, refuses to treat a target
allow or a target approval as a FIP grant, and requires the receiver of a
foreign decision to reevaluate it. What M7A adds is a vocabulary for three
different events, a time-indexed reading of authority, and a candidate
runtime discipline for stale Decisions and stale target policy. None of that
adds a primitive.

FIP 0.2 impact of this study: the specification is unchanged. The reading is
a clarification. A few operational duties are candidate runtime requirements,
not a new FIP version.

## B. Definition

**Governed runtime authority evolution** is the process by which a change in
governed facts produces a new evaluation, a new FIP Decision where one is
required, a new effective authority, and, only where the realization must
change, a new enforcement artifact.

The sequence is:

```text
changed governed facts
    -> authority reevaluation
    -> new FIP Decision where the policy requires one
    -> changed effective authority
    -> changed enforcement realization where required
```

There is no emergency bypass, break-glass primitive, or override primitive.
`EmergencyAuthority`, `BreakGlass`, and `Override` are not FIP objects.

## C. Three events

These events are different. A system that treats them as one event will
either skip semantic evaluation or rewrite a target policy when the
authority never changed.

| Event | Definition | Example |
| --- | --- | --- |
| Interaction Decision | Whether this interaction is authorized under the authority and context that apply now. | Standing authority already permits camera observation. The SMF evaluates one camera request. |
| Technical Policy Update | Semantic authority is unchanged. A target policy changes so an already-authorized effect can be realized. | FIP already authorizes the access. An OpenShell rule is installed to realize it. |
| Semantic Authority Update | The applicable legitimate authority changed because governed facts changed. | Standing authority does not permit the access. A valid delegation, human Decision, scope, purpose, or validity change makes a different authority applicable. The interaction is evaluated again under that state. |

**Clarification.** An Interaction Decision is an Exchange evaluated to an
`authorityDecision`. A Technical Policy Update is compilation and
effective-policy verification of authority that already exists. A Semantic
Authority Update is a new applicable combination of Authority, Authorization,
Prohibition, Delegation, Decision, Condition, Scope, Validity, Purpose, and
Evidence. Only the third event changes what FIP authorizes.

## D. Effective authority through time

Standing documents do not by themselves describe the authority that applies
at a moment. Call that authority `A(t)`.

```text
A(t) = F(
    standing Authority and Authorization,
    Prohibition,
    Delegation,
    Role,
    Purpose,
    Scope,
    Validity,
    Conditions and Constraints,
    Evidence,
    Provenance,
    operational context(t)
)
```

`operational context(t)` is the governed facts the evaluation is allowed to
use at `t`: which Decisions are in context, which Validity states hold,
which Conditions can be evaluated, and which GOCP snapshot admitted the
fields. It is not an agent's free-text claim. Extension objects and memory
cannot manufacture authority. Those exclusions are already normative
(`extension_cannot_grant_authority`, `memory_cannot_manufacture_authority`,
`free_text_cannot_manufacture_authority`).

The runtime property is:

```text
OperationalEffect(t)
    SUBSET OF
EffectiveAuthorizedAuthority(t)
    UNION
ExplicitlyAcceptedExecutionSubstrate(t)
```

`EffectiveAuthorizedAuthority(t)` is `A(t)` after prohibition dominance,
closed-world refusal of unnamed operations, and unsatisfied approval.
Accepted substrate remains outside the grant and cannot override a
prohibition. This is the M6 subset obligation indexed by the authority state
that is current at `t`.

The following stay in force at every `t`. Each one is already normative in
[decisions.md](../specification/fip-0.2/decisions.md) or
[architecture.md](../specification/fip-0.2/architecture.md):

- A prohibition dominates an overlapping permission.
- Missing authority is not permission.
- Missing binding is not execution authorization.
- An obligation does not grant authority.
- `require-approval` does not grant authority until a valid approval
  Decision exists.
- Target substrate does not create FIP authority.
- A target approval (`APPROVAL_PENDING`) does not create FIP authority.
- A target policy, including an observed allow, does not create or upgrade
  FIP authority.

`AUTHORIZED` at `t` is still not `FULL`, not a generated policy, and not
`ENFORCED_ALLOW`.

## E. Expansion and contraction

`A(t2)` is not assumed to contain `A(t1)`. The transition may make authority
larger, smaller, differently scoped, or incomparable.

| Direction | Governed fact | Existing object that carries it |
| --- | --- | --- |
| Expansion | An emergency declaration becomes active | Evidence plus a Condition that can now be evaluated, or a Validity that becomes `valid` |
| Expansion | A valid delegation arrives | `delegatesTo` and `delegatesAuthority` |
| Expansion | An authorized human grants authority | Approval Decision by an actor in `approverIds` |
| Expansion | A mutual-aid agreement becomes applicable | Authority plus Scope and Purpose, adopted by local policy |
| Expansion | A mission phase activates a capability | Scope or a Condition on the Authorization |
| Expansion | Evidence satisfies a Condition | Condition input. Evidence does not itself satisfy the requirement |
| Contraction | The emergency ends | Validity `expired` or `revoked`, or the Condition becomes false |
| Contraction | A delegation expires or is revoked | Validity on the Delegation |
| Contraction | A human authorization is withdrawn | Decision value `rejected`, or Validity `revoked` |
| Contraction | A mission phase ends | Scope or Condition |
| Contraction | Geographic coverage changes | Scope via `appliesWithin`. An act outside scope is denied |
| Contraction | The Purpose no longer applies | `hasPurpose`. A differing expected purpose denies authority |
| Contraction | Resource ownership or control changes | `ownedBy` and `controlledBy` stay descriptive. They do not authorize. A real change is a new Authorization or a Prohibition |
| Contraction | A required Condition becomes false | `DENIED` |
| Contraction | An Authorization expires | Validity other than `valid` denies use |

**Already normative.** Any Validity state other than `valid` denies use of
the object that carries it. A false Condition denies. A prohibition still
dominates while it applies. `revocable` says the running context must not
keep the old wider effect after a new authorized compilation is in force.
`validity-bound` says the effect ends when Validity is no longer `valid`,
even if the process is still running. A target that cannot do that is
`lifetime_mismatch` and must not claim the running context was updated.

**Clarification.** Those rules already forbid monotonic-only thinking.
Expansion without a new valid basis is a missing authority. Contraction
without withdrawal of the dependent effect is a subset failure.

## F. Emergency and break-glass

Break-glass is a governed pattern of existing objects. It is not a bypass
and not a new primitive.

### Scene

A fire unit requests observation of Police Camera-17.

Normal context. No Authorization ties that actor, the Observe action, that
Resource, and a fitting Purpose. The closed world leaves the request
unauthorized. A standing Prohibition on external observation dominates if
it overlaps. The SMF result is `DENIED` or `INCOMPLETE`, not an allow.

Changed context, still inside governance:

| Fact | FIP object |
| --- | --- |
| Fire unit | Actor, with Identity |
| Camera-17 | Resource. No path, host, or device id on the Resource |
| Observe | Action |
| The request itself | Request. A Request does not authorize |
| Evacuation | Purpose |
| Declaration active, life safety, camera covers the evacuation area | Conditions. Unevaluable inputs yield `INCOMPLETE` |
| Evacuation area and the time window | Scope |
| Holds only while the declaration holds, or until a stated time | Validity |
| Mutual-aid source | Authority. The kind token does not grant by itself |
| The temporary grant | Authorization in Permission mode, with requirements |
| Standing external-access ban | Prohibition. It dominates any overlapping Permission |
| Bounded transfer from the police authority | Delegation through `delegatesTo` and `delegatesAuthority` |
| Incident commander approval, if required | Decision, kind approval, actor in `approverIds` |
| The declaration and the agreement text | Evidence. Evidence is not the grant |
| Who asserted the declaration, and from what | Provenance |
| Audit of the temporary use | Obligation. It does not permit |

The result is temporary authorization only when every applicable Condition
holds, Validity is `valid`, Scope and Purpose match, any required Delegation
is explicit, any required approval Decision is valid, and no applicable
Prohibition overlaps the grant.

If the standing Prohibition overlaps the emergency use, the Prohibition
wins. The emergency becomes authorized only when governing facts change
which Prohibition applies: its Scope excludes this Purpose, its Condition
is false, or its Validity no longer holds. That is a change in applicable
governance. It is not an implicit override.

The path is:

```text
changed context and evidence
    -> governed reevaluation
    -> FIP Decision where approval is required
    -> SMF authorityDecision
    -> compilation and enforcement only if AUTHORIZED and FULL
```

`emergency -> bypass SMF` is not a FIP transition.

## G. Human judgment

"Allow it" is not sufficient.

An approval that satisfies `require-approval` is an Exchange of type
Decision whose kind is `approval`, whose value is `approved`, whose
`requirementId` matches, whose Validity is `valid`, whose provenance is
present, and whose actor is one of `approverIds`. An actor outside that
list is ignored. Self-approval counts only when the policy lists that
actor. A rejected value denies the requirement. The Decision is not itself
a deployable artifact. After it exists, compilation still has to succeed.

What the record has to show:

| Need | Object |
| --- | --- |
| Who spoke | Identity, through `hasIdentity` and `decidedBy` |
| What office they hold | Role. A Role does not grant the operation |
| Whether they may approve this requirement | Membership in `approverIds`, or an explicit Delegation of that authority |
| How far the approval reaches | Scope on the Decision or the Authorization |
| Why | Purpose |
| How long | Validity |
| What they relied on | Evidence |
| Where the record came from | Provenance |
| The outcome | Decision |

**Already normative.** Approval of an action is not approval of an arbitrary
policy change. An adapter must not implement `require-approval` by accepting
a target-side proposal that widens the policy beyond the requirement.

**Clarification.** The Incident Commander can authorize temporary camera
access only when the governing policy gives that person the approval role
or an explicit delegation. Rank, presence at the incident, or a sentence in
a radio log does not.

## H. Federation

A fire-side emergency declaration does not create police-side authority.

```text
foreign evidence
    -> receiving enterprise
    -> local authority reevaluation
    -> local FIP Decision
    -> local enforcement
```

**Already normative** in
[audit-and-federation.md](../specification/fip-0.2/audit-and-federation.md).
The portable object is semantic authority plus enforcement requirements.
Bindings are local. A sender's `authorityDecision` is Evidence in the
receiver's provenance. It is not an Authorization. The receiver's SMF
reevaluates under the receiver's policy. A foreign decision must not
manufacture authority. Coverage is not transitive. Cross-enterprise
delegation uses `delegatesTo` and `delegatesAuthority`. There is no implicit
trust of a foreign compiler. `coordination_is_not_enterprise_delegation` is
a normative reason code.

Applied to this scene:

- The mutual-aid agreement is local policy on the police side, or an
  explicit Delegation into that policy. A document sitting in the fire UDG
  is Evidence until the police policy adopts it.
- The fire declaration is foreign Evidence. The police SMF evaluates
  Conditions against it. Trusted evidence that contradicts the request
  yields `REVIEW`.
- Resource ownership stays descriptive. The police agency controls
  Camera-17 by its own Authorization, not by the fire agency's claim.
- A local Prohibition still dominates an overlapping grant.
- Local human approval, if `require-approval` is present, is a police
  Decision by a police `approverIds` actor.
- Receiving-agency sovereignty is the reevaluation duty. The receiver may
  narrow with its own bindings and must not drop requirements and still
  report `FULL`.

## I. SMF runtime role

The accurate definition is:

> The Semantic Micro-Firewall is the runtime semantic authorization point
> that evaluates an interaction against the governed authority and context
> that apply to that evaluation.

That is stronger than "SMF checks a static file," and it matches the
existing pipeline in
[architecture.md](../specification/fip-0.2/architecture.md): an Exchange is
evaluated to an `authorityDecision`. The 0.1 SMF terms `PERMITTED`,
`DENIED`, `INCOMPLETE`, and `ESCALATE` map into 0.2 as specified in
[compatibility.md](../specification/fip-0.2/compatibility.md). `ESCALATE`
is `REVIEW` or `INCOMPLETE`, never `AUTHORIZED`.

Inputs to one evaluation:

| Input | Role |
| --- | --- |
| Exchange | The interaction being decided |
| AuthorityPolicy | Standing authority, including prohibitions and requirements |
| GOCP or context snapshot | Which fields were admitted. Unadmitted domain claims stay out |
| Decisions in context | Approval, rejection, and review outcomes |
| Delegation state | Only explicit delegated authorizations |
| Validity state | Anything other than `valid` denies use |
| Evidence | Support for a Condition or for provenance. Not a grant |

**Clarification.** The SMF can do both of these, and they are the same
operation: reevaluate an interaction, and evaluate it against a versioned
authority and context artifact. The artifact is the policy, the in-context
Decisions, and the fact snapshot used for Conditions and Validity. This
study does not require a continuous global monitor. Freshness of the
snapshot is a deployment duty. A stale snapshot is a stale Decision.

## J. Authority-state versioning

A Decision is tied to the authority and context used to produce it.

```text
AuthorityState v17
    -> Exchange E42
    -> Decision D42
    -> enforcement realization
```

`AuthorityState` is a name for that snapshot. It is not a new primitive.
The snapshot is identified by the policy identity, the Decisions and
Validity states in context, the delegation edges used, and the provenance
of the inputs. Hashing that bundle is a candidate runtime requirement.

When the snapshot becomes v18:

| Object from v17 | Required reading |
| --- | --- |
| D42 | Stays a historical record. It authorizes nothing under v18 unless v18 still contains the facts D42 required and D42's own Validity remains `valid`. |
| Cached Decisions | Must not be replayed against v18. Replay is a new evaluation or it is invalid. |
| Temporary grants | Follow their Validity, Scope, Purpose, and Conditions under v18. |
| OpenShell policies compiled from v17 | Prior verification is void. The effective policy is re-read and checked against v18 before further reliance. |
| Active sessions | A candidate runtime requirement: a session that depended on a fact v18 removed does not keep that effect. `revocable` and `validity-bound` already state this where the author required those lifetimes and the target can enforce them. |
| Credentials | Presentation remains not authorization. A credential cached at v17 does not become a use-authorization at v18. |
| Long-running actions | If the author required `validity-bound` or `revocable`, the old wider effect must not continue. If the target cannot express that, the compilation is `lifetime_mismatch`, not a silent continuation. |
| Delegated capabilities | End when the Delegation's Validity ends or the delegated Authorization no longer applies. |

**Already normative.** A Decision is not a deployable allow. Validity
other than `valid` denies use. `derivedFrom` does not create authority.

**Candidate runtime requirement.** Bind each Decision and each
effective-policy verification to an explicit snapshot identifier, and treat
a mismatch as a failed verification. FIP 0.2 does not yet define that
identifier as a schema field.

## K. Temporary authority

A temporary authorization is an ordinary Authorization with a narrow shape:

- Scope that names the place or jurisdiction, and no wider one
- Purpose that states why, here evacuation
- Validity that ends when the basis ends
- Conditions that can become false
- Provenance for the inputs
- Evidence for the declaration and the agreement
- Obligations such as audit, which still do not grant

**Governance recommendation, not a conformance rule.** Greater privilege
should usually carry shorter Validity, narrower Scope, stronger Provenance,
and a stronger audit Obligation. FIP 0.2 does not require that trade.
Authors who want it write it as Validity, Scope, and an Obligation. A
missing audit Obligation is not automatically supplied by the word
"temporary."

## L. Revocation

Contraction is an enforcement problem, not only an evaluation problem.

At 14:00 the FIP Validity becomes `expired`. If the OpenShell rule is still
installed, technical access can exceed current FIP authority.

The invariant after contraction is the same invariant as after expansion:

```text
EffectiveTargetAuthority(t)
    SUBSET OF
EffectiveFIPAuthority(t)
    UNION
ExplicitlyAcceptedExecutionSubstrate(t)
```

**Already normative** where the author selected a lifetime the target can
enforce. `validity-bound` ends the effect while the process still runs.
`revocable` forbids keeping the old wider effect after the new compilation
is in force. A longer target lifetime is `REJECTED`. The subset invariant
in [adapters.md](../specification/fip-0.2/adapters.md) already forbids a
target restriction from enlarging authority. A leftover allow is that
enlargement.

**Candidate runtime requirement**, not implemented here, and not a silent
addition to FIP 0.2. When `A(t)` contracts, a deployment that claims
currency should:

1. Invalidate the prior effective-policy verification.
2. Remove or replace the target rules that realized the withdrawn grant.
3. Constrain or end a session if the target cannot drop the effect inside
   the still-running context.
4. Drop cached authorization for that grant.
5. Record provenance of the contraction and of the target change.
6. Leave substrate in place. Substrate is not the withdrawn grant, and it
   does not replace the grant.

Until that deployment duty is specified, an adapter that cannot revoke
must keep reporting `lifetime_mismatch` rather than `FULL` for a
`validity-bound` or `revocable` requirement. That duty is already
normative.

## M. Races

Conceptual requirement and future mechanism are separate. This study
requires the conceptual column. It does not choose tokens, locks, or a
product API.

| Race | What must be true | Mechanism class, later |
| --- | --- | --- |
| A. SMF authorizes at t1, authority revoked at t2, action runs at t3 | The effect at t3 needs `A(t3)`. The t1 Decision does not survive the revocation. | Revalidation at use, or a validity-bound realization. Fail closed if the check cannot be made. |
| B. Emergency authority becomes valid, FIP authorizes, OpenShell update is late | No effect from the new grant until the target policy is installed and the effective policy verifies. Semantic authority is not yet operational effect. | Version binding between Decision and installed policy. |
| C. OpenShell rule expands, FIP Decision fails or is absent | The target change is not a grant. Verification fails closed. The extra rule is not installed as a FIP allow. | Target rollback or refusal to install. |
| D. Target policy changes after FIP verification | The verification is void. This is the M5 and M6 rule. | Re-read and re-verify immediately before reliance. |
| E. An old Decision is replayed against a new AuthorityState | The replay is a new evaluation, or it is invalid. | Version binding on the Decision. |
| F. A delegation expires during a long-running operation | The delegated effect ends if the author required `validity-bound` or `revocable` and the target can enforce it. Otherwise the compilation must not claim that lifetime. | Operation termination only when that lifetime was required and is enforceable. |

Atomicity is a candidate implementation of A, B, and F. It is not something
FIP 0.2 currently requires of every target. Short-lived authorization
records are one way to bind a Decision to a snapshot. They are not a new
primitive. Fail-closed behavior when the version check cannot be performed
is the reading that matches missing authority.

## N. Pattern 1, mediated federation

```text
Agent
  -> OpenShell
  -> may reach the federation gateway only
  -> SMF / FIP gateway
  -> per-interaction authorization
  -> governed resources
```

The OpenShell policy is a stable outer envelope. It does not change on
every FIP Decision. The SMF mediates each use.

Advantages. Semantic Authority Updates stay in the SMF. Revocation is the
next Decision, not a race to delete a sandbox rule. The target prover, when
used, checks a rarely changed envelope. Cross-enterprise calls reevaluate
at the receiving gateway.

Limitations. Every governed use has to pass the gateway. A camera, file, or
tool the agent can reach around the gateway is outside this pattern. The
envelope itself must remain inside the standing FIP authority for "call the
gateway," and that envelope must not be described as camera authority.
Latency and availability of the SMF become part of fail-closed behavior: if
the SMF cannot evaluate, the gateway does not grant.

## O. Pattern 2, execution-envelope update

```text
FIP authority evolution
    -> new Decision
    -> Enforcement IR
    -> OpenShell policy update
    -> verification
    -> execution
```

Advantages. The agent receives a direct technical capability that a gateway
cannot proxy. The installed rule can be checked with the FIP subset
verifier and, where the model applies, the NVIDIA prover.

Limitations. Every expansion and contraction is a target-policy change.
Delay, replay, and leftover rules are the races in section M. OpenShell
v0.1.2 can update network rules while a sandbox runs. Filesystem, Landlock,
and process identity are establishment-bound in the M6 profile, so a
contraction of those controls ends the context rather than patching it.
This pattern is a poor fit for a grant the target cannot revoke.

Neither pattern is universally better. Mediated federation fits per-use
decisions whose technical path can be forced through one gateway.
Envelope update fits a capability the process must exercise directly, and
only when the target lifetime can contract with `A(t)`.

## P. NVIDIA Policy Prover

The prover is a target-policy verifier. It is not semantic authority.

Technical Policy Update, authority unchanged:

```text
existing semantic authority
    -> target policy proposal
    -> FIP subset verification
    -> NVIDIA prover, against the operator's modeled boundary
    -> apply
```

Semantic Authority Update:

```text
changed governed facts
    -> new FIP authority
    -> new authorized technical boundary
    -> target compilation
    -> FIP subset verification
    -> NVIDIA prover, where the model applies
    -> apply
```

A prover result of `within_boundary` means the candidate is contained in
the modeled technical boundary that was supplied. It does not mean the
organizational change was legitimate. `unsupported` and `inconclusive`
remain failures. MCP, GraphQL, and credential-use authority stay outside
the v0.1.2 boundary model, as M7 recorded.

## Q. NVIDIA Advisor

M7 stands: an OpenShell approval is not a FIP Decision.

An Advisor approval can be Evidence that a technical gate opened. The FIP
question remains whether the semantic approver has the Role, Authority,
Scope, and Delegation the requirement demands. Those are `approverIds` and
Delegation, not the sandbox operator who ran `openshell rule approve`.

Automatic Advisor approval can admit a new public host when no prover
finding and no destination flag are present. That event is still not FIP
authorization.

```text
NVIDIA_AUTO_APPROVED  !=  FIP_AUTHORIZED
NVIDIA_PROVER_PASS    !=  FIP_AUTHORIZED
OPENSHELL_ALLOW       !=  FIP_AUTHORIZED
```

Each right-hand side is an `authorityDecision` of `AUTHORIZED` under the
current snapshot. Each left-hand side is a target or verifier fact. An
observed allow still does not rewrite `DENIED`, `INCOMPLETE`, or `REVIEW`.

## R. CAMEO boundary

This boundary is a design guide. It is not a FIP conformance rule.
[boundaries.md](../specification/fip-0.2/boundaries.md) already places
Mission Blueprints, automatic derivation, and a control loop that rewrites
policy from runtime events outside FIP. A conforming implementation must
accept a hand-written AuthorityPolicy and Exchange.

| Change | Where it belongs |
| --- | --- |
| Temporary camera access under an existing mutual-aid Authorization | Local GOCP, FIP, and SMF |
| One Delegation or approval Decision inside the current mission | Local runtime authority evolution |
| An entire agency joins the mission | Likely CAMEO recompilation of the Mission Blueprint |
| The mission objective changes | CAMEO recompilation |
| A new capability class appears that the blueprint never named | Likely CAMEO recompilation, then a new Authority Plan |

Runtime feedback can tell BILLA that a local grant was used or withdrawn.
That report does not itself rewrite the blueprint. Recompilation is a CAMEO
act. Local evolution is a new evaluation under documents that already exist.

## S. Safety invariants

| Id | Statement | Label |
| --- | --- | --- |
| I1 | No operational effect without currently valid semantic authority, except explicitly accepted execution substrate, and that substrate does not override a FIP prohibition. | Already normative, as the subset invariant plus prohibition dominance. The word "currently" is the clarification that Validity and Conditions are part of the input. |
| I2 | Target policy cannot create semantic authority. | Already normative. An observed allow does not rewrite a denial. |
| I3 | Target approval cannot create semantic authority. | Already normative. `APPROVAL_PENDING` does not satisfy `require-approval`. |
| I4 | Prover success cannot create semantic authority. | Clarification of I2. The prover result is Evidence about a target policy. |
| I5 | Foreign authority evidence cannot automatically create local authority. | Already normative. The receiver reevaluates. |
| I6 | Authority expansion requires a new valid authority basis and, where the policy requires approval, a new Decision. | Clarification. A basis is an Authorization that evaluates under the new facts. A Decision is required when `require-approval` or `REVIEW` applies, not on every expansion. |
| I7 | Authority contraction invalidates dependent stale Decisions and the enforcement realizations that depended on them. | Already normative for Validity, `revocable`, and `validity-bound` when the target can enforce that lifetime. Candidate runtime requirement for cached session state the lifetime field does not cover. |
| I8 | A Decision is bound to the authority and context snapshot used to derive it. | Clarification of provenance. An explicit snapshot identifier is a candidate runtime requirement. |
| I9 | Expired or revoked authority must not survive in a cached Decision, a session, a credential use, or a stale target policy. | Already normative for Validity and for target lifetimes the author required. Credential presentation is already not authorization. Session teardown beyond those lifetimes is a candidate runtime requirement. |
| I10 | Emergency handling goes through governance. It does not bypass the SMF. | Clarification. No primitive in FIP 0.2 is an emergency bypass. |
| I11 | Prohibition dominance continues during exceptional conditions. A higher-order change counts only when the applicable policy itself changes which Prohibition applies, by Scope, Condition, or Validity. There is no implicit emergency override. | Already normative, plus this clarification. |
| I12 | Runtime enforcement authority remains a subset of currently effective FIP authority plus explicitly accepted substrate. | Already normative, indexed by `t` as a clarification. |

I6 is intentionally narrower than "every expansion needs a fresh approval
Decision." An Authorization that becomes applicable because a Condition
flipped does not need a second human if the policy did not require
approval. It does need a new evaluation.

## T. Q13 attack catalog

Q13 is not run here. FIP 0.1 experimental evidence remains FIP 0.1 evidence.

Retained static and adapter attacks:

| Attack | Layer |
| --- | --- |
| Binding substitution | Adapter/compiler |
| Path widening | Adapter/compiler, target-policy |
| Operation widening | Adapter/compiler |
| allOf dropping | Semantic, adapter/compiler |
| Prohibition bypass | Semantic |
| Substrate laundering or widening | Adapter/compiler, target-policy |
| Lifetime widening | Authority-state, adapter/compiler |
| Capability spoofing | Adapter/compiler |
| Credential widening | Semantic, adapter/compiler |
| Target, version, or profile mismatch | Adapter/compiler |
| Adapter or policy mutation | Target-policy |
| Workdir leakage | Target-policy, runtime enforcement |
| Enforcement downgrade | Target-policy, runtime enforcement |
| Alternate-path bypass | Runtime enforcement |

Added runtime-authority-transition attacks:

| Attack | Layer |
| --- | --- |
| Stale emergency state | Authority-state |
| Forged emergency evidence | Semantic, authority-state |
| Expired delegation replay | Authority-state |
| Revoked delegation replay | Authority-state |
| Approval replay | Authority-state |
| Decision replay against a new AuthorityState | Authority-state |
| Purpose substitution after authorization | Semantic, authority-state |
| Scope widening after authorization | Semantic, authority-state |
| Resource substitution after authorization | Semantic |
| Actor substitution | Semantic |
| Authority retained after the emergency ends | Authority-state, runtime enforcement |
| Stale OpenShell rule after FIP contraction | Target-policy, runtime enforcement |
| Delayed revocation | Runtime enforcement |
| Target policy update before the semantic Decision | Target-policy |
| Semantic Decision without the required target update | Runtime enforcement |
| Concurrent expand and contract | Authority-state, runtime enforcement |
| Long-running action survives revocation | Runtime enforcement |
| Cached authorization survives Validity expiration | Authority-state |
| Foreign Decision treated as a local grant | Cross-enterprise |
| Automatic NVIDIA approval treated as FIP authorization | Target-policy, semantic |
| NVIDIA prover pass treated as FIP authorization | Target-policy, semantic |
| Stale effective-policy verification | Target-policy, runtime enforcement |

## U. Recommended Q13 structure

Four phases. Names are convenient, not a specification.

| Phase | Question | Evidence it may use |
| --- | --- | --- |
| Q13A | Do FIP 0.2 documents and the evaluator still honor the frozen 0.1 distinctions, including `ESCALATE` not becoming `AUTHORIZED`? | New 0.2 runs. Existing 0.1 reports stay labeled 0.1. |
| Q13B | Can an adversary widen a static compilation or a target policy? | The retained attack list, against the pinned v0.1.2 adapter, without new product scope. |
| Q13C | Can an adversary keep an effect after `A(t)` changes? | The new attack list. Document and evaluator cases can run without a sandbox. Target leftover-rule cases use the pinned runtime only where M6 already showed a deployable policy. |
| Q13D | Combinatorial and fuzz campaigns over compositions of the above. | After A through C have oracles. Not a substitute for them. |

Q13C does not need Sentry, a live prover binary, or a new primitive. Cases
that only restate M6 limits, such as exact model identity, stay limits.
They are not new failures.

## V. FIP 0.2 impact

**CLARIFICATION_ONLY** for how the existing specification is read.

The specification text, schemas, primitives (28), and relationships (26)
are **NO_CHANGE**. This study is not an `OPTIONAL_EXTENSION` and not a
`FUTURE_VERSION_CANDIDATE`. Candidate runtime requirements in sections J, L,
and M stay outside FIP 0.2 until a later revision adopts them.

## W. Files

- Added `docs/research/governed-runtime-authority-evolution.md`
- `docs/research/nvidia-open-agent-safety-platform-integration-study.md`
  gains one cross-reference. Its conclusions are unchanged.

No normative specification file, schema, adapter, or M4, M5, or M6 evidence
file is part of this change. Provenance is not regenerated. `docs/research/`
is outside the FIP 0.2 provenance root.

## X. Validation

`python tests/check_links.py` passed. `python tools/public_release_audit.py`
passed with 0 findings. `git diff --check` on `docs/research` reported no
whitespace errors. `docs/specification/fip-0.2/primitives.md` still states
28 primitives. `docs/specification/fip-0.2/relations.md` still states 26
relationships. Those files, the FIP 0.2 schemas, and the M4 and M5 evidence
directories are unchanged from HEAD. The pinned adapter and M6 artifacts
remain the prior uncommitted M6 tree. This study did not edit them.

## Y. Git status

HEAD remains `affa5fc2ae1e9b18e141c7e16b09d83debcdfdbf` on
`feature/openshell-integration`. `docs/research/` is untracked and holds
this study plus the M7 study. No commit, push, tag, or merge.

## Z. Recommendation

**READY_FOR_Q13**

The evolution model fits the existing semantics. Q13 can test the attack
catalog without another architecture pass. Candidate runtime requirements
for snapshot identifiers and session teardown are future deployment work.
They do not block the pinned-adapter experiment.
