# Relationships

FIP 0.2 defines exactly 26 relationships. The first 24 keep the FIP 0.1 names
and order. `hasExecutionBinding` and `requiresEnforcement` are new. The
normative enumeration is
[vocabulary/fip-0.2.jsonld](vocabulary/fip-0.2.jsonld).

A relationship is executable when its endpoints are present. A missing endpoint
on a consequential operational act yields `INCOMPLETE`. It does not yield
permission.

| Relationship | Normative consequence |
| --- | --- |
| `requests` | Links a requesting act to the action it proposes. No execution effect. |
| `respondsTo` | Links a Response to the exchange it answers. Required for Response. |
| `usesResource` | Binds an action or exchange to a semantic Resource. Required before a binding may be required for that action. |
| `hasPurpose` | Binds a purpose to an authorization or exchange. A stated expected purpose that differs denies authority. |
| `hasIdentity` | Associates an Actor with an Identity. It does not grant an operation. |
| `presentsCredential` | Associates a presented Credential. Presentation is not authorization. A presented credential without a use-authorization MUST be denied for consequential effect. |
| `hasRole` | Associates an Actor with a Role. It does not grant an operation. |
| `ownedBy` | Descriptive stewardship. The owner is not thereby authorized to act. |
| `controlledBy` | Descriptive control. The controller is not thereby authorized to act. |
| `actsUnderAuthority` | Required link from an authorization or consequential exchange to an Authority. |
| `authorizedBy` | Required link from a permitted action to an Authorization. |
| `governedBy` | Required link from an authorization or exchange to a Policy. |
| `permits` | Edge from a Policy or Authorization to the actions it permits. A summary state `allowed` MUST agree. |
| `prohibits` | Edge from a Policy or Prohibition to what it forbids. A summary state `prohibited` MUST agree. Dominates overlapping `permits`. |
| `obligates` | Edge from a Policy or Obligation to the duties it requires. A summary state `obligated` MUST agree. Does not permit. |
| `constrainedBy` | Attaches a Constraint. The constraint is evaluated. It is not a comment. |
| `appliesWithin` | Attaches a Scope. An act outside that scope is denied. |
| `validDuring` | Attaches a Validity. A state other than `valid` denies use. |
| `delegatesTo` | Names the delegate. Delegation without this edge is incomplete. |
| `delegatesAuthority` | Names the authority transferred. Only referenced authorizations move. |
| `hasEvidence` | Attaches Evidence. It does not replace provenance or satisfy a requirement. |
| `derivedFrom` | Provenance derivation. It does not create authority. |
| `assertedBy` | Names the asserter. Required on provenance for operational documents. |
| `decidedBy` | Names the actor that recorded a Decision. |
| `hasExecutionBinding` | Links a Resource or Action to one or more ExecutionBindings. |
| `requiresEnforcement` | Links an Authorization, Permission, Prohibition, or Obligation to one or more EnforcementRequirements. |

If both a normative summary state and these edges are present, they MUST
agree:

| Summary state | Required edge agreement |
| --- | --- |
| `allowed` | At least one `permits` edge, and no dominating `prohibits` edge, before the act can be `AUTHORIZED`. |
| `prohibited` | A `prohibits` edge is present. |
| `obligated` | An `obligates` edge is present. |
| `unknown` | No `permits` edge is present. |

Disagreement yields `INCOMPLETE`. `unknown` is not permission.
