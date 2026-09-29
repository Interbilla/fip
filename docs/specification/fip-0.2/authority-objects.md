# Authority objects

This section norms the primitives that gate authority. Execution locators are
specified in [execution-binding.md](execution-binding.md), not here.

## Condition

A Condition is an executable predicate. `type` is one of `scope-match`,
`validity-window`, `purpose-match`, `approval-present`, and reserved `custom`.

| Type | Holds when |
| --- | --- |
| `scope-match` | The exchange scope is within the referenced Scope. |
| `validity-window` | The referenced Validity `state` is `valid`. |
| `purpose-match` | The exchange purpose equals the condition's purpose. |
| `approval-present` | An approval Decision satisfying [enforcement-requirement.md](enforcement-requirement.md) is in context for the referenced requirement. |
| `custom` | Reserved. Not conforming in M0. |

If a condition cannot be evaluated, the result is `INCOMPLETE`, not
permission. A failed condition on a permit yields `DENIED` when the predicate
is evaluated and is false, and `INCOMPLETE` when the inputs needed to evaluate
it are absent.

## Constraint

A Constraint is an executable limit. `type` is one of `locator-pattern`,
`operation`, `protocol-parameter`, and reserved `custom`.

A `protocol-parameter` constraint MAY name an HTTP method, an HTTP path, an
MCP tool argument name, or another parameter of a specified protocol profile.
The constraint is part of the requirement. An adapter that cannot enforce it
without widening it MUST NOT mark it enforced.

Unknown constraint types fail closed.

## Scope

Scope dimensions are exactly `spatial`, `temporal`, and `jurisdictional`.
No fourth dimension is defined. A scope value is a string compared within a
single dimension. M0 does not define calendar arithmetic or geographic
containment. If a temporal or spatial comparison is required and no comparison
rule is stated on the condition, the condition is unevaluable and the result
is `INCOMPLETE`.

Scope MUST NOT be used as a filesystem path, host, or port.

## Validity

Validity `state` is exactly `valid`, `expired`, `revoked`, `superseded`, or
`not-yet-valid`. Optional `notBefore` and `notAfter` are RFC 3339 timestamps.
If they are inconsistent with `state`, the object is `INCOMPLETE`.

Any state other than `valid` denies use of the authorization, delegation, or
decision that carries it. The reason codes are `validity_expired`,
`validity_revoked`, `validity_superseded`, and `validity_not_yet_valid`.

## Authorization and Permission

An Authorization ties `actorId`, `authorityId`, action identifiers, resource
identifiers, an optional purpose, requirement identifiers, scopes, and
validity. A Permission is the `permits` relationship from that authorization
to those actions.

In operational mode, an authorization that permits an action MUST reference at
least one EnforcementRequirement (`requiresEnforcement`). A missing
requirement reference on an operational permit yields `INCOMPLETE`.

A missing Authority on a consequential act yields `INCOMPLETE` with code
`missing_authority`. It is not permission.

A missing ExecutionBinding for an operational permit yields `INCOMPLETE` with
code `missing_execution_binding`. It is not execution authorization. The act
MUST NOT be described as `AUTHORIZED` while a required binding is absent,
because the operational document is not fully specified.

In semantic-only mode, missing bindings are expected. The authority decision
follows the semantic rules only, and compilation disposition is `NOT_COMPILED`.

## Prohibition

A Prohibition is the `prohibits` relationship. It MAY name actions, resources,
binding identifiers, a binding pattern, and deny requirements.

An applicable prohibition produces `authorityDecision` `DENIED` for the
overlapping act, with code `prohibition_dominates` when a permit also matched,
or `explicit_prohibition` when only the prohibition matched.

## Obligation

An Obligation is the `obligates` relationship. It MUST reference one or more
EnforcementRequirements. It MUST NOT be represented as a permit.

An obligation does not grant execution authority. Code
`obligation_is_not_authority` applies if an implementation would otherwise
treat the obligation as a permit. `compilationDisposition` `FULL` additionally
requires each referenced requirement to be enforced.

A normative summary of `obligated` agrees with the presence of the obligation
edge. It does not skip the requirement.

## Delegation

A Delegation includes `from`, `to`, and `canDelegate`. It MAY list the
authorization identifiers and binding identifiers that move.

Delegation is authorized only when `canDelegate` is true, or when `canDelegate`
is absent and the linked Authority `kind` is `delegable`. If `canDelegate` is
false, the delegation is `DENIED` even when the authority kind is `delegable`.
Implicit delegation, coordination, and emergent multi-agent assignment are not
delegations and MUST be denied with `delegation_requires_explicit_authority`
or `coordination_is_not_enterprise_delegation` as appropriate.

A delegate receives only the referenced authorizations and bindings. Delegation
does not create new bindings.

## Evidence, provenance, and credentials

Evidence, Provenance, and Credential remain distinct.

- Supplying Evidence does not satisfy a provenance requirement.
- A technically valid Credential is not an Authorization. Code
  `credential_is_not_authorization`.
- Provenance `digest`, when present, is an opaque string. M0 does not define
  a canonicalization or signature algorithm. A digest MUST NOT be treated as
  verified.
- Caller-supplied assertions that a payload was tampered or replayed are
  inputs. If a document states `tamperedAfterBinding` or `staleReplay` as
  true, a conforming evaluator MUST deny. FIP does not by itself observe the
  host.

## Free text and memory

Untrusted natural language and an agent memory write MUST NOT create
authority. Codes `free_text_cannot_manufacture_authority`,
`authority_source_free_text`, and `memory_cannot_manufacture_authority` apply
as they did for those cases in 0.1. Domain text that GOCP did not admit stays
descriptive.
