# Authorization grant matching

Non-normative note for the Q13C run-3 failure `L-resource-substitution`.
It does not change the FIP 0.2 specification. Resource identity is exact.
No hierarchical or related-resource rule is defined, so none is inferred.

## Matcher before the repair

`_exchange_against_policy` selects a policy grant by action identifier, then
walks authorizations that list that action.

| Exchange field | Policy field | Matched before | Rule | On failure |
| --- | --- | --- | --- | --- |
| `action` | Authorization `actionIds` and the grant `actionId` | Yes | Exact identifier | No grant: `REVIEW` with `absence_is_not_permission` |
| `purpose` | Authorization `purpose`, when both are present | Yes | Exact string | `DENIED`, reason `purpose_mismatch` |
| `scope` | A `scope-match` condition | Only when that condition is present | Exact value within one dimension. No containment | Condition false: `DENIED`. Missing input: `INCOMPLETE` |
| `resource` | Authorization `resourceIds` | No | The grant was selected by action. Projection kept the policy resource | Inconsistent exchange stayed `AUTHORIZED` |
| `actor.id` | Authorization `actorId` | No | Not consulted | A different actor stayed `AUTHORIZED` |
| `authority.id` | Authorization `authorityId` | No | Not consulted | A different authority identifier stayed `AUTHORIZED` |
| `authorization.id` | Authorization `authorizationId` | No | Not consulted | A different authorization identifier stayed `AUTHORIZED` |
| `role` | None on Authorization | No | Role does not grant an operation | An extra role label neither grants nor is a constraint |
| binding | Policy execution bindings | No exchange binding field | Bindings are taken from the matched policy after authorization | A different requested resource must not be rewritten onto the policy binding |

`purpose_mismatch` is a reason string. It is not a schema reason code. The
closed reason-code list is unchanged.

## Repair

An authorization is eligible only when the presented identifiers are exactly
those on that authorization:

- A presented resource identifier must be a member of `resourceIds`.
- A presented actor identifier must equal `actorId`.
- A presented authority identifier must equal `authorityId`.
- A presented authorization identifier must equal `authorizationId`.
- Purpose keeps the existing exact comparison.
- `scopeIds`, when present, use the existing scope-match comparison: equal
  value within the referenced dimension.
- An action that is outside every authorization is `DENIED` with reason
  `action_mismatch` when the policy has authorizations. A policy with no
  authorizations stays `REVIEW` with `absence_is_not_permission`.

The first failing identity is a reason, not a new code: `resource_mismatch`,
`actor_mismatch`, `authority_mismatch`, `authorization_mismatch`,
`action_mismatch`, or the existing `purpose_mismatch`. The decision is
`DENIED` in authority evaluation. Projection is not asked to repair it.

Role remains unconstrained. A role label does not authorize, and it does not
deny an otherwise consistent authorization, because Authorization has no role
constraint.
