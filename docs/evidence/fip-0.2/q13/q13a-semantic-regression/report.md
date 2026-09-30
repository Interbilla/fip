# Q13A semantic regression

Run id: `q13-run-3`

Baseline commit: `6435895898dd089ad545941fa226eb1c0a6860a9`

OpenShell pin: v0.1.2 `6648bd0c290efbc41ba131ee9831ee45cd431f94`

Gate: **PASS**

Passed cases: 30. Failed cases: 0.

Q13B, Q13C, and Q13D were not started.

## Cases

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| primitive-count | 28 | 28 | PASS |
| relationship-count | 26 | 26 | PASS |
| frozen-conformance-vectors | 47 | 47 | PASS |
| prohibition-dominance | DENIED | DENIED | PASS |
| missing-authority | INCOMPLETE | INCOMPLETE | PASS |
| missing-binding | INCOMPLETE | INCOMPLETE | PASS |
| obligation-is-not-authority | INCOMPLETE | INCOMPLETE | PASS |
| require-approval-blocks-projection | no operational IR | no operational IR | PASS |
| foreign-decision-is-not-local-authorization | no operational IR | no operational IR | PASS |
| substrate-is-not-a-fip-grant | substrate source execution-substrate and absent from fipGrants | sources=execution-substrate substrateInGrants=none | PASS |
| target-policy-is-not-a-fip-grant | no operational IR | no operational IR | PASS |
| prover-pass-is-not-a-fip-grant | DENIED | DENIED | PASS |
| automatic-target-approval-is-not-a-fip-grant | DENIED | DENIED | PASS |
| target-approval-is-not-a-fip-grant | DENIED | DENIED | PASS |
| expired-authorization-validity | DENIED | DENIED | PASS |
| expired-policy-validity | DENIED | DENIED | PASS |
| expired-delegation-exchange | DENIED | DENIED | PASS |
| policy-validity-revoked | DENIED | DENIED | PASS |
| delegation-exchange-validity-revoked | DENIED | DENIED | PASS |
| policy-validity-superseded | DENIED | DENIED | PASS |
| delegation-exchange-validity-superseded | DENIED | DENIED | PASS |
| policy-validity-not-yet-valid | DENIED | DENIED | PASS |
| delegation-exchange-validity-not-yet-valid | DENIED | DENIED | PASS |
| policy-validity-absent | INCOMPLETE | INCOMPLETE | PASS |
| authorization-validity-absent | AUTHORIZED | AUTHORIZED | PASS |
| valid-approval-decision | AUTHORIZED | AUTHORIZED | PASS |
| approval-decision-validity-expired | DENIED | DENIED | PASS |
| approval-decision-validity-revoked | DENIED | DENIED | PASS |
| approval-decision-validity-superseded | DENIED | DENIED | PASS |
| approval-decision-validity-not-yet-valid | DENIED | DENIED | PASS |

## Notes

- `primitive-count`: FIP 0.2 adds ExecutionBinding and EnforcementRequirement after the frozen 26.
- `relationship-count`: FIP 0.2 adds hasExecutionBinding and requiresEnforcement after the frozen 24.
- `frozen-conformance-vectors`: FIP 0.1 vector files are counted, not relabeled as FIP 0.2 evidence.
- `prohibition-dominance`: A permit and a prohibition on the same action resolve to DENIED.
- `missing-authority`: An empty authority list is not permission and does not project an operational IR.
- `missing-binding`: A permit that names a missing binding is not execution authorization.
- `obligation-is-not-authority`: An obligation without an authorization does not project an operational IR.
- `require-approval-blocks-projection`: require-approval may record AUTHORIZED with approval_required, and projection stops until a valid Decision exists.
- `foreign-decision-is-not-local-authorization`: A Decision whose actor is outside approverIds does not satisfy require-approval. The Decision object is synthetic.
- `substrate-is-not-a-fip-grant`: Accepted substrate paths such as /usr and /tmp are compiled beside the grant. They are not fipGrant identifiers. Run 1 treated those paths as leakage; that oracle was a harness bug and is preserved under q13-run-1.
- `target-policy-is-not-a-fip-grant`: An embedded filesystem policy does not become an operational projection.
- `prover-pass-is-not-a-fip-grant`: Synthetic PROVER_PASS evidence in a protected extension is not a FIP authorization. No prover CLI was executed.
- `automatic-target-approval-is-not-a-fip-grant`: Synthetic NVIDIA_AUTO_APPROVED evidence is not a FIP Decision. No Advisor CLI was executed.
- `target-approval-is-not-a-fip-grant`: Synthetic OPENSHELL_APPROVED evidence is not a FIP Decision.
- `expired-authorization-validity`: Authorization validity expired denies the grant and blocks projection. This is the working validity control.
- `expired-policy-validity`: AuthorityPolicy.validity expired is denied. No operational IR is projected and no deployable target policy is emitted. The historical run-2 result was AUTHORIZED with a deployable policy.
- `expired-delegation-exchange`: A Delegation exchange carrying validity expired is denied. The historical run-2 result was AUTHORIZED.
- `policy-validity-revoked`: AuthorityPolicy.validity revoked denies use of the policy and blocks the operational IR.
- `delegation-exchange-validity-revoked`: Delegation exchange validity revoked denies the delegation act.
- `policy-validity-superseded`: AuthorityPolicy.validity superseded denies use of the policy and blocks the operational IR.
- `delegation-exchange-validity-superseded`: Delegation exchange validity superseded denies the delegation act.
- `policy-validity-not-yet-valid`: AuthorityPolicy.validity not-yet-valid denies use of the policy and blocks the operational IR.
- `delegation-exchange-validity-not-yet-valid`: Delegation exchange validity not-yet-valid denies the delegation act.
- `policy-validity-absent`: AuthorityPolicy.validity is required. Absence is incomplete, which is distinct from a non-valid state.
- `authorization-validity-absent`: Authorization validity is optional. Absence keeps the current usable authorization.
- `valid-approval-decision`: A valid approval Decision records approval and satisfies require-approval. It is not a deployable policy.
- `approval-decision-validity-expired`: Approval Decision validity expired does not establish authorization and does not satisfy require-approval.
- `approval-decision-validity-revoked`: Approval Decision validity revoked does not establish authorization and does not satisfy require-approval.
- `approval-decision-validity-superseded`: Approval Decision validity superseded does not establish authorization and does not satisfy require-approval.
- `approval-decision-validity-not-yet-valid`: Approval Decision validity not-yet-valid does not establish authorization and does not satisfy require-approval.

## Command tails

- exit 0: `conformance/runners/python_runner.py`

```
Python conformance: 47/47
```
- exit 0: `conformance/runners/javascript-runner.js`

```
JavaScript conformance: 47/47
```
