# Q13A semantic regression

Run id: `q13-run-1`

Baseline commit: `6435895898dd089ad545941fa226eb1c0a6860a9`

OpenShell pin: v0.1.2 `6648bd0c290efbc41ba131ee9831ee45cd431f94`

Gate: **FAIL**

Passed cases: 14. Failed cases: 3.

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
| substrate-is-not-a-fip-grant | substrate source execution-substrate | sources=execution-substrate | FAIL |
| target-policy-is-not-a-fip-grant | no operational IR | no operational IR | PASS |
| prover-pass-is-not-a-fip-grant | DENIED | DENIED | PASS |
| automatic-target-approval-is-not-a-fip-grant | DENIED | DENIED | PASS |
| target-approval-is-not-a-fip-grant | DENIED | DENIED | PASS |
| expired-authorization-validity | DENIED | DENIED | PASS |
| expired-policy-validity | DENIED | AUTHORIZED | FAIL |
| expired-delegation-exchange | DENIED | AUTHORIZED | FAIL |

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
- `substrate-is-not-a-fip-grant`: Accepted substrate is compiled beside the grant and is not recorded as a fipGrant path.
- `target-policy-is-not-a-fip-grant`: An embedded filesystem policy does not become an operational projection.
- `prover-pass-is-not-a-fip-grant`: Synthetic PROVER_PASS evidence in a protected extension is not a FIP authorization. No prover CLI was executed.
- `automatic-target-approval-is-not-a-fip-grant`: Synthetic NVIDIA_AUTO_APPROVED evidence is not a FIP Decision. No Advisor CLI was executed.
- `target-approval-is-not-a-fip-grant`: Synthetic OPENSHELL_APPROVED evidence is not a FIP Decision.
- `expired-authorization-validity`: Authorization validity expired denies the grant and blocks projection. This is the working validity control.
- `expired-policy-validity`: AuthorityPolicy.validity expired remains AUTHORIZED and still projects an operational IR. Deployable target policy emitted: yes. primitives.md says a non-valid Validity denies use of the object that carries it.
- `expired-delegation-exchange`: A Delegation exchange carrying validity expired is AUTHORIZED. authority-objects.md says a non-valid state denies use of the delegation that carries it. No target policy is emitted because the exchange is semantic-only.

## Command tails

- exit 0: `conformance/runners/python_runner.py`

```
Python conformance: 47/47
```
- exit 0: `conformance/runners/javascript-runner.js`

```
JavaScript conformance: 47/47
```
