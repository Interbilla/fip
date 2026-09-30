# Q13C q13c-run-3

Conclusion: **FAIL**. The first gate failure is preserved. No later case was executed.

## Failure

Case `L-resource-substitution`.

The exchange names resource `mission:Other` and action `ReadInspectionInput`. The companion authorization names resource `mission:InspectionInput` for that action.

Observed:

- authority decision `AUTHORIZED`
- operational IR emitted
- derivation matched the fresh projection
- compilation `FULL`
- deployable filesystem policy emitted

The projected binding remains the policy resource `mission:InspectionInput` at `/mission/input`. The exchange resource was not copied into the IR. The decision still accepted an exchange whose resource is not the authorized resource.

No runtime action executed.

## Delegation repair observed in this run

`F-forged-delegation` is `DENIED` with no operational IR and no deployable policy.

`T6` is `AUTHORIZED` for `canDelegate: true` on a delegable authority, after the same authority with `canDelegate: false` was `DENIED` with `delegation_requires_explicit_authority`.

## Not executed after the stop

Actor substitution, role substitution, binding substitution, foreign decision and foreign IR, target contraction, derivation freshness against a contracted state, TOCTOU, mediated federation, execution envelope, session persistence, long-running action, and credential persistence.
