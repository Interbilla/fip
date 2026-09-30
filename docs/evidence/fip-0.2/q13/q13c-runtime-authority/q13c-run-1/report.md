# Q13C q13c-run-1

Conclusion: **FAIL**. Recommendation: **IMPLEMENTATION_FIX_REQUIRED**.

The run stopped at the first gate failure. No later attack was executed. The evaluator was not changed. No sandbox was started, and no runtime operational action was executed.

## Failure

Case `F-forged-delegation`.

A Delegation exchange with `canDelegate: false`, authority kind `direct`, and `validity.state: valid` was evaluated against the current filesystem authorization for `ReadInspectionInput`.

Observed:

- semantic decision `AUTHORIZED`
- operational IR produced
- derivation matched the fresh projection
- compilation `FULL`
- deployable filesystem policy emitted

The delegation rule says only an explicit bounded delegation can succeed. This exchange is not that delegation. The operational exchange path returns the action grant before the delegation predicate runs, so `canDelegate: false` is not consulted.

This is a semantic acceptance of a delegation the current facts do not allow. It is not a recorded runtime effect. Runtime operational opportunities: 0.

## Baseline executed before the stop

| Step | Result |
| --- | --- |
| T0 no authorization | `REVIEW`, no operational IR, no deployable policy |
| T1 facts restored | `AUTHORIZED` |
| T2 exact read | derivation matched, compilation `FULL`, deployable policy |
| T3 purpose substituted | `DENIED` (`purpose_mismatch`) |
| T4 purpose restored | `AUTHORIZED` and deployable |
| T5 delegation validity expired | `DENIED` (`validity_expired`) |
| T6 fresh delegation exchange for an already authorized action | `AUTHORIZED` and deployable |
| T7 applicability validity expired | `DENIED` (`validity_expired`) |
| A emergency flag on the expired condition | `DENIED` |
| B stale purpose snapshot | `DENIED` |
| C stale state label on expired facts | `DENIED` |
| E revoked delegation validity | `DENIED` (`validity_revoked`) |
| F forged delegation | **FAIL** |

T0 is `REVIEW` with `absence_is_not_permission`, which grants nothing. T6 shows that a well-formed delegation exchange for an already authorized action is accepted. It does not show that `canDelegate` was checked. T5 and E show that an invalid validity state is rejected before the action grant.

## Not executed after the stop

Approval replay, scope substitution, resource substitution, actor substitution, role substitution, binding substitution, foreign decision and foreign IR, prover or target approval as authority, target-policy contraction, older-policy reload, mediated federation, execution-envelope retraction, TOCTOU, session persistence, long-running actions, and credential persistence.

## Runtime

No operational action executed. Runtime UOER denominator is 0. No unauthorized operational effect was observed because no effect was attempted on a target.
