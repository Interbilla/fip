# Q13D q13d-run-4

Generator `q13d-generator-4`. Conclusion: **PASS_WITH_DOCUMENTED_LIMITATIONS**.

757 constrained cases completed with no oracle violation. This count is aggregate generated exposure, not an empirical probability of universal safety. No runtime action executed. Runtime operational opportunities: 0. Unauthorized deployable emissions: 0.

## Seeds

| Seed | Content |
| --- | --- |
| q13d-seed-0001 | Pairwise combinations of actor, resource, action, purpose, scope, authority, authorization, delegation, validity, approval, and binding |
| q13d-seed-0002 | Higher-order combinations A through L |
| q13d-seed-0003 | Transition sequences A through E |
| q13d-seed-0004 | Historical failure seeds and the approval-withheld oracle regression |
| q13d-seed-0005 | Positive controls, target mutations, and unsupported target requirements |
| q13d-seed-0006 | Cross-surface, cross-enterprise, prohibition, role, and condition cases |

## Primary counts

| Outcome | Count |
| --- | --- |
| POSITIVE_CONTROL_AUTHORIZED | 130 |
| SEMANTICALLY_PREVENTED | 569 |
| DERIVATION_REJECTED | 19 |
| COVERAGE_REJECTED | 18 |
| TARGET_POLICY_REJECTED | 9 |
| TARGET_STALE_DETECTED | 3 |
| TARGET_LIMITED | 5 |
| APPROVAL_WITHHELD | 4 |

Semantic decisions: 186 `AUTHORIZED`, 443 `DENIED`, 128 `INCOMPLETE`. Operational IRs: 182. Deployable policies: 157, all on cases whose oracle allowed a current deployable policy. Widened or stale policies were rejected by a separate check and were not counted as unauthorized emissions.

## Historical seeds

Expired policy, expired delegation, forged delegation, and resource substitution are `DENIED` with no deployable policy. The ancestor IR is `DERIVATION_REJECTED`. The pattern locator `/mission/*` is `COVERAGE_REJECTED` and not deployable. Absent approval stays `APPROVAL_WITHHELD`: `AUTHORIZED` with `approval_required`, no operational IR, and no deployable policy.

## Limitations

Model identity, independent credential use, and strict executable identity stay semantically authorized where the policy is valid and are not `FULL` or deployable. Filesystem stale-policy detection is not live retraction. No session or sandbox operation was run.

Runs `q13d-run-1`, `q13d-run-2`, and `q13d-run-3` are preserved oracle or generator stops. They are not product failures.
