# Q13C q13c-run-4

Conclusion: **PASS_WITH_DOCUMENTED_LIMITATIONS**.

39 cases completed. No gate failure. No runtime action executed. Runtime operational opportunities: 0.

## Historical cases now fail closed

`F-forged-delegation` is `DENIED` with `delegation_requires_explicit_authority` on the paired control, and the forged exchange itself is `DENIED` with no operational IR.

`L-resource-substitution` is `DENIED` with no operational IR and no deployable policy. The exchange resource `mission:Other` is not rewritten to `mission:InspectionInput`.

## Transition sequence

| Step | Result |
| --- | --- |
| T0 | `REVIEW`, no IR, no policy |
| T1, T2 | `AUTHORIZED`, derivation matched, deployable `FULL` |
| T3 purpose mismatch | `DENIED` |
| T4 purpose restored | `AUTHORIZED`, deployable |
| T5 delegation expired | `DENIED` |
| T6 bounded delegation | `AUTHORIZED` after `canDelegate: false` was `DENIED` |
| T7 applicability ended | `DENIED` |

## Temporal freshness

After the policy validity expires, the fresh exchange is `DENIED` and emits no IR. The previously deployable filesystem policy is no longer accepted against the empty grant set (`read_authority_mismatch`, `path_broader_or_unaccepted`). That is detection, not retraction. The pinned filesystem policy remains establishment-bound and requires context restart. The prior IR does not match the contracted sources.

An exchange evaluated against that expired policy reports reason `action_mismatch`, because the expired policy produces no action grant. Direct policy evaluation still denies with `validity_expired`. The exchange is not authorized.

## Limitations recorded in this run

Role is not an authorization constraint. A role label on an otherwise exact read stays `AUTHORIZED` for that same action and does not add a grant.

No sandbox, session, long-running action, or credential use was executed. Those rows are `UNOBSERVED` or `TARGET_LIMITED`. They are not runtime prevents and they are not FIP grants.

A current approval authorizes the delete policy semantically. OpenShell compilation of that delete requirement is `REJECTED`, so it is not a deployable filesystem policy.
