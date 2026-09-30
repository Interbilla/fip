# q13c-run-2 oracle note

`q13c-run-2` is preserved as the runner wrote it. This note is outside that directory.

The stop at `G-expired-approval` is an oracle defect. The expired approval produced the same non-executable state as no approval: `AUTHORIZED` with `approval_required`, no operational IR, and no deployable policy. A current approval in the same run produced an operational IR. The expired decision was not accepted as executable authority.

The oracle treated the decision word `AUTHORIZED` as acceptance. The next run uses executable authority: an operational IR, a deployable policy, or `AUTHORIZED` without `approval_required`.
