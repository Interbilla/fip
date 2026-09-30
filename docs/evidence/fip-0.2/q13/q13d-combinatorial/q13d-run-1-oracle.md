# q13d-run-1 oracle note

`q13d-run-1` is preserved as the generator wrote it. This note is outside that directory.

The stop at `q13d-seed-0001-0001-positive` is an oracle defect. The exact filesystem read was `AUTHORIZED`, derivation matched, compilation was `FULL`, and the policy was deployable. The oracle required `coverageDisposition == FULL` from a nested field the coverage result does not use, so the value was empty and the positive control was marked a violation.

The next run reads `compilationDisposition` from the coverage result itself.
