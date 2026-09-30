# Q13 adversarial enforcement campaign

Baseline commit `6435895898dd089ad545941fa226eb1c0a6860a9`.

Pinned target: NVIDIA OpenShell v0.1.2 commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`.

Closeout disposition: **Q13_QUALIFIED_WITH_DOCUMENTED_LIMITATIONS**. See [Q13-QUALIFICATION-REPORT.md](Q13-QUALIFICATION-REPORT.md).

The accepted normative specification change from the campaign baseline is the derivation clarification in [enforcement-ir.md](../../../specification/fip-0.2/enforcement-ir.md) and the sentences that point to it.

## Gate

Q13A run `q13-run-3` is **PASS**. Q13B runs `q13b-run-1` and `q13b-run-2` are preserved **FAIL** results. Q13B run `q13b-run-3` is **PASS_WITH_DOCUMENTED_LIMITATIONS**. Q13C runs `q13c-run-1` and `q13c-run-3` are preserved **FAIL** results. Q13C run `q13c-run-2` is a preserved oracle stop. Q13C run `q13c-run-4` is **PASS_WITH_DOCUMENTED_LIMITATIONS**. Q13D run `q13d-run-4` is **PASS_WITH_DOCUMENTED_LIMITATIONS**.

Preserved historical runs:

- [q13-run-1](q13a-semantic-regression/q13-run-1/report.md): substrate-oracle failure plus validity failures.
- [q13-run-2](q13a-semantic-regression/q13-run-2/report.md): corrected substrate oracle, 15 PASS / 2 FAIL.

The run-2 failures `expired-policy-validity` and `expired-delegation-exchange` stay labeled as historical failures.

## Reports

- [Q13 qualification report](Q13-QUALIFICATION-REPORT.md)
- [Q13A report](q13a-semantic-regression/report.md)
- [Q13A results](q13a-semantic-regression/results.json)
- [Q13A run-3 engineering note](q13a-semantic-regression/q13-run-3/engineering-note.md)
- [Q13B run-1 report](q13b-static-enforcement/q13b-run-1/report.md)
- [Q13B run-2 report](q13b-static-enforcement/q13b-run-2/report.md)
- [Q13B run-3 report](q13b-static-enforcement/q13b-run-3/report.md)
- [Q13B run-3 engineering note](q13b-static-enforcement/q13b-run-3/engineering-note.md)
- [Q13B status](q13b-static-enforcement/NOT_RUN.md)
- [Q13C run-1 report](q13c-runtime-authority/q13c-run-1/report.md)
- [Q13C run-3 report](q13c-runtime-authority/q13c-run-3/report.md)
- [Q13C run-4 report](q13c-runtime-authority/q13c-run-4/report.md)
- [Q13C status](q13c-runtime-authority/NOT_RUN.md)
- [Q13D run-4 report](q13d-combinatorial/q13d-run-4/report.md)
- [Q13D status](q13d-combinatorial/NOT_RUN.md)

Runner: `docs/evidence/fip-0.2/q13/run_q13.py`.
