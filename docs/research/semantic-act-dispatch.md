# Semantic act dispatch

Non-normative engineering note for the Q13C run-1 failure `F-forged-delegation`.
It does not change the FIP 0.2 specification. Primitive count remains 28.
Relationship count remains 26.

Preserved `q13c-run-1` hashes, LF-normalized, recorded before the evaluator change:

| File | SHA-256 |
| --- | --- |
| failure/observed.json | `4c354e019c07e4240b47f1a0e727e141f515cbb22008916170137e5c390490b3` |
| failure/prior-ir.json | `adcf7245439a246ff239c677ce9008f4e92b9e4a8dbd3f9ddf91739e927a276f` |
| failure/prior-target-policy.json | `85754a9ce0d120fa80b1f8d260907021146dc7d898b820da8434ad989f2f41a2` |
| failure/record.json | `04877ac98dae28a832f60d7b93512d7c7a522509a6d66429d9c02f1576871081` |
| failure/source.json | `13815ac762b6287ed489bb6c63cc2bf233e0bce76c40b04654e947a22f622ee7` |
| hashes.json | `740bfd61bc261fce9de10b9c8029b861e2a42fca94e97fc72c4cb97d6ab92d2f` |
| report.md | `5baf0ce4a86f1a26f2a2dcb1be8bc02cde503263f9a466ba4b08edf4eee898ef` |
| results.json | `d9416cf0fbbc2ab42bf9fca056630b6e8ddd432a79539a7c8e522dbf9819f2c3` |
| transition-sequence.json | `9750bd431abb0df3797d95b25e54c416f93b55833c773a33d9d8100e25dda32c` |

## Call order in `_assess_exchange`

1. Status, mode, and known `exchangeType`.
2. `_blocked_inputs`, including forbidden act changes.
3. Required fields for that act.
4. Exchange `validity`, when the act is Request, Instruction, Delegation, Authorization, or Decision and the field is present.
5. Act-specific returns for Assertion, Recommendation, Response, and Decision.
6. Operational branch: if `mode == "operational"` and the act is in `CONSEQUENTIAL`, provenance, authority, companion policy, and policy identity are checked, then `_exchange_against_policy` returns.
7. `_delegation`, only if step 6 did not return.

`CONSEQUENTIAL` is Request, Instruction, Delegation, and Authorization.

## Specialized rules

| Act | Specialized rule | Where it runs | Operational reachability |
| --- | --- | --- | --- |
| Assertion | No operational effect | Return before the consequential branch | Reachable |
| Recommendation | No operational effect | Return before the consequential branch | Reachable |
| Response | No independent execution grant | Return before the consequential branch | Reachable |
| Decision | Approval decision rules, including decision validity | `_assess_decision`, before the consequential branch | Reachable. Decision is not consequential |
| Request | No effect from well-formedness; operational grant, purpose, and conditions | The consequential branch is the Request rule. Forbidden Request escalations run in `_blocked_inputs` | No separate Request predicate is skipped |
| Instruction | Still requires a non-dominated authorization | Prohibition dominance is inside the policy grant. Instruction-to-Delegation escalation runs in `_blocked_inputs` | No separate Instruction predicate is skipped |
| Delegation | `canDelegate`, coordination, and delegable authority kind | `_delegation` | Bypassed when mode is operational, because step 6 returns first |
| Authorization | Stating a grant is not compilation | No separate Authorization predicate exists. The consequential branch evaluates the companion policy and leaves compilation to a later compiler | No skipped Authorization predicate |

## Defect

The bypass is a dispatch defect. An operational Delegation exchange with `canDelegate: false` is authorized from the action grant. `_delegation` still returns `DENIED` with `delegation_requires_explicit_authority` for the same facts in semantic-only mode, and for an operational exchange only when the generic return is not taken first.

Request, Instruction, and Authorization do not have a specialized predicate sitting after that return. They are not the same defect. Their rules are either in front of the return or are the return itself.

## Repair boundary

Call the existing `_delegation` predicate before the operational grant. A denial from that predicate is the authority decision. An authorization from that predicate still passes through the existing operational requirements: provenance, authority, companion policy, policy identity, and the policy grant. The old late call to `_delegation` is removed because the early return makes it unreachable. No second evaluator. No new delegation meaning.
