# Q13 qualification report

Disposition: **Q13_QUALIFIED_WITH_DOCUMENTED_LIMITATIONS**.

This report records the accepted Q13 campaign. It does not add a qualification claim beyond the preserved runs.

Campaign baseline: `6435895898dd089ad545941fa226eb1c0a6860a9`.

Pinned target: NVIDIA OpenShell **v0.1.2**, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`. Statements about OpenShell in this campaign are about that pin. They are not statements about a later OpenShell release.

Accepted implementation, and no other behavioral change:

- AuthorityPolicy and Delegation Validity are applied before use.
- A Delegation predicate runs before the operational grant.
- An exchange matches the granting Authorization by exact field identity.
- A consumed deployable IR must match a fresh projection. That clarification is the normative specification change from the baseline.
- The reference implementation verifies that derivation.
- An exact OpenShell filesystem profile rejects a pattern locator as exact coverage.

Failed runs are preserved. Their outcomes are not reclassified here.

Sentences inside an early run report that say a later phase had not started are the record of that run. This report is the closeout disposition.

## Q13A — semantic validity

Purpose: evaluated authority must equal currently valid authority.

Historical product failures, preserved:

- `q13-run-1` and `q13-run-2`: an expired AuthorityPolicy was `AUTHORIZED`.
- `q13-run-1` and `q13-run-2`: an expired Delegation exchange was `AUTHORIZED`.

`q13-run-1` also failed `substrate-is-not-a-fip-grant` on the oracle's expected text. `q13-run-2` corrected that oracle. The two validity failures remained. They are the product failures.

Repair: current Validity is applied to the policy and to the delegation exchange. A state other than `valid` denies use.

Accepted result: [q13-run-3](q13a-semantic-regression/q13-run-3/report.md) **PASS** (30/30).

## Q13B — static enforcement integrity

Purpose: a consumed deployable result must match a fresh projection, and a target requirement must be exactly representable. Coverage does not create authority. A target policy does not widen verified authority.

Historical product failure 1, preserved in [q13b-run-1](q13b-static-enforcement/q13b-run-1/report.md): after projection, `/mission/input` was consumed as `/mission`.

Repair: fresh semantic recomputation and derivation verification. A security-content mismatch is `REJECTED` with `subset_not_demonstrated` and is not deployable.

Historical product failure 2, preserved in [q13b-run-2](q13b-static-enforcement/q13b-run-2/report.md): `/mission/*` was stamped `FULL` as exact filesystem enforcement. Derivation had matched. This was not a derivation failure.

Repair: the OpenShell v0.1.2 exact filesystem profile. A pattern locator stays semantically `AUTHORIZED` and is coverage `REJECTED` with `filesystem_locator_not_exact`. That rejection is not `subset_not_demonstrated`.

Accepted result: [q13b-run-3](q13b-static-enforcement/q13b-run-3/report.md) **PASS_WITH_DOCUMENTED_LIMITATIONS**. The run matrix records a static gate of PASS and 0 unauthorized deployable emissions. The accepted qualification includes the limits in the [engineering note](q13b-static-enforcement/q13b-run-3/engineering-note.md): a directory rule includes descendants, and the symlink target is not proved statically.

## Q13C — governed runtime authority evolution

Purpose: authority-specific predicates cannot be bypassed; an exchange must match the granting Authorization; contraction is reflected by fresh evaluation; a stale IR is not current proof; a stale target policy is detected.

Historical product failure 1, preserved in [q13c-run-1](q13c-runtime-authority/q13c-run-1/report.md): `canDelegate: false` was bypassed by generic consequential dispatch. The forged delegation was `AUTHORIZED`, an operational IR was emitted, derivation matched, coverage was `FULL`, and a policy was deployable.

Repair: the Delegation predicate executes before the operational grant.

Harness stop, preserved in [q13c-run-2](q13c-runtime-authority/q13c-run-2/report.md) and explained in [q13c-run-2-oracle.md](q13c-runtime-authority/q13c-run-2-oracle.md): `AUTHORIZED` with `approval_required`, no operational IR, and no deployable policy was classified as executable authorization. The expired approval had not created executable authority. This is not a product failure.

Historical product failure 2, preserved in [q13c-run-3](q13c-runtime-authority/q13c-run-3/report.md): resource substitution was `AUTHORIZED` and deployable. The projected binding stayed on the authorized resource.

Repair: authorization-field consistency. Presented resource, actor, authority, authorization, purpose, and scope must match the grant exactly. A role label is not an authorization constraint.

Accepted result: [q13c-run-4](q13c-runtime-authority/q13c-run-4/report.md) **PASS_WITH_DOCUMENTED_LIMITATIONS**.

Limitation recorded in that run: the stale filesystem policy was detected (`read_authority_mismatch`, `path_broader_or_unaccepted`) and was not live-retracted. Filesystem enforcement on this pin is establishment-bound. An exchange against an expired policy is `DENIED` with reason `action_mismatch` because that policy produces no action grant. Direct policy evaluation still denies with `validity_expired`.

## Q13D — combinatorial qualification

Purpose: deterministic combinations of the semantic, projection, coverage, target, and temporal dimensions.

Accepted generator: `q13d-generator-4`. Accepted run: [q13d-run-4](q13d-combinatorial/q13d-run-4/report.md).

Aggregate generated exposure: **757** cases. That count is not a set of statistically independent trials and is not a probability of universal safety.

| Seed | Content | Cases |
| --- | --- | ---: |
| `q13d-seed-0001` | Pairwise combinations | 685 |
| `q13d-seed-0002` | Higher-order combinations A–L | 14 |
| `q13d-seed-0003` | Temporal sequences A–E | 17 |
| `q13d-seed-0004` | Historical regressions and the approval-withheld oracle regression | 7 |
| `q13d-seed-0005` | Positive controls and target mutations | 16 |
| `q13d-seed-0006` | Cross-surface and cross-enterprise cases | 18 |

The historical product failures are permanent regression seeds in that run: expired policy, expired delegation, ancestor IR, `/mission/*`, `canDelegate: false`, and resource substitution. Each fails closed at the repaired layer. Exact filesystem, REST, TCP, and MCP controls remain usable.

Accepted result: **PASS_WITH_DOCUMENTED_LIMITATIONS**.

`q13d-run-1`, `q13d-run-2`, and `q13d-run-3` are preserved generator or oracle stops. They are not product failures.

## Safety chain

The qualified chain is:

valid semantic authority → faithful projection → verified derivation → exact target representability → truthful coverage → non-widening target policy → stale-policy detection after authority change.

Live runtime retraction was not demonstrated.

## Invariants qualified inside that chain

These are bounded by the runs above.

- `AUTHORIZED`, `FULL`, a target policy, and `ENFORCED_ALLOW` are different facts.
- An IR is a derived projection. It is not an independent grant.
- Coverage does not create authority. `FULL` applies to a verified projection.
- A target capability does not create FIP authority.
- Substrate does not become an `fipGrant` and does not override a prohibition.
- An applicable prohibition dominates an overlapping permission.
- Foreign evidence, including a foreign Decision, Delegation, or Enforcement IR, does not become a local grant.
- A target approval or prover result does not become FIP authority.
- A stale semantic state requires fresh evaluation.
- A stale IR requires fresh derivation.
- A stale target policy is not accepted as current authority. Detection was demonstrated. Live retraction was not.

## Limitations

These limits are part of the qualification, not footnotes.

- Q13 executed no runtime operation.
- Runtime opportunities = 0.
- Runtime UOER denominator = 0.
- A stale filesystem policy was detected and was not live-retracted.
- Filesystem enforcement on pinned v0.1.2 is establishment-bound.
- A directory rule includes descendants. The static adapter does not prove that an exact path is a single file.
- The symlink target is not proved statically.
- TCP runtime is unobserved. Static compilation of an exact host and port was demonstrated.
- MCP runtime is unobserved. Static compilation of an exact method and tool was demonstrated.
- Exact executable identity is unsupported and fails closed.
- Independent credential-use authority is unsupported and fails closed.
- Exact model identity is unsupported and fails closed.
- Unsupported requirements fail closed. They are not stamped `FULL`.

## Historical failure table

Product failures:

| Phase | Run | Failure | Classification | Repair | Accepted regression | Final status |
| --- | --- | --- | --- | --- | --- | --- |
| Q13A | q13-run-1, q13-run-2 | Expired AuthorityPolicy accepted | Product | Current Validity denies non-valid policy use | q13-run-3; Q13D seed | PASS on the repaired layer |
| Q13A | q13-run-1, q13-run-2 | Expired Delegation exchange accepted | Product | Current Validity denies the exchange | q13-run-3; Q13D seed | PASS on the repaired layer |
| Q13B | q13b-run-1 | `/mission/input` consumed as `/mission` | Product | Fresh projection and derivation verification | q13b-run-3; Q13D seed | DERIVATION_REJECTED |
| Q13B | q13b-run-2 | `/mission/*` stamped FULL | Product | Exact filesystem representability | q13b-run-3; Q13D seed | COVERAGE_REJECTED, not FULL |
| Q13C | q13c-run-1 | `canDelegate: false` bypassed | Product | Delegation predicate before the operational grant | q13c-run-4; Q13D seed | DENIED |
| Q13C | q13c-run-3 | Resource substitution accepted | Product | Authorization-field identity matching | q13c-run-4; Q13D seed | DENIED, no IR |

Harness or oracle failures. These are not product failures:

| Phase | Run | Failure | Classification | Repair | Accepted regression | Final status |
| --- | --- | --- | --- | --- | --- | --- |
| Q13A | q13-run-1 | Substrate oracle text mismatch | Harness | Oracle corrected before q13-run-2 | q13-run-3 substrate case | Preserved |
| Q13C | q13c-run-2 | `approval_required` classified as executable authorization | Oracle | Executable authority requires an IR, a deployable policy, or `AUTHORIZED` without `approval_required` | q13c-run-4; Q13D approval-withheld seed | Preserved |
| Q13D | q13d-run-1 | Exact read marked a violation because coverage disposition was read from the wrong field | Oracle | Read `compilationDisposition` from the coverage result | q13d-run-4 positive filesystem control | Preserved |
| Q13D | q13d-run-2 | Resource-less Delegation treated as a missing-resource attack | Oracle | Missing resource applies only where the act requires a resource | q13d-run-4 | Preserved |
| Q13D | q13d-run-3 | Absent-approval case was given a current approval | Generator | Attach an approval only when the case asks for one | q13d-run-4 | Preserved |

## Evidence index

Runs:

- [Q13A q13-run-1](q13a-semantic-regression/q13-run-1/report.md)
- [Q13A q13-run-2](q13a-semantic-regression/q13-run-2/report.md)
- [Q13A q13-run-3](q13a-semantic-regression/q13-run-3/report.md)
- [Q13B q13b-run-1](q13b-static-enforcement/q13b-run-1/report.md)
- [Q13B q13b-run-2](q13b-static-enforcement/q13b-run-2/report.md)
- [Q13B q13b-run-3](q13b-static-enforcement/q13b-run-3/report.md)
- [Q13C q13c-run-1](q13c-runtime-authority/q13c-run-1/report.md)
- [Q13C q13c-run-2](q13c-runtime-authority/q13c-run-2/report.md)
- [Q13C q13c-run-3](q13c-runtime-authority/q13c-run-3/report.md)
- [Q13C q13c-run-4](q13c-runtime-authority/q13c-run-4/report.md)
- [Q13D q13d-run-1](q13d-combinatorial/q13d-run-1/report.md)
- [Q13D q13d-run-2](q13d-combinatorial/q13d-run-2/report.md)
- [Q13D q13d-run-3](q13d-combinatorial/q13d-run-3/report.md)
- [Q13D q13d-run-4](q13d-combinatorial/q13d-run-4/report.md)

Research notes:

- [Semantic act dispatch](../../../research/semantic-act-dispatch.md)
- [Authorization grant matching](../../../research/authorization-grant-matching.md)
- [Enforcement IR authority binding](../../../research/enforcement-ir-authority-binding.md)

Specification clarification:

- [enforcement-ir.md](../../../specification/fip-0.2/enforcement-ir.md)
- Pointing sentences in [architecture.md](../../../specification/fip-0.2/architecture.md), [adapters.md](../../../specification/fip-0.2/adapters.md), [decisions.md](../../../specification/fip-0.2/decisions.md), and [audit-and-federation.md](../../../specification/fip-0.2/audit-and-federation.md)

Regression tests:

- [test_fip02_validity.py](../../../../tests/test_fip02_validity.py)
- [test_fip02_delegation_dispatch.py](../../../../tests/test_fip02_delegation_dispatch.py)
- [test_fip02_authorization_match.py](../../../../tests/test_fip02_authorization_match.py)
- [test_fip02_derivation.py](../../../../tests/test_fip02_derivation.py)
- [test_fip02_filesystem_representability.py](../../../../tests/test_fip02_filesystem_representability.py)

Provenance:

- [FIP 0.1 manifest](../../../source-artifact-hashes.sha256) — 96 artifacts, unchanged
- [FIP 0.2 manifest](../../../fip-0.2-artifact-hashes.sha256) — 115 artifacts

Generator and campaign metadata:

- [q13d_generate.py](q13d_generate.py) — accepted generator `q13d-generator-4`
- [q13d-run-4 campaign.json](q13d-combinatorial/q13d-run-4/campaign.json)
- [q13d-run-4 hashes.json](q13d-combinatorial/q13d-run-4/hashes.json)
- [Campaign status](README.md)
