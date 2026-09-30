# Q13A run-3 engineering note

Baseline commit `6435895898dd089ad545941fa226eb1c0a6860a9`.

Prospective source: uncommitted post-fix working tree.

Preserved failures: [q13-run-1](../q13-run-1/report.md) and [q13-run-2](../q13-run-2/report.md). Run-2 remains 15 PASS / 2 FAIL for `expired-policy-validity` and `expired-delegation-exchange`. Those labels are unchanged.

Reason for the fix: the specification already says a non-valid Validity prevents use of the object that carries it. The reference evaluator applied that rule to Authorization validity and did not apply it to AuthorityPolicy validity or to a Delegation exchange that carries Validity.

## Specification inventory

Classifications use only existing FIP 0.2 text and schemas. No specification file was edited.

| Object | Classification | Specification basis |
| --- | --- | --- |
| AuthorityPolicy.validity | VALIDITY_NORMATIVE_FOR_USE | Schema requires `validity`. `documents.md` requires a Validity of `valid` for any object the policy relies on. `primitives.md` denies use of an object whose Validity is not `valid`. `decisions.md` requires `DENIED` when validity is not `valid`. |
| Authorization.validity | VALIDITY_NORMATIVE_FOR_USE | `authority-objects.md` denies use of the authorization that carries a non-valid state. The schema field is optional, so absence stays usable. |
| Exchange.authorization.validity | VALIDITY_NORMATIVE_FOR_USE | The exchange authorization reference carries a validity state. `authority-objects.md` denies use of that authorization when the state is not `valid`. Absence still defaults to usable. |
| Delegation exchange.validity | VALIDITY_NORMATIVE_FOR_USE | `authority-objects.md` denies use of the delegation that carries a non-valid state. The exchange schema provides `validity`. The delegation record itself does not. |
| Policy delegation record | VALIDITY_NOT_APPLICABLE | `common.schema.json` delegation properties are `delegationId`, `from`, `to`, `canDelegate`, `authorizationIds`, and `bindingIds`. No Validity field is defined. |
| Decision.validity | VALIDITY_NORMATIVE_FOR_USE | `authority-objects.md` denies use of the decision that carries a non-valid state. `enforcement-requirement.md` requires an approval Decision's Validity to be `valid`. A missing approval Validity stays `INCOMPLETE` with `approval_required`. A rejected approval value stays `INCOMPLETE`. |
| Exchange.validity on Request, Instruction, or Authorization | VALIDITY_NORMATIVE_FOR_USE | Those acts can lead to authorization. `decisions.md` requires validity to be consistent for `AUTHORIZED`, and `primitives.md` denies use of the object that carries a non-valid Validity. The field is optional. |
| Exchange.validity on Assertion, Recommendation, or Response | VALIDITY_PRESENT_BUT_NOT_AUTHORITY_GATING | The exchange schema allows the field. Those acts already cannot establish execution authority (`documents.md`). This repair does not add a new gate for them. |
| Authority | VALIDITY_NOT_APPLICABLE | The schema authority object has `id` and `kind` only. No Validity field is assigned. |
| Permission | VALIDITY_NOT_APPLICABLE | `authority-objects.md` defines Permission as the `permits` relationship from an Authorization. It has no separate Validity field. |
| Prohibition | VALIDITY_NOT_APPLICABLE | The prohibition schema has no Validity field. |
| ExecutionBinding | VALIDITY_NOT_APPLICABLE | `execution-binding.md` does not assign a Validity object to the binding. |
| EnforcementRequirement | VALIDITY_NOT_APPLICABLE | The requirement schema has no Validity field. `validity-bound` is a lifetime token. `enforcement-requirement.md` says that lifetime ends when the attached Validity is no longer `valid`; the attachment is the Validity already carried by the policy, authorization, or decision. |
| Condition type `validity-window` | VALIDITY_NORMATIVE_FOR_USE for the predicate | `authority-objects.md` says the referenced Validity state must be `valid`, and an unevaluable condition is `INCOMPLETE`. The condition schema does not contain a Validity object or a `validityId`, and the policy schema has no `validities` array. The existing unresolved reference stays `INCOMPLETE`. |

Schema states are `valid`, `expired`, `revoked`, `superseded`, and `not-yet-valid`. The non-valid codes already named in `decisions.md` are `validity_expired`, `validity_revoked`, `validity_superseded`, and `validity_not_yet_valid`. Policy denial also records the reason `policy_validity` so the code is not reported as `missing_authority`.

## Evaluator change

`reference/fip-0.2/fip02/authority.py`

- An AuthorityPolicy whose required Validity is missing is `INCOMPLETE`. A present non-valid state is `DENIED` with the existing state code and reason `policy_validity`, before grant assembly. Projection then has no operational IR, so no deployable target policy is compiled.
- A Request, Instruction, Delegation, Authorization, or Decision exchange that carries non-valid Validity is `DENIED` with the existing state code. Absent exchange Validity is unchanged.
- An approval Decision whose Validity state is non-valid is `DENIED` with that code and does not satisfy `require-approval`. A missing Decision Validity stays `INCOMPLETE`.

Prohibition dominance, missing authority, approval satisfaction, delegation `canDelegate`, composition, bindings, and enforcement requirements are unchanged.

## Test plan

Objectives: every authority-relevant Validity location either denies a non-valid state or keeps its specified absence behavior, and a non-valid AuthorityPolicy produces no deployable target policy.

System boundaries: the FIP 0.2 reference evaluator, projection, and the pinned OpenShell adapter gate. No live sandbox. No prover CLI. No Advisor CLI.

Dependencies: the existing examples, the OpenShell manifest and execution profile, and Python unittest.

Mock requirements: approval Decisions and delegation exchanges are in-memory documents. No external approval service.

Success criteria: unit tests in `tests/test_fip02_validity.py` pass; Q13A run-3 passes; Python and JavaScript conformance stay 47/47; the frozen vocabulary stays 28 primitives and 26 relationships.

Failure cases: each schema non-valid state on Authorization, AuthorityPolicy, Delegation exchange, exchange authorization reference, and approval Decision; missing policy Validity; missing approval Validity; rejected approval value; unresolved `validity-window`; inconsistent `notBefore` and `notAfter`.

Integration: an expired AuthorityPolicy is assessed, projected, and presented to the adapter. The adapter emits no `FULL` deployable policy.

Schema and data-model compatibility: no schema or specification change. Documents that already carry `valid` keep their previous decisions. Documents that carried a non-valid Validity and were previously authorized are now denied.

Workflow: assess, then project, then adapter compilation only from an operational IR. A denied policy never reaches a deployable compilation.
