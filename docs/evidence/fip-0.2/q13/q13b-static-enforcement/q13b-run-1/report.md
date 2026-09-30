# Q13B static enforcement

Run id: `q13b-run-1`

Baseline commit: `6435895898dd089ad545941fa226eb1c0a6860a9`

OpenShell pin: v0.1.2 `6648bd0c290efbc41ba131ee9831ee45cd431f94`

Generator: `q13b-0`. Seed: `q13b-ordered-0`.

Gate: **FAIL**

Executed cases: 15. Unauthorized deployable emissions: 1.

Runtime was not started. Runtime UOER denominator is 0.

The run stopped at `filesystem-ir-ancestor-after-decision`. Later attack classes were not executed.

| Case | Class | Point | Semantic | Compilation | Deployable | Result |
| --- | --- | --- | --- | --- | --- | --- |
| filesystem-exact-read | positive-control | baseline | AUTHORIZED | FULL | True | PASS |
| rest-exact-get | positive-control | baseline | AUTHORIZED | FULL | True | PASS |
| tcp-exact-connect | positive-control | baseline | AUTHORIZED | FULL | True | PASS |
| mcp-exact-tool | positive-control | baseline | AUTHORIZED | FULL | True | PASS |
| process-exact-executable | process-executable | semantic | AUTHORIZED | REJECTED | False | PASS |
| credential-use | credential | semantic | AUTHORIZED | REJECTED | False | PASS |
| model-exact-identity | inference-model | semantic | AUTHORIZED | REJECTED | False | PASS |
| strict-executable-rest | coverage | semantic | AUTHORIZED | REJECTED | False | PASS |
| expired-policy-not-compiled | lifetime | semantic | DENIED | NOT_COMPILED | False | PASS |
| filesystem-relative-path | filesystem-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-dotdot-path | filesystem-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-read-to-delete | filesystem-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| rest-query-not-enforced | rest-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-policy-add-path | filesystem-widening | policy | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-ancestor-after-decision | semantic-to-binding | ir | AUTHORIZED | FULL | True | FAIL |

## Notes

- `filesystem-exact-read`: Exact read /mission/input compiles FULL. Substrate paths stay out of fipGrants. Caught by `adapter`.
- `rest-exact-get`: M5 target-restricted GET /weather remains FULL. Query enforcement is not claimed by this grant. Caught by `adapter`.
- `tcp-exact-connect`: Exact host and port compile. Runtime remains UNOBSERVED. Classification stays SUPPORTED_UNOBSERVED. Caught by `adapter`.
- `mcp-exact-tool`: Exact tools/call list_issues compiles. Runtime remains UNOBSERVED. Classification stays SUPPORTED_UNOBSERVED. Caught by `adapter`.
- `process-exact-executable`: Kind process stays unenforced. No descendant or generic process grant is compiled. Caught by `coverage`.
- `credential-use`: Credential use stays rejected. Provider attachment is not emitted as credential authority. Caught by `coverage`.
- `model-exact-identity`: Exact model identity stays rejected. Provider access is not emitted as model authority. Caught by `coverage`.
- `strict-executable-rest`: An executable ExecutionBinding stays non-deployable. Caught by `coverage`.
- `expired-policy-not-compiled`: A non-valid AuthorityPolicy Validity produces no deployable target policy. Caught by `semantic`.
- `filesystem-relative-path`: A relative path is not an exact filesystem grant and must not compile FULL. Caught by `adapter`.
- `filesystem-dotdot-path`: A dotdot path is not an exact filesystem grant and must not compile FULL. Caught by `adapter`.
- `filesystem-read-to-delete`: Delete is not compiled as a read or write grant. Caught by `coverage`.
- `rest-query-not-enforced`: A query-bearing URI is rejected. The compiler does not drop the query and stamp FULL. Caught by `coverage`.
- `filesystem-policy-add-path`: Adding /mission/sibling after compile must fail verify_policy. Reasons: read_authority_mismatch,path_broader_or_unaccepted,path_broader_or_unaccepted Caught by `verifier`.
- `filesystem-ir-ancestor-after-decision`: The evaluated grant is read /mission/input. The IR locator was changed to /mission before coverage and compilation. Excess paths: read:/mission. Caught by `none`.
