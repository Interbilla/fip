# Q13B static enforcement

Run id: `q13b-run-3`

Baseline commit: `6435895898dd089ad545941fa226eb1c0a6860a9`

OpenShell pin: v0.1.2 `6648bd0c290efbc41ba131ee9831ee45cd431f94`

Generator: `q13b-2`. Seed: `q13b-ordered-0`.

Gate: **PASS**

Executed cases: 43. Unauthorized deployable emissions: 0.

Runtime was not started. Runtime UOER denominator is 0.

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
| filesystem-ir-ancestor-after-decision | semantic-to-binding | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-operation-write | semantic-to-binding | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-requirement-deleted | semantic-to-binding | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-allof-to-anyof | composition | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-lifetime-revocable | lifetime | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-resource-substituted | semantic-to-binding | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-action-substituted | semantic-to-binding | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-ir-substrate-in-grants | substrate-laundering | ir | AUTHORIZED | REJECTED | False | PASS |
| rest-ir-host-widened | rest-widening | ir | AUTHORIZED | REJECTED | False | PASS |
| tcp-ir-port-widened | tcp-widening | ir | AUTHORIZED | REJECTED | False | PASS |
| mcp-ir-tool-widened | mcp | ir | AUTHORIZED | REJECTED | False | PASS |
| filesystem-glob-path | representability | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-question-path | representability | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-bracket-path | representability | semantic | AUTHORIZED | REJECTED | False | PASS |
| filesystem-range-path | representability | semantic | AUTHORIZED | REJECTED | False | PASS |
| rest-method-star | rest-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| tcp-any-host | tcp-widening | semantic | AUTHORIZED | REJECTED | False | PASS |
| prohibition-dropped-from-ir | prohibition | ir | AUTHORIZED | REJECTED | False | PASS |
| approval-without-decision | approval | semantic | AUTHORIZED | NOT_COMPILED | False | PASS |
| approval-supplied-ir-without-projection | approval | ir | REVIEW | REJECTED | False | PASS |
| lifetime-not-yet-valid | lifetime | semantic | DENIED | NOT_COMPILED | False | PASS |
| coverage-stamped-full-credential | coverage | coverage | AUTHORIZED | REJECTED | False | PASS |
| capability-manifest-identity-swap | capability-manifest | manifest | AUTHORIZED | REJECTED | False | PASS |
| substrate-not-in-fip-grants | substrate-laundering | baseline | AUTHORIZED | FULL | True | PASS |
| rest-policy-host-widened | target-policy-mutation | policy | AUTHORIZED | REJECTED | False | PASS |
| rest-policy-downgraded-to-tcp | cross-surface | policy | AUTHORIZED | REJECTED | False | PASS |
| tcp-policy-port-widened | target-policy-mutation | policy | AUTHORIZED | REJECTED | False | PASS |
| mcp-policy-tool-widened | target-policy-mutation | policy | AUTHORIZED | REJECTED | False | PASS |
| mcp-policy-downgraded-to-tcp | cross-surface | policy | AUTHORIZED | REJECTED | False | PASS |

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
- `filesystem-relative-path`: A relative path is not an exact filesystem grant and must not compile FULL. Caught by `representability`.
- `filesystem-dotdot-path`: A dotdot path is not an exact filesystem grant and must not compile FULL. Caught by `representability`.
- `filesystem-read-to-delete`: Delete is not compiled as a read or write grant. Caught by `coverage`.
- `rest-query-not-enforced`: A query-bearing URI is rejected. The compiler does not drop the query and stamp FULL. Caught by `coverage`.
- `filesystem-policy-add-path`: Adding /mission/sibling after compile must fail verify_policy. Reasons: read_authority_mismatch,path_broader_or_unaccepted,path_broader_or_unaccepted Caught by `verifier`.
- `filesystem-ir-ancestor-after-decision`: The evaluated grant is read /mission/input. The IR locator was changed to /mission before coverage and compilation. Excess paths: none. Caught by `derivation`.
- `filesystem-ir-operation-write`: Consumed read binding operation changed to write. Caught by `derivation`.
- `filesystem-ir-requirement-deleted`: One consumed requirement was deleted after projection. Caught by `derivation`.
- `filesystem-ir-allof-to-anyof`: Consumed composition changed from allOf to anyOf. Caught by `derivation`.
- `filesystem-ir-lifetime-revocable`: Consumed lifetime changed from establishment-bound to revocable. Caught by `derivation`.
- `filesystem-ir-resource-substituted`: Consumed binding resourceId was substituted. Caught by `derivation`.
- `filesystem-ir-action-substituted`: Consumed binding actionId was substituted. Caught by `derivation`.
- `filesystem-ir-substrate-in-grants`: A substrate path was inserted into coverage.fipGrants. Caught by `derivation`.
- `rest-ir-host-widened`: Consumed REST host changed after projection. Caught by `derivation`.
- `tcp-ir-port-widened`: Consumed TCP port changed after projection. Caught by `derivation`.
- `mcp-ir-tool-widened`: Consumed MCP tool name changed after projection. Caught by `derivation`.
- `filesystem-glob-path`: A star locator is pattern syntax and is not an exact filesystem grant. Caught by `representability`.
- `filesystem-question-path`: A question-mark locator is pattern syntax and is not an exact filesystem grant. Caught by `representability`.
- `filesystem-bracket-path`: A bracket locator is pattern syntax and is not an exact filesystem grant. Caught by `representability`.
- `filesystem-range-path`: A character-range locator is pattern syntax and is not an exact filesystem grant. Caught by `representability`.
- `rest-method-star`: A wildcard HTTP method is not compiled FULL. Caught by `coverage`.
- `tcp-any-host`: A wildcard TCP host is not compiled FULL. Caught by `coverage`.
- `prohibition-dropped-from-ir`: A consumed prohibition was removed after projection. Caught by `derivation`.
- `approval-without-decision`: Require-approval without a completed approval has no operational IR. Caught by `projection`.
- `approval-supplied-ir-without-projection`: A supplied IR cannot revive a decision that currently has no operational projection. Caught by `derivation`.
- `lifetime-not-yet-valid`: A not-yet-valid AuthorityPolicy produces no deployable policy. Caught by `semantic`.
- `coverage-stamped-full-credential`: Stamping FULL on a credential assessment does not emit a deployable policy. Caught by `adapter`.
- `capability-manifest-identity-swap`: A substituted capability manifest does not make the REST grant deployable. Caught by `adapter`.
- `substrate-not-in-fip-grants`: Accepted substrate paths are absent from fipGrants:  Caught by `coverage`.
- `rest-policy-host-widened`: REST host changed after compilation. Reasons: host_widened Caught by `verifier`.
- `rest-policy-downgraded-to-tcp`: A REST rule was rewritten as unrestricted TCP. Reasons: protocol_downgraded Caught by `verifier`.
- `tcp-policy-port-widened`: TCP port changed after compilation. Reasons: port_widened Caught by `verifier`.
- `mcp-policy-tool-widened`: MCP tool changed after compilation. Reasons: tool_widened Caught by `verifier`.
- `mcp-policy-downgraded-to-tcp`: An MCP rule was rewritten as unrestricted TCP. Reasons: protocol_not_mcp Caught by `verifier`.
