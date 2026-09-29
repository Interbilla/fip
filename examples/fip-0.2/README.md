# FIP 0.2 illustrations

These files are non-normative. They are not conformance vectors, they are not
evaluated by the FIP 0.1 adapters, and they do not authorize a deployment.
The normative rules are in
[the FIP 0.2 specification](../../docs/specification/fip-0.2/README.md).

No file here is a target policy. The OpenShell filesystem slice is a FIP
document. The target adapter, not this directory, compiles it.

| Example | File | What it illustrates |
| --- | --- | --- |
| Filesystem read and write | [filesystem-read-write.json](filesystem-read-write.json) | Semantic resources bound to path locators and read/write operations. The audit duty is an obligation, not a second grant. |
| OpenShell filesystem slice | [openshell-filesystem-read-write.json](openshell-filesystem-read-write.json) | The same two paths with `establishment-bound` lifetime and `target-native` audit. This is the slice the pinned OpenShell adapter can compile. |
| REST GET | [rest-get.json](rest-get.json) | Architectural probe. One HTTP GET on one host, plus a prohibition of other service, API, and inference-provider bindings. Coverage stays `PARTIAL` because the permit asks for correlated audit, which this profile does not provide. |
| OpenShell REST qualification | [openshell-rest-get.json](openshell-rest-get.json) | Strict executable-identity probe. The permit is `allOf` of the API binding and kind `executable`. Coverage is `REJECTED` with `subset_not_demonstrated`. The adapter diagnostic is `executable_identity_not_exact`. The example is not rewritten to become deployable. |
| OpenShell target-restricted REST | [openshell-rest-target-restricted.json](openshell-rest-target-restricted.json) | API-only probe. Coverage is `FULL` and the compiler may emit a policy. `/usr/bin/curl` is read from `targetExecutableRestrictions` on the compilation profile. It is not an ExecutionBinding and not a FIP grant. |
| OpenShell REST runtime fixture | [openshell-rest-runtime.json](openshell-rest-runtime.json) | The API-only model aimed at `example.com` `GET /` so a live sandbox can reach a public HTTPS server. The host and path differ from the conformance probe. The authority model does not. |
| OpenShell TCP connect | [openshell-tcp-connect.json](openshell-tcp-connect.json) | Exact host and port, `service` plus `connect`, no HTTP method or path. Compiles to `protocol: tcp`. Runtime stays unobserved. |
| OpenShell MCP tool | [openshell-mcp-tool.json](openshell-mcp-tool.json) | Exact MCP method `tools/call` and tool `list_issues`. Network reachability is not this grant. Runtime stays unobserved. |
| OpenShell process execute | [openshell-process-execute.json](openshell-process-execute.json) | Kind `process` probe. Coverage stays rejected. Seccomp is not a substitute grant. |
| Model access | [model-inference.json](model-inference.json) | A model invocation and a provider invocation in one `allOf` group. Neither binding is a general network permit. |
| Proxy-mediated credential | [proxy-mediated-credential.json](proxy-mediated-credential.json) | Credential use with `disclosure` `proxy-mediated`, and a prohibition of every other credential binding. The document contains no secret. |
| Prohibition | [prohibition.json](prohibition.json) | A permit to read `/mission/input` and a permit to read `/mission/output` that is dominated by a deny of the same output binding. The authority evaluator must not treat the output read as authorized. |
| Human approval | [human-approval.json](human-approval.json) and [human-approval-decision.json](human-approval-decision.json) | Delete stays `require-approval` until an approver Decision exists. The Decision exchange does not itself deploy anything. Without that Decision, execution authority is absent. |
| Several bindings, one action | [multi-binding-action.json](multi-binding-action.json) | `QueryStatus` requires connect, proxy-mediated credential use, and HTTP GET together. |
| Lifted 0.1 exchange | [lifted-0.1-exchange.json](lifted-0.1-exchange.json) | Semantic-only. Empty bindings. No locator is inferred from `Org-B:Board-1`. Compilation is not authorized. |
