# q13b-run-3 engineering note

Pin: NVIDIA OpenShell v0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`.
Source inspected: the pinned v0.1.2 tree at that commit. The pin was not changed.

## Filesystem path interpretation

`openshell-policy` `validate_sandbox_policy` accepts a filesystem path when it is absolute, has no `..` component, is at most 4096 bytes, and the policy has at most 256 paths. Read-write `/` is rejected. The validator does not treat `*`, `?`, or `[` as syntax.

`openshell-sandbox` `landlock.rs` opens each path with `PathFd::new`, which is `open(path, O_PATH)`. That call does not expand globs. A path whose name contains `*` is a literal pathname.

`PathBeneath` then applies to the opened inode. `access_for_path_fd` keeps directory rights only when the inode is a directory. A directory rule covers the hierarchy beneath that inode. A regular file uses file rights only. The static adapter does not open the path, so it cannot see that distinction.

`try_open_path` in `hard_requirement` fails startup when a path cannot be opened, including a missing path. It does not drop that path and continue with a wider ruleset. `best_effort` can skip a missing path. This adapter emits `hard_requirement`.

`normalize_path` in `openshell-policy-schema` is lexical and does not touch the filesystem. It collapses repeated separators, drops `.`, and drops a trailing slash. It preserves `..`. It does not resolve symlinks. `open` follows symlinks to the final inode. This static profile does not prove the symlink target.

HTTP and MCP path matching uses `tokenize_runtime_path_glob`. That tokenizer treats `*`, `**`, `?`, and `[...]` as pattern syntax. That tokenizer is not applied to filesystem policy paths.

## Profile contract used by this fix

`filesystemOperations: exact` on adapter `openshell-v0.1.2` may be FULL only for an absolute path that is not `/`, whose segments are nonempty, and whose segments are not `.`, `..`, or pattern syntax (`*`, `?`, or a `[` that would start a character class).

The profile does not rewrite `/mission/../secret` into `/secret`. It rejects that locator.

The profile does not reject an ordinary absolute path such as `/mission/input` or `/mission`. Landlock hierarchy-beneath for a directory inode remains a target limitation of the static claim: FULL means the path string is exactly the Landlock path, not that the adapter proved the inode is a single file.

A pattern locator stays AUTHORIZED at semantics. Coverage is REJECTED with `unsupported_requirement` and diagnostic `filesystem_locator_not_exact`. That diagnostic is not `subset_not_demonstrated`. Derivation still passes when the consumed IR matches the fresh projection.

## Campaign result

q13b-run-1 ancestor substitution remains a derivation mismatch.
q13b-run-2 `/mission/*` stamped FULL is now rejected by this profile check.
q13b-run-3 completed with no unauthorized deployable emission.
