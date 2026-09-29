# ExecutionBinding

ExecutionBinding is the primitive that connects a semantic Resource or Action
to a concrete runtime entity. The semantic Resource and Action stay free of
locators and execution verbs.

A binding MUST include `bindingId`, `kind`, `operation`, and `lifetime`. It
SHOULD include `resourceId` when it binds a resource. A binding that names an
action includes `actionId`.

## Cardinality

`hasExecutionBinding` is one-to-many. One semantic resource MAY have several
bindings. One action MAY depend on several bindings. One binding MAY be reused
by several requirements.

Default composition of the requirements that cite those bindings is `allOf`,
defined in [enforcement-requirement.md](enforcement-requirement.md). Authorizing
an action does not authorize a proper subset of an `allOf` group.

## Kinds

`kind` is exactly one of:

`filesystem`, `service`, `api`, `process`, `executable`, `model`,
`inference-provider`, `credential`, `device`, `message-channel`, `datastore`,
`custom`.

| Kind | What it binds | What it does not bind |
| --- | --- | --- |
| `filesystem` | A path and `read` or `write` | A network destination |
| `service` | A host, port, or service id, usually `connect` | An application method or tool |
| `api` | An application operation at a locator | Bare connectivity, unless a separate `service` binding says so |
| `process` | Running or creating a process | A syscall list |
| `executable` | An executable identity allowed to perform an operation | Every binary on the host |
| `model` | A model identifier and `invoke` | Arbitrary reachability to a provider network |
| `inference-provider` | The provider that serves a model | A general permit for that provider's other APIs |
| `credential` | The right to use a named credential | Possession of the secret |
| `device` | A device identifier and `command` | A network request used as a stand-in for the device |
| `message-channel` | A channel id with `publish` or `subscribe` | Unrelated channels |
| `datastore` | A store locator with `query` or `modify` | An unstated query dialect |
| `custom` | Reserved. Not usable in a conforming M0 document | — |

A kind token MUST NOT be a vendor product name.

## Locator types

A locator is a set of typed fields. At least one MUST be present. Legal fields
are `path`, `host`, `port`, `uri`, `serviceId`, `executableId`, `modelId`,
`deviceId`, and `channelId`.

These fields MUST NOT appear on Resource or Action. `port` is an integer from
1 through 65535. A path is a runtime path string. Scope values are not paths.

`spatial`, `temporal`, and `jurisdictional` scope remain authority bounds.
They are not locators. A conforming implementation MUST NOT copy a spatial
scope value into a filesystem path.

## Operations

`operation` is exactly one of:

`read`, `write`, `execute`, `connect`, `invoke`, `create`, `modify`, `delete`,
`publish`, `subscribe`, `query`, `command`, `custom`.

`custom` is reserved and is not conforming in M0, for the same reason as a
custom kind.

An Action name such as `ReadInspectionInput` is not an operation. The
operation is the binding's `read`.

## Protocol profiles

A protocol block is present only when the kind needs application detail. The
normative families are `http`, `mcp`, `graphql`, `websocket`, `json-rpc`, and
reserved `custom`.

| Family | Parameters a document MAY set | Enforcement note |
| --- | --- | --- |
| `http` | `transport`, `method`, `path` | A connect binding does not satisfy a method or path constraint. |
| `mcp` | `method`, `tool` | A host and port do not satisfy a tool constraint. Argument limits are Constraints. A target that cannot enforce an argument MUST NOT mark that constraint enforced. |
| `graphql` | `operationType`, `operationName`, `fields` | Operation type is `query`, `mutation`, `subscription`, or `*`. |
| `websocket` | `method`, `path` | Method is `GET` for the handshake or `WEBSOCKET_TEXT` for a client text message. |
| `json-rpc` | `method` | The method is an exact string, or `*` for every method. |
| `custom` | Reserved | Not conforming in M0. |

Path patterns in `http.path` are minimal. An exact string matches one path.
`*` matches a single path segment. `**` matches any remainder. No other pattern
language is defined. A target whose pattern language cannot express the FIP
pattern without widening it MUST reject the requirement.

This profile set is generic. It is not a copy of any vendor policy schema.
Fields that exist only in a vendor document MUST NOT be added here. They MAY
appear later as opaque adapter annotations on an Enforcement IR, where core
evaluation MUST ignore them.

## Credential disclosure

A binding of kind `credential` MUST set `disclosure` to one of:

| Value | Meaning |
| --- | --- |
| `none` | The actor is not authorized to use the credential. |
| `proxy-mediated` | A mediating enforcement point may apply the credential. The execution environment MUST NOT receive the secret. |
| `process-visible` | The process may receive secret material. This MUST be explicit. It is not the default. |

No other binding is required to set `disclosure`. Absence of `disclosure` on a
non-credential binding means the binding carries no secret. A document MUST
NOT include a property whose value is secret material.

Disclosure is independent of binding precision. A target that can apply a
secret through a mediator still has to constrain the binding's provider,
host, port, path, or protocol to the dimensions that mediator actually
checks. Coverage rules for that split are in
[adapters.md](adapters.md).

## One resource, several runtime entities

The author states each runtime entity as its own binding and points the action
at all of them through requirements. For a semantic database resource the
bindings MAY be a network `connect`, a `credential` use, an `api` or
`datastore` query, and a filesystem `read` of a certificate. None of those
locators are stored on the Resource.

## One action, several controls

The action stays semantic. Each control is an EnforcementRequirement that
lists the binding identifiers it governs. A compiler MUST treat an `allOf`
group as a unit, as specified for composition.
