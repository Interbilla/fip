# Documents and semantic acts

## AuthorityPolicy

An AuthorityPolicy is the standing authority an author maintains. A conforming
policy document MUST include:

| Field | Rule |
| --- | --- |
| `fipVersion` | The string `0.2`. |
| `document` | The string `AuthorityPolicy`. |
| `status` | The string `ENFORCEMENT CANDIDATE`. |
| `mode` | `operational` or `semantic-only`. |
| `policyId` | Unique within the author's policy set. Identifiers are unique inside the document. They are not globally registered. |

An operational policy MUST also include `traceId`, at least one Actor, one
Authority, one Authorization, the Resources and Actions those authorizations
use, the ExecutionBindings those authorizations require, the
EnforcementRequirements they reference, a Validity of `valid` for any object
the policy relies on, and Provenance with `assertedBy` and `traceId`.

A semantic-only policy MUST NOT be compiled to a deployable artifact. It MAY
omit bindings. Missing bindings in semantic-only mode are expected. They are
not execution authorization.

The policy shape is [schema/authority-policy.schema.json](schema/authority-policy.schema.json).

## Exchange

An Exchange is one proposed interaction. A conforming exchange MUST include
`fipVersion` `0.2`, `document` `Exchange`, `status` `ENFORCEMENT CANDIDATE`,
`mode`, `exchangeId`, and `exchangeType`.

An operational exchange MUST include `policyId` and `traceId`, and it is
evaluated against that AuthorityPolicy. A semantic-only exchange MAY omit
`policyId`. A lifted 0.1 exchange uses `mode` `semantic-only` and `fipCompat`
`0.1`.

Authors MUST NOT put `authorityDecision`, `compilationDisposition`,
`runtimeDisposition`, or `deployable` in an AuthorityPolicy or Exchange. Those
are outputs of an evaluator, a compiler, or a runtime. A document that
contains them is not conforming. This stops an author from stamping a file as
fully compiled.

The exchange shape is [schema/exchange.schema.json](schema/exchange.schema.json).

## Semantic acts

`exchangeType` is exactly one of:

`Assertion`, `Recommendation`, `Request`, `Response`, `Instruction`,
`Delegation`, `Authorization`, `Decision`.

Consequential acts are `Request`, `Instruction`, `Delegation`, and
`Authorization`. Only consequential acts can lead to compilation, and only
after authority and compilation succeed.

| Act | Required fields | Effect rule |
| --- | --- | --- |
| Assertion | `actor`, `resource`, `provenance` | MUST NOT acquire operational effect. |
| Recommendation | `actor`, `action` | MUST NOT create authorization or operational effect. |
| Request | `actor`, `resource`, `action`, `purpose` | No effect from well-formedness alone. |
| Response | `actor`, `respondsTo` | No independent execution grant. |
| Instruction | `actor`, `resource`, `action`, `authority`, `authorization` | Still requires a non-dominated authorization. |
| Delegation | `actor`, `delegation`, `action`, `authority` | Only an explicit bounded delegation can succeed. |
| Authorization | `actor`, `authorization`, `authority` | The act of stating a grant is not itself the grant's compilation. |
| Decision | `decision`, `provenance` | Records an outcome. An approval Decision is defined in [enforcement-requirement.md](enforcement-requirement.md). |

In operational mode, a consequential exchange that lacks provenance, authority,
or a policy authorization is `INCOMPLETE`.

## Forbidden act changes

A conforming evaluator MUST deny these silent changes from the stated act to
`attemptedEffect`:

| From | Must not silently become |
| --- | --- |
| Assertion | Instruction, Authorization, or `command` |
| Recommendation | Instruction, Authorization, or Delegation |
| Request | Permission or Authorization |
| Instruction | Delegation |

The reason code is `silent_semantic_escalation`.

## Identifiers and references

Identifiers are non-empty strings. They MUST be unique among objects of the
same class in one document. A reference across documents MUST name `policyId`
and the local identifier. FIP does not register a public identifier space.

The vocabulary namespace `urn:fip:0.2:` is release-local to this specification.
It is not a claim of a public registry.

## Bundles

A policy and an exchange are separate documents. M0 defines no multi-document
container. An implementation MUST NOT infer a missing companion document.
