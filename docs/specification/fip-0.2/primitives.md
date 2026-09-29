# Primitives

FIP 0.2 defines exactly 28 primitives. The first 26 keep the FIP 0.1 names and
order. ExecutionBinding and EnforcementRequirement are new. No other name is a
primitive. In particular, no filesystem, network, process, protocol, vendor, or
product name is a primitive.

The normative enumeration is
[vocabulary/fip-0.2.jsonld](vocabulary/fip-0.2.jsonld).

| Primitive | Normative role |
| --- | --- |
| Actor | The subject that proposes or performs a semantic act. |
| Resource | A semantic object. It MUST NOT carry a path, host, port, URI, model id, device id, or other runtime locator. |
| Role | A descriptive claim on an Actor. A role MUST NOT by itself authorize an operation. |
| Identity | The identifier by which an Actor is distinguished. FIP does not operate an identity provider. |
| Credential | A semantic resource naming a credential the actor may be authorized to use. The document MUST NOT contain secret bytes, passwords, or bearer tokens. |
| Request | A semantic act that proposes an action. It does not itself authorize execution. |
| Response | A semantic act that answers a prior exchange. |
| Action | A semantic verb. Concrete operations MUST be stated on an ExecutionBinding or EnforcementRequirement, not on the Action. |
| Assertion | An informational act. It MUST NOT acquire operational effect. |
| Recommendation | An advisory act. It MUST NOT create authorization or operational effect. |
| Instruction | A consequential act. Effect still requires authority, authorization, and, in operational mode, successful compilation. |
| Delegation | An explicit, bounded transfer of authority. Implicit delegation is not a Delegation. |
| Decision | A recorded outcome. Its `kind` distinguishes authority, approval, and review. A Decision is not by itself a deployable allow. |
| Purpose | Why an act is proposed. Purpose mismatch denies authority. Purpose MUST NOT select a locator. |
| Condition | An executable predicate that gates a requirement. An unevaluable condition yields `INCOMPLETE`. |
| Constraint | An executable limit attached to a requirement or authorization. An unknown constraint type fails closed. |
| Authority | The source under which an actor acts. The `kind` token is open and descriptive. No kind token names a runtime product, and none creates execution rights by itself. |
| Authorization | The grant that ties an actor, actions, resources, purpose, authority, and requirements together. |
| Permission | The normative mode that an authorization permits the named actions. In operational mode it MUST reference enforcement requirements. |
| Prohibition | The normative mode that forbids named actions or bindings. An applicable prohibition dominates an overlapping permission. |
| Obligation | A required duty, such as audit. An obligation does not grant execution authority. |
| Policy | The identity and normative content of an AuthorityPolicy. An identifier alone is not an operational policy. |
| Evidence | Material offered in support of a claim. Evidence does not satisfy provenance, and it does not satisfy a requirement. |
| Provenance | Origin and derivation of a document or decision. It does not create authority. |
| Validity | One of `valid`, `expired`, `revoked`, `superseded`, `not-yet-valid`. Any state other than `valid` denies use of the object that carries it. |
| Scope | A spatial, temporal, or jurisdictional bound on authority. It is not a runtime locator. |
| ExecutionBinding | The mapping from a semantic resource or action to a runtime kind, locator, and operation. |
| EnforcementRequirement | A required security effect over one or more bindings. |

Resource and Action remain semantic in every conforming document. Locators and
operations that name runtime behavior belong to ExecutionBinding and
EnforcementRequirement.
