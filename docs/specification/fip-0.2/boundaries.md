# Boundaries

## OpenShell is a non-normative reference target

NVIDIA OpenShell is the first reference enforcement target for later
implementation milestones. That fact is stated here so adapter authors know
which target the project intends to implement first.

The following are normative exclusions:

- OpenShell MUST NOT appear in the FIP core vocabulary.
- No primitive, relationship, binding kind, operation, protocol family,
  effect, or reason code is an OpenShell field name.
- This specification does not define OpenShell policy YAML, a sandbox
  lifecycle, a kernel mechanism, or a vendor prover.
- A Capability Manifest MAY use an `adapterId` that names that product.
  An audit correlation record MAY use the same `adapterId`. Those strings
  identify an adapter. They do not add vocabulary.
- A conforming FIP document remains meaningful if that product does not exist.

This specification does not define an OpenShell policy document. A reference
adapter may emit one for a pinned release. That file is an adapter artifact.
It is not a FIP primitive, relationship, or authoring document.

An adapter honors the subset invariant, publishes a manifest, discloses
substrate separately from grants, and refuses to treat a log-only default as
enforcement of a permit or a deny. Those duties are specified in
[adapters.md](adapters.md) without vendor fields.

## CAMEO is outside this specification

CAMEO is not part of FIP. A conforming implementation MUST accept a
hand-written AuthorityPolicy and Exchange. It MUST NOT require CAMEO, a
Mission Blueprint, or any automatic generator.

The following are outside FIP and are not specified here:

- Mission Blueprint documents
- mission reasoning and capability composition
- automatic derivation of authority
- automatic generation of policies, bindings, or requirements
- automatic security-plan generation
- proof that two different targets compiled equivalent authority
- a control loop that rewrites policy from runtime events

The audit-correlation record is inside FIP so that an external loop can
observe enforcement without being required to run. The loop itself is not
FIP.

Material produced by an external generator is ordinary FIP 0.2 if and only if
it conforms to this specification. The same schema and the same fail-closed
rules apply. The generator is not an authority source.
