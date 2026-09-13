/**
 * Foundational UDG RC 0.1 standalone JavaScript reference adapter.
 * Serialized-boundary only. No BILLA, CAMEO, Explorer, or Interbilla imports.
 * REFERENCE CANDIDATE. NOT A PUBLISHED STANDARD.
 */
"use strict";

const VERSION = "0.1";
const STATUS = "REFERENCE CANDIDATE";
const PUBLICATION = "NOT A PUBLISHED STANDARD";
const CANONICAL = "NOT CANONICAL EXTERNAL VOCABULARY";

const SEMANTIC_ACTS = [
  "Assertion", "Recommendation", "Request", "Response",
  "Instruction", "Delegation", "Authorization", "Decision",
];
const CONSEQUENTIAL_ACTS = ["Request", "Instruction", "Delegation", "Authorization"];
const VALIDITY_STATES = ["valid", "expired", "revoked", "superseded", "not-yet-valid"];
const SCOPE_DIMENSIONS = ["spatial", "temporal", "jurisdictional"];
const FIREWALL_DECISIONS = ["PERMITTED", "DENIED", "INCOMPLETE", "ESCALATE"];
const PROTECTED_GOVERNANCE = [
  "authority", "authorization", "permission", "prohibition", "obligation",
  "delegation", "provenance", "policy", "validity",
];
const FORBIDDEN_ESCALATIONS = new Set([
  "Assertion|Instruction", "Assertion|Authorization", "Assertion|command",
  "Recommendation|Instruction", "Recommendation|Authorization", "Recommendation|Delegation",
  "Request|Permission", "Request|Authorization", "Instruction|Delegation",
]);
const REQUIRED_BY_ACT = {
  Assertion: ["actor", "resource", "provenance"],
  Recommendation: ["actor", "action"],
  Request: ["actor", "resource", "action", "purpose"],
  Response: ["actor", "respondsTo"],
  Instruction: ["actor", "resource", "action", "authority", "authorization"],
  Delegation: ["actor", "delegation", "action", "authority"],
  Authorization: ["actor", "authorization", "authority"],
  Decision: ["decision", "provenance"],
};
const DEFINITION = "A semantic micro-firewall constrains which semantic assertions are allowed to cross a trust boundary and acquire operational effect.";
const NOT_CLAIM = "This evaluator does not claim that a semantic micro-firewall prevents all prompt injection.";

function present(value) {
  return !(value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0) || (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0));
}

function validityOf(exchange) {
  const auth = exchange.authorization || {};
  const validity = exchange.validity || {};
  return auth.validity || validity.state || null;
}

function normative(exchange) {
  return String((exchange.normative || {}).state || "unknown");
}

function meta() {
  return {
    status: STATUS,
    publication: PUBLICATION,
    canonical: CANONICAL,
    version: VERSION,
    published_objects: 0,
    canonical_swids: 0,
    new_foundational_primitives: 0,
    new_foundational_relations: 0,
  };
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((acc, key) => {
      acc[key] = sortKeys(value[key]);
      return acc;
    }, {});
  }
  return value;
}

function parse(text) {
  const payload = JSON.parse(text);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("exchange_must_be_object");
  }
  return payload;
}

function normalize(exchange) {
  return {
    status: STATUS,
    publication: PUBLICATION,
    canonical: CANONICAL,
    ...JSON.parse(JSON.stringify(exchange)),
  };
}

function serialize(exchange) {
  return JSON.stringify(sortKeys(normalize(exchange)));
}

function preserveExtensions(exchange) {
  return JSON.parse(JSON.stringify(exchange.extensions || []));
}

function validate(exchange) {
  const errors = [];
  const warnings = [];
  const act = String(exchange.exchangeType || "");
  if (!SEMANTIC_ACTS.includes(act)) {
    errors.push(`unknown_exchange_type:${act || "missing"}`);
    return validationResult(false, errors, warnings, act, exchange);
  }
  for (const field of REQUIRED_BY_ACT[act] || []) {
    if (field === "delegation" && !present(exchange.delegation)) errors.push("missing:delegation");
    else if (field === "respondsTo" && !present(exchange.respondsTo)) errors.push("missing:respondsTo");
    else if (field === "decision") {
      const decision = exchange.decision;
      const value = decision && typeof decision === "object" ? decision.value : decision;
      if (!present(value)) errors.push("missing:decision");
    } else if (!["delegation", "respondsTo", "decision"].includes(field) && !present(exchange[field])) {
      errors.push(`missing:${field}`);
    }
  }
  const attempted = exchange.attemptedEffect;
  if (attempted && FORBIDDEN_ESCALATIONS.has(`${act}|${attempted}`)) {
    errors.push(`silent_type_change:${act}->${attempted}`);
  }
  for (const scope of exchange.scope || []) {
    const dim = (scope || {}).dimension;
    if (dim && !SCOPE_DIMENSIONS.includes(dim)) errors.push(`unknown_scope_dimension:${dim}`);
  }
  const validity = validityOf(exchange);
  if (validity && !VALIDITY_STATES.includes(validity)) errors.push(`unknown_validity:${validity}`);
  for (const ext of exchange.extensions || []) {
    const claims = ext.claims || {};
    for (const key of PROTECTED_GOVERNANCE) {
      if (claims[key] || ext[`override_${key}`]) errors.push(`extension_overrides_${key}`);
    }
    if (ext.eraseProvenance || claims.erase_provenance) errors.push("extension_suppresses_provenance");
  }
  if (CONSEQUENTIAL_ACTS.includes(act) && !present(exchange.provenance)) {
    warnings.push("consequential_exchange_missing_provenance");
  }
  return validationResult(!errors.length, errors, warnings, act, exchange);
}

function evaluate(exchange) {
  const validation = validate(exchange);
  const act = String(exchange.exchangeType || "");
  const attempted = exchange.attemptedEffect;
  const untrusted = [];
  let missing = [];
  const evaluated = {
    identity: present((exchange.actor || {}).id || exchange.actor),
    role: present((exchange.actor || {}).role),
    act,
    resource: present(exchange.resource),
    action: present(exchange.action),
    purpose: present(exchange.purpose),
    authority: present(exchange.authority),
    authorization: present(exchange.authorization),
    credential: present(exchange.credential),
    policy: present(exchange.policy),
    scope: Boolean(exchange.scope && exchange.scope.length),
    validity: validityOf(exchange),
    delegation: present(exchange.delegation),
    provenance: present(exchange.provenance),
    evidence: present(exchange.evidence),
    normative: normative(exchange),
  };

  if (exchange.untrustedFreeText && !evaluated.authority) {
    return decision("DENIED", exchange, validation, evaluated, ["Untrusted natural language does not create authority."], ["free_text_cannot_manufacture_authority"], [], []);
  }
  if (exchange.authoritySource === "free_text") {
    return decision("DENIED", exchange, validation, evaluated, ["Natural-language interpretation alone does not create operational authority."], ["authority_source_free_text"], [], []);
  }
  if (exchange.channel === "agent-to-memory" && (attempted === "manufacture_authority" || attempted === "authorization")) {
    return decision("DENIED", exchange, validation, evaluated, ["An agent cannot manufacture authority by writing to shared memory."], ["memory_cannot_manufacture_authority"], [], []);
  }
  if (attempted && FORBIDDEN_ESCALATIONS.has(`${act}|${attempted}`)) {
    return decision("DENIED", exchange, validation, evaluated, [`${act} must not silently become ${attempted}.`], ["silent_semantic_escalation"], [], []);
  }

  for (const ext of exchange.extensions || []) {
    const claims = ext.claims || {};
    const ns = ext.namespace || "unknown";
    if (ext.recognized === false) untrusted.push(ns);
    if (claims.authority || claims.permission || claims.delegation) {
      return decision("DENIED", exchange, validation, evaluated, ["Unknown or hostile extension cannot manufacture authority, permission, or delegation."], ["extension_cannot_grant_authority"], [], untrusted);
    }
    if (claims.override_policy || ext.override_policy) {
      return decision("DENIED", exchange, validation, evaluated, ["Extension cannot override foundational policy."], ["extension_cannot_override_policy"], [], untrusted);
    }
    if (ext.eraseProvenance || claims.erase_provenance) {
      return decision("DENIED", exchange, validation, evaluated, ["Extension cannot suppress foundational provenance."], ["extension_cannot_erase_provenance"], [], untrusted);
    }
  }

  const validity = validityOf(exchange);
  if (["expired", "revoked", "superseded"].includes(validity)) {
    return decision("DENIED", exchange, validation, evaluated, [`Authorization/authority is ${validity}.`], [`validity_${validity}`], [], untrusted);
  }
  if (validity === "not-yet-valid") {
    return decision("DENIED", exchange, validation, evaluated, ["Authorization is not yet valid."], ["validity_not_yet_valid"], [], untrusted);
  }
  if (normative(exchange) === "prohibited") {
    return decision("DENIED", exchange, validation, evaluated, ["Explicit prohibition applies. Absence of permission is not required for this deny."], ["explicit_prohibition"], [], untrusted);
  }

  const expectedScope = exchange.expectedScope || [];
  if (expectedScope.length && exchange.scope) {
    const got = new Set((exchange.scope || []).map((row) => `${row.dimension}|${row.value}`));
    const need = expectedScope.map((row) => `${row.dimension}|${row.value}`);
    if (!need.every((item) => got.has(item))) {
      return decision("DENIED", exchange, validation, evaluated, ["Scope does not match the authorized spatial/temporal bound."], ["scope_mismatch"], [], untrusted);
    }
  }
  if (exchange.expectedPurpose && exchange.purpose && exchange.purpose !== exchange.expectedPurpose) {
    return decision("DENIED", exchange, validation, evaluated, ["Purpose does not match the authorized purpose."], ["purpose_mismatch"], [], untrusted);
  }
  if (exchange.expectedActor && (exchange.actor || {}).id && (exchange.actor || {}).id !== exchange.expectedActor) {
    return decision("DENIED", exchange, validation, evaluated, ["Identity does not match the authorized actor."], ["identity_mismatch"], [], untrusted);
  }
  if (exchange.staleReplay) {
    return decision("DENIED", exchange, validation, evaluated, ["Stale exchange replay is not accepted."], ["stale_replay"], [], untrusted);
  }
  if (exchange.tamperedAfterBinding) {
    return decision("DENIED", exchange, validation, evaluated, ["Extension or payload changed after provenance binding."], ["tampered_after_binding"], [], untrusted);
  }
  if (exchange.conflictingPolicy) {
    return decision("ESCALATE", exchange, validation, evaluated, ["Applicable policies conflict; human or higher-assurance review is required."], ["conflicting_policy"], [], untrusted);
  }
  if (exchange.correlatedPrivilegeChain || ((exchange.history || {}).privilegeEscalationPath)) {
    return decision("ESCALATE", exchange, validation, evaluated, ["Cross-boundary correlated privilege chain requires review. No new Foundational primitive is required."], ["correlated_privilege_chain"], [], untrusted);
  }

  const instruction = exchange.instruction || {};
  const trusted = exchange.trustedEvidence || {};
  if (exchange.evidenceMismatch || (instruction.requested_command && trusted.observed_command && instruction.requested_command !== trusted.observed_command)) {
    return decision("ESCALATE", exchange, validation, evaluated, ["Trusted evidence contradicts asserted or requested action. Agent self-report is not ground truth."], ["EVIDENCE_MISMATCH", "PROVENANCE_MISMATCH"], [], untrusted);
  }
  if (exchange.evidenceSource === "agent_self_report" && CONSEQUENTIAL_ACTS.includes(act)) {
    return decision("ESCALATE", exchange, validation, evaluated, ["Agent-declared assertion is not independently provenanced evidence."], ["assertion_is_not_trusted_evidence"], [], untrusted);
  }
  if (exchange.purpose === "cross-agent-communication" || exchange.purpose === "establish-cross-agent-channel") {
    if (!(exchange.authorization || {}).permitsCommunication) {
      return decision("DENIED", exchange, validation, evaluated, ["Valid package-access credential is not authorization to establish cross-agent communication."], ["package_access_is_not_communication_authorization"], [], untrusted);
    }
  }
  if (exchange.emergentCoordination || exchange.emergentDelegation) {
    if (!(exchange.delegation || {}).authorizedChain) {
      return decision("DENIED", exchange, validation, evaluated, ["Emergent coordination is not enterprise delegation."], ["coordination_is_not_enterprise_delegation"], [], untrusted);
    }
  }
  if (evaluated.credential && !evaluated.authorization && (CONSEQUENTIAL_ACTS.includes(act) || present(exchange.action))) {
    return decision("DENIED", exchange, validation, evaluated, ["A technically valid credential is not authorization."], ["credential_is_not_authorization"], [], untrusted);
  }

  if (act === "Delegation") {
    const delegation = exchange.delegation || {};
    if (!delegation.canDelegate && (exchange.authority || {}).kind !== "delegable") {
      return decision("DENIED", exchange, validation, evaluated, ["Delegation requires explicit authority to delegate."], ["delegation_requires_explicit_authority"], [], untrusted);
    }
    if (delegation.canDelegate === false) {
      return decision("DENIED", exchange, validation, evaluated, ["Delegation requires explicit authority to delegate."], ["delegation_requires_explicit_authority"], [], untrusted);
    }
  }

  if (CONSEQUENTIAL_ACTS.includes(act)) {
    for (const field of REQUIRED_BY_ACT[act] || []) {
      if (field === "delegation" && !present(exchange.delegation)) missing.push("delegation");
      else if (!["delegation", "respondsTo", "decision"].includes(field) && !present(exchange[field])) missing.push(field);
    }
    if (["Request", "Instruction", "Delegation", "Authorization"].includes(act) && !evaluated.authority) missing.push("authority");
    if (!evaluated.provenance) missing.push("provenance");
    missing = [...new Set(missing)];
    if (missing.length) {
      return decision("INCOMPLETE", exchange, validation, evaluated, [`Missing structured fields: ${missing.join(", ")}.`], ["incomplete_structured_fields"], missing, untrusted);
    }
    if (evaluated.authority && !evaluated.policy) {
      return decision("ESCALATE", exchange, validation, evaluated, ["Authority is present but policy is not independently established."], ["authority_without_policy"], [], untrusted);
    }
    if (act === "Request" && normative(exchange) === "unknown" && !(exchange.authorization || {}).id) {
      return decision("ESCALATE", exchange, validation, evaluated, ["Permission is not established. Absence of prohibition is not permission."], ["permission_not_established"], [], untrusted);
    }
  }

  if (act === "Recommendation") {
    return decision("DENIED", exchange, validation, evaluated, ["A recommendation may be recorded but does not acquire operational effect."], ["recommendation_has_no_operational_effect"], [], untrusted);
  }
  if (act === "Assertion") {
    return decision("DENIED", exchange, validation, evaluated, ["An informational assertion is not an operational instruction."], ["assertion_is_not_command"], [], untrusted);
  }
  if (untrusted.length && CONSEQUENTIAL_ACTS.includes(act) && exchange.foundationalTrusted === false) {
    return decision("ESCALATE", exchange, validation, evaluated, ["Extension namespace is unrecognized; foundational layer is not independently trusted."], ["unknown_publisher"], [], untrusted);
  }
  if (evaluated.authority && evaluated.policy && evaluated.provenance && (validity === null || validity === "valid")) {
    return decision("PERMITTED", exchange, validation, evaluated, ["Structured identity, authority, policy, validity, and provenance are consistent."], ["structured_governance_present"], [], untrusted);
  }
  return decision("ESCALATE", exchange, validation, evaluated, ["Structured fields are present but the boundary remains uncertain."], ["uncertain_boundary"], [], untrusted);
}

function validationResult(ok, errors, warnings, act, exchange) {
  return { valid: ok, exchangeId: exchange.exchangeId, exchangeType: act, errors, warnings, ...meta() };
}

function decision(result, exchange, validation, evaluated, reasons, codes, missing, untrusted) {
  if (!FIREWALL_DECISIONS.includes(result)) throw new Error(result);
  const authority = exchange.authority || {};
  const delegation = exchange.delegation || {};
  return {
    decision: result,
    reasons,
    codes,
    evaluated,
    applicablePolicy: (exchange.policy || {}).id,
    authorityChain: [authority.id, delegation.from, delegation.to].filter(Boolean),
    missingSemantics: missing,
    untrustedExtensions: untrusted,
    provenance: exchange.provenance,
    traceId: (exchange.provenance || {}).traceId || exchange.exchangeId,
    exchangeId: exchange.exchangeId,
    exchangeType: exchange.exchangeType,
    validation,
    llmRequired: false,
    definition: DEFINITION,
    notClaim: NOT_CLAIM,
    ...meta(),
  };
}

function evaluateJson(text) {
  return evaluate(parse(text));
}

function roundTrip(text) {
  const first = parse(text);
  const serialized = serialize(first);
  const second = parse(serialized);
  const mutated = serialize(second) !== serialized;
  return { ok: !mutated, serialized, semantic_mutation: mutated, ...meta() };
}

module.exports = {
  VERSION, STATUS, PUBLICATION, CANONICAL, SEMANTIC_ACTS, CONSEQUENTIAL_ACTS,
  parse, serialize, normalize, validate, evaluate, evaluateJson, preserveExtensions, roundTrip,
};
