# Semantic Micro-Firewall reference

The deterministic evaluator in each reference adapter demonstrates the boundary:
validate a FIP exchange, distinguish semantic acts, require explicit consequential
context, reject authority-manufacturing extensions, evaluate scope and validity,
and return `PERMITTED`, `DENIED`, `INCOMPLETE`, or `ESCALATE`.

It is intentionally small research code, not a network firewall or production
policy engine. Operational effects must still be enforced by a separate gateway
that acts only on an accepted decision.

