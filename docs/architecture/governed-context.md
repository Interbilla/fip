# Governed operational context

A GOCP is a versioned allow-list of fields and mappings that may feed a FIP
interaction. Unmapped domain assertions remain descriptive or are ignored,
rejected, or quarantined. Runtime policy may permit changes to values; an agent
must not autonomously change the active schema or mapping semantics. Active
profiles are immutable during a run.

GOCP is architecture around FIP, not one of FIP's 26 primitives.

