# Graceful degradation

Implementations should preserve unknown descriptive extensions without granting
them governance authority. Missing consequential context should produce a
deterministic `INCOMPLETE`, `DENIED`, or `ESCALATE` result rather than inferred
permission. Interoperability is tested by matching vector decisions and codes;
agreement beyond the frozen profile is not claimed.

