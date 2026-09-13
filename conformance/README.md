# Conformance

The 47 input vectors and expected results are byte-identical copies of the frozen
external release. A reference conforms to this candidate profile when every
decision and ordered code list matches.

```bash
python conformance/runners/python_runner.py
node conformance/runners/javascript-runner.js
```

This is engineering conformance to a Reference Candidate, not certification.

