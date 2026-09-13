# Reproducibility guide

1. Create a clean Python 3.10+ environment.
2. Run `python tools/test_all.py` (Node.js 18+ is needed for JavaScript comparison).
3. Inspect `vocabulary/fip-0.1.jsonld`.
4. Run `python examples/run_examples.py`.
5. Run `python gocp/project.py`.
6. Implement the evaluator independently from the specification and run the
   unchanged vectors.
7. Report mismatches or counterexamples with all inputs and observed decisions.

Internal generative experiments require remote-model infrastructure and are not
packaged as a one-command public claim. Their summarized limitations remain part
of the evidence record.
