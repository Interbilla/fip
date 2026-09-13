.PHONY: test conformance examples
test: conformance examples
	python -m unittest discover -s tests -v
	python tests/check_links.py
	python tools/public_release_audit.py

conformance:
	python conformance/runners/python_runner.py
	node conformance/runners/javascript-runner.js

examples:
	python examples/run_examples.py
