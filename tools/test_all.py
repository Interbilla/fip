#!/usr/bin/env python3
import subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
commands = [
    [sys.executable, "conformance/runners/python_runner.py"],
    ["node", "conformance/runners/javascript-runner.js"],
    [sys.executable, "examples/run_examples.py"],
    [sys.executable, "gocp/project.py"],
    [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
    [sys.executable, "tests/check_links.py"],
    [sys.executable, "tools/public_release_audit.py"],
]
for command in commands:
    subprocess.run(command, cwd=ROOT, check=True)
print("FIP release validation suite: PASS")

