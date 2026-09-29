import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from canonical_hash import sha256_canonical_text  # noqa: E402

class JavaScriptProvenanceTest(unittest.TestCase):
    def test_frozen_javascript_digest(self):
        actual = sha256_canonical_text(ROOT / "reference/javascript/fip-reference.js")
        self.assertEqual(actual, "7fc43338f5d586dad29c97635ac58a043922b674d76bf28efd0f42d15eb95947")

