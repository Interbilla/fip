import hashlib, importlib.util, json, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "reference/python/fip_reference/core.py"
spec = importlib.util.spec_from_file_location("fip_test", PY)
fip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fip)

class ReleaseTests(unittest.TestCase):
    def test_frozen_python_digest(self):
        self.assertEqual(hashlib.sha256(PY.read_bytes()).hexdigest(), "c8bf2a3172d2572bbcc975b1831576a4da24edea59eda8f34f8362a25f19efec")

    def test_vocabulary(self):
        vocab = json.loads((ROOT / "vocabulary/fip-0.1.jsonld").read_text())
        self.assertEqual(vocab["primitives"], fip.FOUNDATIONAL_PRIMITIVES)
        self.assertEqual(vocab["relations"], fip.RELATIONS)
        self.assertEqual((len(vocab["primitives"]), len(vocab["relations"])), (26, 24))

    def test_vector_sets(self):
        vectors = {p.name for p in (ROOT / "conformance/vectors").glob("*.json")}
        expected = {p.name for p in (ROOT / "conformance/expected-results").glob("*.json")}
        self.assertEqual(vectors, expected)
        self.assertEqual(len(vectors), 47)

    def test_schema_documents(self):
        schemas = [json.loads(path.read_text()) for path in [ROOT / "vocabulary/fip-0.1.schema.json", ROOT / "gocp/schema/profile.schema.json"]]
        for schema in schemas:
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["type"], "object")
        profile = json.loads((ROOT / "gocp/examples/synthetic-profile.json").read_text())
        self.assertTrue(set(schemas[1]["required"]).issubset(profile))
        self.assertIs(profile["immutableDuringRun"], True)
        try:
            import jsonschema
        except ModuleNotFoundError:
            return
        for schema in schemas:
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(profile, schemas[1])

    def test_python_conformance(self):
        subprocess.run([sys.executable, "conformance/runners/python_runner.py"], cwd=ROOT, check=True)

if __name__ == "__main__":
    unittest.main()
