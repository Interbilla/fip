#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "../..");
const fip = require(path.join(root, "reference/javascript/fip-reference.js"));
const dir = path.join(root, "conformance/vectors");
const names = fs.readdirSync(dir).filter(x => x.endsWith(".json")).sort();
let passed = 0;
for (const name of names) {
  const input = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
  const expected = JSON.parse(fs.readFileSync(path.join(root, "conformance/expected-results", name), "utf8"));
  const actual = fip.evaluate(input);
  const ok = actual.decision === expected.decision && JSON.stringify(actual.codes || []) === JSON.stringify(expected.codes || []);
  if (ok) passed += 1;
  else console.error(`FAIL ${name}`);
}
console.log(`JavaScript conformance: ${passed}/${names.length}`);
process.exit(passed === 47 && names.length === 47 ? 0 : 1);

