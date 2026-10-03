// Independent check of Kavach's canonical JSON (RFC 8785, JCS): every case
// in the vector file must canonicalise, with the canonicalize package (the
// reference implementation by an RFC 8785 author), to exactly the bytes
// Kavach's own test expects (crates/kavach-ports/tests/jcs_vectors.rs).
// Refused cases (numbers that are not safe integers) are Kavach's own rule,
// not JCS's, so they are not checked here.
import { readFileSync } from 'node:fs';
import canonicalize from 'canonicalize';

const doc = JSON.parse(readFileSync(process.argv[2], 'utf8'));
let failed = doc.cases.length === 0 ? 1 : 0;
for (const c of doc.cases) {
  const got = canonicalize(JSON.parse(c.input));
  if (got === c.canonical) {
    console.log(`ok   ${c.name}`);
  } else {
    console.log(`FAIL ${c.name}\n  canonicalize: ${got}\n  vector:       ${c.canonical}`);
    failed += 1;
  }
}
console.log(`${doc.cases.length - failed} of ${doc.cases.length} JCS vectors match canonicalize`);
process.exit(failed === 0 ? 0 : 1);
