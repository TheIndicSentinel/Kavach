# Independent verifier

`kavach_verify.py` checks Kavach evidence bundles, checkpoints and credentials against the public specifications in [`docs/specs/`](../docs/specs/). It is **not** a build of the Rust verifier: it is a second implementation, in another language, written from the specification text alone, with the Python standard library only (Ed25519, X25519 and AES-GCM are written out in the file from RFC 8032, RFC 7748 and NIST SP 800-38D). If it and the Rust tools disagree, one of them or the specification is wrong, and that is the point.

```
python3 conformance/kavach_verify.py bundle DIR --keys KEYS.json [--expect-checkpoint FILE] [--now RFC3339] [--dev] [--allow-warnings]
python3 conformance/kavach_verify.py credential VECTOR.json
python3 conformance/kavach_verify.py mandate VECTOR.json
python3 conformance/kavach_verify.py jcs VECTOR.json
python3 conformance/kavach_verify.py checkpoints VECTOR.json
```

Exit status: `0` verified, `2` verified with warnings (the same warnings as `kavach-evidence verify-bundle`), `1` does not verify. The report is JSON on standard output.

## Tests

```
python3 -I -m unittest discover -s conformance -v
```

They check that every published vector verifies with the warnings the specification lists, and that mutations are refused: a changed record, manifest or file list, wrong keys, keys inside the bundle, an unknown record kind (refused, never skipped), a revocation in a version 1 bundle, a repeated member name, a removed or repeated record, a repeated outcome, a non-integer number, and an unknown `hash_alg`. CI runs them as "Independent verifier".

## What it is not

- **Not for production secrets.** The credential command takes a provider's private key, and pure-Python big-integer arithmetic is not constant-time. It is for conformance checking and audit.
- **Not a replacement for the Rust verifier** in a deployment: it is slower and covers the formats in `docs/specs/` only (bundle versions 1 to 4, checkpoints, credentials, mandates and system-of-record events).
- **Not covering** mandate *status* (live or revoked) or the evidence record's own fields beyond the bundle spec: status lives in Kavach's store, not in a token.

## Found so far

Writing this verifier from the specification found two places where the Rust verifier was looser than the specification: it accepted a member name used twice in one object (serde keeps the last), and it never read a record's `hash_alg`. Both are fixed in the Rust verifier and covered by tests there.

The mandate specification found a third: token verification never re-checked a mandate's form (version, contact floor, depth, lifetime, channels, ceilings); those were enforced only when issuing. Verification now checks them.
