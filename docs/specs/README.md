# Kavach specifications

Normative definitions of what Kavach writes and what a verifier must check, written so that someone can implement a verifier **without reading the Rust code**.

| Spec | Defines | Test vectors |
|---|---|---|
| [evidence-bundle.md](evidence-bundle.md) | The evidence chain: records and their kinds, outcomes, checkpoints, the bundle manifest, and how to verify them | `crates/kavach-evidence-cli/tests/vectors/` (`bundle-v1`, `bundle-v2`), `crates/kavach-ports/tests/vectors/` (`checkpoint-v1.json`, `jcs-v1.json`) |
| [credential-format.md](credential-format.md) | The resource credential a provider receives and what it must check | `crates/kavach-credential/tests/vectors/credential-v1.json` |

Not yet specified normatively: the Task Mandate and the system-of-record event (ADR-004 is the design record; vectors do not exist yet).

## Conventions
- **MUST, MUST NOT, SHOULD, MAY** are used as in RFC 2119.
- JSON is RFC 8259, UTF-8, without a byte-order mark. **Canonical JSON** is RFC 8785 (JCS).
- **Hex** is lowercase, with no prefix. **Base64url** is RFC 4648 §5 without padding.
- **Times** are RFC 3339 in UTC with a `Z` suffix.
- Signatures are **Ed25519** (RFC 8032, the pure algorithm, not Ed25519ph).

## Versions and extension
A format carries its own version. A verifier MUST refuse a version it does not know. A record **kind** that a verifier does not know is refused, never skipped. A new kind is added to the registry in the evidence-bundle spec with a format version, so an old verifier fails on a new bundle rather than misreading it.

## Conformance
An implementation conforms when it passes the vectors named above and refuses what the spec says to refuse. [`conformance/`](../../conformance/README.md) holds an independent verifier, written from these documents alone and run in CI on every pull request. A discrepancy between it and the Rust implementation is a bug in one of them or in the spec text, and is fixed in the spec first.

## Status
Pre-alpha. These specs describe `0.1.0-alpha.1`. They are not a security assessment, and a conforming verifier proves only what [SECURITY_PROPERTIES.md](../SECURITY_PROPERTIES.md) says an evidence check proves.
