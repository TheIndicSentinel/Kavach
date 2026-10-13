# Resource credential, version 1 (normative)

A resource credential is what the Kavach gateway hands to a **provider** (a backend that performs an action) so that the provider can verify, by itself, that this exact request was authorized. It is a **nested JWT, signed then encrypted** (RFC 7519 §11.2): an inner JWS (EdDSA) inside an outer JWE (ECDH-ES on X25519, A256GCM). Both layers carry explicit types (RFC 8725 §3.11).

Conventions are in [README.md](README.md). A provider written from this text is in [`conformance/`](../../conformance/README.md).

## 1. What it is for, and what it is not

- It binds one decision to one request: the agent, the mandate, the evidence record, the provider, the time window and the request itself (destination, channel, template).
- **Only the provider can read it.** The destination is inside the encryption, so nothing in transit, in a log line or in a stolen token shows it or lets the request be redirected.
- It authorizes a single request and lives at most 15 seconds. Using it twice is the provider's idempotency check (§5).
- It is **not** a bearer token for anything else, and it says nothing about whether the decision was right.

A provider that verifies it itself enforces the decision even if the gateway were bypassed. A provider that does not (it accepts its own API token) is a different mode, in which the gateway enforces: see ADR-015 and [SECURITY_PROPERTIES.md](../SECURITY_PROPERTIES.md).

## 2. The token

A compact JWE (RFC 7516): five parts separated by `.`:

```
BASE64URL(header) . (empty) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
```

The encrypted-key part is **empty**: the content key is derived directly from the key agreement. A token longer than 32,768 bytes MUST be refused.

### 2.1 JWE header
A JSON object, in canonical form (RFC 8785), with exactly these members and no others:

| Member | Value |
|---|---|
| `alg` | `ECDH-ES` |
| `enc` | `A256GCM` |
| `epk` | `{ "kty": "OKP", "crv": "X25519", "x": <base64url of the 32-byte ephemeral public key> }`, with exactly these members |
| `kid` | The id of the provider's encryption key |
| `typ` | `kavach-credential+jwe` |
| `cty` | `kavach-credential+jws` |

A provider MUST refuse a header with another `alg`, `enc`, `typ` or `cty`, with a member not listed, or with an `epk` that is not an X25519 OKP key. It MUST refuse a `kid` that is not its own.

### 2.2 Content key
1. `Z` = X25519(provider private key, `epk`). The result MUST NOT be all zero bytes (a low-order point): refuse it.
2. `CEK` = the first 32 bytes of `SHA-256( 0x00000001 || Z || OtherInfo )`, where `OtherInfo` is, in order and each length-prefixed by its length as 4 bytes big-endian: the ASCII bytes of `A256GCM`, then an **empty** PartyUInfo, then an **empty** PartyVInfo; followed by the key length in bits (`256`) as 4 bytes big-endian. This is the Concat KDF of NIST SP 800-56A, as RFC 7518 §4.6.2 uses it for `ECDH-ES` with the `enc` value as AlgorithmID.

So `OtherInfo` is `00000007 "A256GCM" 00000000 00000000 00000100`.

### 2.3 Decryption
AES-256-GCM with key `CEK`, the 12-byte `iv`, the 16-byte `tag`, and the additional authenticated data **`ASCII(BASE64URL(header))`**, the header part exactly as it appears in the token. A tag that does not authenticate MUST be refused. The plaintext is the UTF-8 text of an inner JWS.

## 3. The inner JWS

A compact JWS (RFC 7515): `BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)`, at most 16,384 bytes.

- **Header:** canonical JSON with exactly `alg` = `EdDSA`, `kid` (the credential signing key) and `typ` = `kavach-credential+jws`.
- **Payload:** canonical JSON (RFC 8785) of the claims in §3.1.
- **Signature:** Ed25519 over the ASCII bytes of `BASE64URL(header) . BASE64URL(payload)`.
- A header or payload that is **not** in canonical form MUST be refused, so that every token has exactly one valid encoding. Base64url MUST have no padding and no non-zero trailing bits. The signature is verified before the payload is parsed.

### 3.1 Claims
Exactly these members and no others (`send_by` is optional):

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | The issuer (Kavach) |
| `tenant` | string | Tenant |
| `agent` | string | The agent that made the request |
| `mandate_id` | string | The mandate it was authorized under |
| `record_id` | string | The evidence record of the decision |
| `jti` | string | The credential id: equal to the evidence record's `credential_id`. Unique per credential |
| `aud` | string | The provider this is for |
| `action` | string | The action (for example `send_reminder`) |
| `req` | object | `{ "channel": string, "destination": string, "template_id": string }`, exactly these members |
| `iat` | integer | Issued at, Unix seconds |
| `exp` | integer | Expiry, Unix seconds. `exp − iat` is at most 15 and `exp > iat` |
| `send_by` | integer, optional | The deadline after which the request must not be started. `exp` is at most `send_by` |

## 4. What a provider MUST check

In this order:

1. The token is well formed (§2) and decrypts with the provider's own key (§2.2, §2.3).
2. The inner JWS is well formed and canonical (§3) and its signature verifies with a **trusted credential key** named by its `kid`. The provider is given its trusted credential keys by the operator, never from the token.
3. `aud` equals the provider's own audience.
4. *Idempotency lookup (§5).*
5. Time, with `now` on the provider's clock and `leeway` a small non-negative number of seconds (default 0):
   - `exp − iat` is at most 15 and `exp > iat`;
   - `iat` is at most `now + 5 + leeway`;
   - `now` is less than `exp + leeway`;
   - if `send_by` is present: `now + leeway` is less than `send_by`, and `exp` is at most `send_by`.
6. The request it received (destination, channel, template) equals `req`. It acts on `req`, not on anything else it was sent.

A provider that does not receive the request fields separately simply takes `req` as the request.

## 5. Replay
A provider MUST deliver a given `jti` at most once. It keeps a record of each `jti` (or of the digest in §5.1) for at least as long as a credential can be presented: until `send_by`, in practice one working day. A second presentation returns the stored result and does not deliver again. The lookup is between steps 3 and 5 of §4, so a stored result stays recoverable after expiry without ever allowing a new delivery.

### 5.1 The digest of a credential
`claims_sha256` = `hex( SHA-256( JCS(claims) ) )`. Token bytes cannot serve as "the same credential", since every encryption of the same claims differs.

## 6. Test vector
`crates/kavach-credential/tests/vectors/credential-v1.json`:

| Member | Meaning |
|---|---|
| `provider_jwk` | The provider's X25519 key pair, as a JWK (`d` is the private key; test keys only) |
| `credential_signing_jwk` | The credential signing public key, as a JWK |
| `token` | The credential |
| `claims`, `claims_sha256` | The expected claims, and the digest of their canonical form |
| `audience` | The audience the provider uses |
| `verify_at` | The `now` to use (Unix seconds) |

A provider MUST, for this vector, decrypt, verify, find `claims` equal to the expected claims, accept the time checks at `verify_at`, and compute `claims_sha256`. It MUST refuse the token with one bit of the tag changed, refuse it at `verify_at + 15` (expired), and refuse it for another audience.
