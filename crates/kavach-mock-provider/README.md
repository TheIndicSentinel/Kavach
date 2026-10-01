# kavach-mock-provider — PROTOCOL FIXTURE

A mock messaging provider that accepts **only** Kavach resource credentials. It
exists so the gateway, the end-to-end tests and the network-isolation tests
have a backend that enforces the credential. **It is not a real provider**, is
`publish = false`, and is not in the production image.

Real WhatsApp/SMS providers accept their own API tokens. For them, the
boundary is the gateway holding the provider token plus network isolation;
destination binding by the backend exists only for backends that adopt the
Kavach credential format.

```bash
# 1. Provider encryption key; prints the entry for Kavach's --providers file
kavach-mock-provider keygen --out ./provider.key --kid mock-messaging-enc-1

# 2. Serve (API on 8095; inbox of delivered messages on 8099, loopback only)
kavach-mock-provider serve --encryption-key ./provider.key \
  --encryption-kid mock-messaging-enc-1 --credential-keys ./credential-keys.json
```

`credential-keys.json` is `{"keys": [{"kid": "kavach-credential-1", "public_key": "<hex Ed25519>"}]}`
(`kavach-keys public-key --dir <credential keys dir> --kid kavach-credential-1`).

The protocol, status codes and reserved test numbers are documented in the
crate docs (`src/lib.rs`) and ADR-007. State is in memory: a restart forgets
`jti`s, and the clock is this host's, not trusted time.
