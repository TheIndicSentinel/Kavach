// Decrypts and verifies the checked-in Kavach credential vector with the
// independent `jose` library, so a bug shared by Kavach's issuer and its
// verifier cannot hide behind a round-trip test (ADR-006 D12).
//
//   node check.mjs ../../crates/kavach-credential/tests/vectors/credential-v1.json
import { readFileSync } from "node:fs";
import { deepStrictEqual, equal, rejects } from "node:assert/strict";
import { compactDecrypt, compactVerify, importJWK } from "jose";

const vector = JSON.parse(readFileSync(process.argv[2], "utf8"));
const providerKey = await importJWK(vector.provider_jwk, "ECDH-ES");
const signingKey = await importJWK(vector.credential_signing_jwk, "EdDSA");
const decryptOptions = {
  keyManagementAlgorithms: ["ECDH-ES"],
  contentEncryptionAlgorithms: ["A256GCM"],
};

// Outer JWE: ECDH-ES on X25519, A256GCM, explicit types, our recipient.
const { plaintext, protectedHeader: jweHeader } = await compactDecrypt(
  vector.token,
  providerKey,
  decryptOptions,
);
equal(jweHeader.alg, "ECDH-ES");
equal(jweHeader.enc, "A256GCM");
equal(jweHeader.typ, "kavach-credential+jwe");
equal(jweHeader.cty, "kavach-credential+jws");
equal(jweHeader.kid, vector.provider_jwk.kid);
equal(jweHeader.epk.crv, "X25519");

// Inner JWS: EdDSA by the credential key.
const jws = new TextDecoder().decode(plaintext);
const { payload, protectedHeader: jwsHeader } = await compactVerify(jws, signingKey, {
  algorithms: ["EdDSA"],
});
equal(jwsHeader.typ, "kavach-credential+jws");
equal(jwsHeader.kid, vector.credential_signing_jwk.kid);
deepStrictEqual(JSON.parse(new TextDecoder().decode(payload)), vector.claims);

// Negative: a flipped tag bit must not decrypt.
const parts = vector.token.split(".");
const tag = Buffer.from(parts[4], "base64url");
tag[0] ^= 1;
parts[4] = tag.toString("base64url");
await rejects(compactDecrypt(parts.join("."), providerKey, decryptOptions));

console.log("jose cross-check: ok (decrypted, verified, claims match, tamper refused)");
