# Key Runbook

How to create, distribute, rotate and retire Kavach's keys, and what to do when one is compromised. It is for the operators of a deployment. Key handling guarantees are in [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md); the ways around them are in [BYPASS_INVENTORY.md](BYPASS_INVENTORY.md).

## The keys

Every signing key is Ed25519. Each role has its own key: Kavach refuses to start if two roles share a key id or key material.

| Role | Signs | Used by | Who must trust its public key | How long what it signs must verify | Where it may live |
|---|---|---|---|---|---|
| **Mandate** | Mandates | The API | The API itself (mandate configuration) | Until the mandate expires (the template's `ttl_seconds`) | Key file or HSM |
| **Evidence** | Agent decision records and outcomes | The API | Every verifier (trusted keys file) | For as long as the evidence is kept | Key file or HSM |
| **Checkpoint** | Evidence checkpoints | The API | Every verifier (trusted keys file) | For as long as the evidence is kept | Key file or HSM |
| **Credential** | Resource credentials | The API | Every resource provider | 15 seconds at most | Key file or HSM |
| **Export** (`export-…`) | Evidence bundle manifests | Whoever exports, never the API host | Every verifier (trusted keys file) | For as long as the bundle is kept | Key file or HSM |
| **System of record** | Events that issue mandates | The system of record | The API (`sor_issuers` in the mandate configuration) | Minutes (event freshness) | The system of record's own |
| **Pack, model, tool** signers | Policy packs, model records, the tool registry | Governance signers | The API (trusted signers file) | While the signed file is in use | Key file |

Secrets that are not signing keys:

- **Subject pseudonym key** (`--subject-pseudonym-key`): a 32-byte secret that turns subjects into pseudonyms in evidence. Changing it changes every pseudonym, so records before and after no longer match by subject. Rotate it only with a plan for that (and see erasure, ADR-005).
- **Provider encryption keys** (X25519, `--providers`): each provider's own; Kavach holds only their public halves.
- **HSM PIN** (`--hsm-pin-file`): logs in to the token. Whoever has it can make the HSM sign.

## Creating a key

- **Key file:** `kavach-keys generate --dir <dir> --kid <id>` writes an owner-only file; `kavach-keys public-key --dir <dir> --kid <id>` prints its public half.
- **HSM:** generate the key inside the token with the vendor's tool, or with OpenSC for any PKCS#11 token:
  ```sh
  pkcs11-tool --module <vendor.so> --token-label <token> --login \
    --keypairgen --key-type EC:edwards25519 --label <id> --usage-sign
  ```
  The key must be sensitive and never extractable (most tools do this by default; check the private key's attributes). Kavach refuses a key that was imported or was ever extractable, outside `--insecure-dev`. The label is the key id.
- **Ids:** a new id for every key (`kavach-mandate-2` after `kavach-mandate-1`), never reused. Export key ids start with `export-`. Never use a `dev-` id outside a development stack: Kavach refuses them.

## Giving out public keys

| Public key of | Goes to |
|---|---|
| Evidence, checkpoint, export | The verifiers' trusted keys file (`kavach-evidence verify-bundle --keys`), kept away from the deployment |
| Credential | Each resource provider's trusted credential keys |
| Mandate | Nobody outside: the API reads it from its own key (and earlier ones from `previous_mandate_keys`) |
| System of record | `sor_issuers` in the mandate configuration |

## Rotating a key, with an overlap

The rule for every role: **the new key signs from the switch; the old key stays trusted for verification only, for as long as anything it signed must still verify.** After that, the old public key is removed where it is no longer needed, and the old private key is destroyed.

**Mandate key.** Mandates signed by the old key keep their authority during the overlap.
1. Create the new key (file or HSM).
2. In the mandate configuration, set `signing_kid` to the new id and add the old key to `previous_mandate_keys`:
   ```json
   "signing_kid": "kavach-mandate-2",
   "previous_mandate_keys": [ { "kid": "kavach-mandate-1", "public_key": "<64 hex>" } ]
   ```
   Kavach refuses the current key in this list, by id or by key material, and lists the same key only once.
3. Restart every API replica. New mandates and delegations are signed with the new key; mandates signed with the old one still verify.
4. The overlap lasts until the last mandate signed with the old key has expired: the longest template `ttl_seconds` after the switch.
5. Remove the old key from `previous_mandate_keys`, restart, and destroy the old private key. Mandates still signed with it stop verifying, which is the intent.

**Evidence and checkpoint keys.** Evidence must verify for as long as it is kept, so the old public key stays in the verifiers' trusted keys file permanently.
1. Create the new key. Add its public key to the trusted keys file **before** the switch.
2. Set `--evidence-key-id` (or `--checkpoint-key-id`) to the new id and restart every replica. Each record and checkpoint names the key that signed it, so the chain continues across the change.
3. Destroy the old private key. Keep its public key in the trusted keys file.

**Credential key.** Credentials live 15 seconds, so the overlap is short.
1. Create the new key and have every provider trust its public key, next to the old one.
2. Set `--credential-key-id` and restart every replica.
3. After a minute (15 seconds plus clock skew), providers drop the old key. Destroy the old private key.

**Export key.** The exporter's own key.
1. Add the new public key to the verifiers' trusted keys file.
2. Export with the new `--key-id`. Keep the old public key while bundles signed with it are kept.

**System-of-record key.** Add the new key to `sor_issuers` for that system, restart, have the system of record switch, then remove the old entry and restart.

**Keys in an HSM** rotate the same way: the new key is generated in the HSM, its label is the new id, and `--hsm-keys` does not change.

## When a key is compromised

First, everywhere: record when the compromise began (or the earliest time it could have), contain it as below, and follow your incident process. There is no overlap: the compromised key stops being trusted for anything it could have signed after that time.

| Key | What an attacker can do | Do now |
|---|---|---|
| **Mandate** | Issue mandates that verify, for any template and agent | Switch to a new key with no `previous_mandate_keys` entry for the old one and restart. Every mandate signed with the old key stops verifying: agents are blocked until the system of record issues new mandates (fail closed). Destroy the old key |
| **Evidence** | Forge records and outcomes that verify | Switch the key and restart. In the verifiers' trusted keys file, set `valid_until_seq` on the old key to the record of the last checkpoint kept off-host before the compromise. Export now and verify against those kept checkpoints |
| **Checkpoint** | Forge checkpoints, hiding a rewrite of the chain | Switch the key and restart. Set `valid_until_seq` on the old key, as for the evidence key. Copies kept off-host from before the compromise stay trustworthy; verify the chain against them. Copy a new checkpoint off-host as soon as one is written |
| **Credential** | Mint credentials that providers accept, for 15 seconds each | Have every provider drop the old key at once, switch, restart. Check provider logs for credentials Kavach has no evidence record for |
| **Export** | Sign bundles that look like yours | Tell every verifier to drop the old key; export again with a new one |
| **System of record** | Issue events, and so mandates within the templates | Remove its entry from `sor_issuers`, restart; revoke mandates issued from it since the compromise |
| **HSM PIN** | Make the HSM sign with any key on the token, but not read the keys | Change the PIN with the vendor's tool, update the PIN file, restart. Review what was signed while it was exposed, as above |

**Limits on a compromised key.** Set `valid_until_seq` on the key in the verifiers' trusted keys file, taken from a checkpoint kept off-host before the compromise ([EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md#trusted-keys)). The verifier then refuses whatever the key signed for any later record, including backdated forgeries, unless a kept checkpoint covers it. `not_after` set to the compromise time retires the key in time too, but a stolen key can backdate its signatures, so do not rely on it alone.

## Backups

- **Signing keys need no backup.** Losing one means rotating it; verifiers need only public keys. Back up the public keys and the trusted keys file instead.
- **Keys in an HSM:** use the vendor's backup or cluster features, if any. Kavach needs only the token label and the key labels.
- **The subject pseudonym key does need a backup.** Losing it breaks the link between records of the same subject.

## The HSM PIN

- Only in an owner-only file (`--hsm-pin-file`); never a flag value or an environment variable. Kavach refuses a file that its group or others can read.
- Change it with the vendor's tool, update the file, then restart the API.
- Whoever can read it can make the HSM sign. Protect it like a key file.

## Development keys

A development bundle's keys (`dev-…`) are refused outside `--insecure-dev`, and evidence they sign is refused by the verifier unless a development stack is being verified explicitly. Never copy a development key into a deployment.
