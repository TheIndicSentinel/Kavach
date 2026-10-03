# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the parsers that read untrusted input. This is its own workspace, built with the dated nightly in `rust-toolchain.toml`; the main workspace keeps its stable pin and never builds this one.

## Targets

Ordered by exposure: who can send the input.

| Target | Input | Reached by | Invariants beyond "no crash" |
|---|---|---|---|
| `jws_verify` | Any string as a compact JWS of every Kavach type (mandate, SoR event, credential) | Agents, systems of record, providers | — |
| `jws_signed` | `header\npayload`, signed with a trusted key so parsing after the signature check is reached | The same, past the signature | A verified token has exactly one encoding: its header and payload are the JCS form of what was parsed, and re-signing gives the same token |
| `sor_event` | An SoR event payload, signed by the registered `lms` issuer, through the whole issuance path | Systems of record | An issued mandate verifies as active; a retry finds the same mandate; issuing from the same event again is refused |
| `agent_token` | First byte `0`: any string as an agent token. Otherwise `header\nclaims`, signed with the JWKS key | Agents | An accepted token was signed with EdDSA and names a 1–256 character principal |
| `tool_params` | First byte picks a registry tool; the rest is its parameters as JSON | Agents | A call extracted without violations holds no raw identifier in a reference-only field. The oracle is independent of the detector: at most 8 digits, no PAN |
| `hmac_v2` | Method, path, body and the three HMAC headers. Fixed server time, fresh nonce store per input | Service callers of `/v1/evaluate` | Accepted only with the right MAC, a timestamp within 300 s and a well-formed nonce; a nonce is never accepted twice |
| `jcs_differential` | Any JSON | Everything signed | `kavach_ports::jcs` and a small reference serialiser written from RFC 8785 refuse the same values and otherwise produce the same bytes; canonicalising twice changes nothing. The Node `canonicalize` cross-check in CI is the authority (`crates/kavach-ports/tests/vectors/jcs-v1.json`) |
| `credential_open` | Mode 0: any string as a credential. Mode 1: claims bytes signed with the credential key and encrypted to the provider. Mode 2: byte edits to the checked-in credential vector | Providers | An opened credential is addressed to this provider, lives at most 15 s, is not expired or past `send_by`, and its claims are the canonical form of what was signed; any edit to the vector token is refused |

| `bundle_verify` | Even first byte: (file, position, byte) edits to the checked-in signed bundle. Odd: all four files from the input | Operators and auditors (`verify-bundle`) | A bundle that verifies with the trusted export signature has data files identical to the original and a manifest with the same content. A changed bundle fails, or at most verifies unsigned (the documented warning) |

Planned next: CEL.

## Limits

Each of these counts as a finding, the same as a crash:

| Limit | Value |
|---|---|
| Process memory (`-rss_limit_mb`) | 2048 MB |
| One allocation (`-malloc_limit_mb`) | 512 MB |
| One input (`-timeout`) | 10 s |
| Input size (`-max_len`) | Per target, in `.github/workflows/fuzz.yml` |

## Running

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo fuzz run jws_signed corpus/jws_signed seeds/jws_signed -- \
  -max_total_time=60 -rss_limit_mb=2048 -malloc_limit_mb=512 -timeout=10
```

`seeds/` holds the starting inputs and is committed. `corpus/` and `artifacts/` are not. The nightly **Fuzz** workflow runs every target for 10 minutes and is not a required check. A pull request that changes `fuzz/` or the workflow builds every target and runs each for 60 s, to check the harness still works.

## A finding

1. Download the input from the failed run's artifact. Reproduce it with `cargo fuzz run <target> <file>`.
2. Fix the code, then add the input as a regression test in the owning crate's tests.
3. Add the input to `seeds/<target>/` as well.

Findings in key, credential, data-plane or migration code go to the second reviewer.
