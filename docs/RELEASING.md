# Releasing

Kavach is pre-alpha. Versions are `0.1.0-alpha.N` until v0.1 is declared. **Nothing is published until the name is cleared**, and every publish is the owner's decision. The release workflow only ever creates a *draft*.

## What a release contains

`.github/workflows/release.yml` builds, on GitHub's runners, with the pinned toolchain and `--locked`:

| File | What it is |
|---|---|
| `kavach-<version>-<target>.tar.gz` | `kavach` (the developer CLI) and `kavach-evidence` (the offline evidence verifier), with LICENSE, README and CHANGELOG |
| `kavach-<version>-docs.tar.gz` | Man pages (`kavach man --out`) and shell completions |
| `*-<version>-<target>.cdx.json` | One CycloneDX 1.5 SBOM per binary and target |
| `SHA256SUMS` | Checksums of all of the above |

Targets: `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (built on Ubuntu 22.04, needing glibc 2.34 or later), `aarch64-apple-darwin`, and `x86_64-apple-darwin` (cross-built on Apple silicon). Windows is not built: the dev stack relies on Unix signals and is not tested there. The API server ships later, as a container image.

Every file gets **SLSA build provenance** (`actions/attest-build-provenance`). It is signed with GitHub's Sigstore identity for this workflow and recorded in Sigstore's public transparency log.

## Dry runs

A pull request that changes the workflow, or a manual run (*Actions → Release → Run workflow*), builds and attests everything and uploads it as a workflow artifact (`release-files`). Nothing is released. Use one before every release.

## Cutting a release (owner only, after name clearance)

1. **Version.** Set `[workspace.package] version` in `Cargo.toml`, and the internal dependency versions in `[workspace.dependencies]`, to the new `0.1.0-alpha.N`. Check: `cargo build -p kavach-cli && target/debug/kavach --version`.
2. **Changelog.** Move the `[Unreleased]` entries in `CHANGELOG.md` under a heading for the version.
3. **Gates.** Run the privacy and guardrails review (and any other gate the project requires) on the release commit. Each review records its pass in `.harness/gates.json`, tied to that commit. Without them, the local `release_gate` hook blocks release commands.
4. **Tag.** On `main`, at the release commit: `git tag -s v0.1.0-alpha.N` (signed), then `git push origin v0.1.0-alpha.N`. The workflow refuses a tag that does not match the workspace version.
5. **Review the draft.** It is created as a pre-release draft. Check the files, the checksums and the attestations:
   ```bash
   gh release download v0.1.0-alpha.N --dir /tmp/kavach-release
   cd /tmp/kavach-release && sha256sum -c SHA256SUMS
   gh attestation verify kavach-0.1.0-alpha.N-x86_64-unknown-linux-gnu.tar.gz --repo TheIndicSentinel/Kavach
   ```
6. **Publish** the draft by hand, or delete it.

Not part of a release yet: crates.io, Homebrew, installers, and macOS signing and notarization. All of them wait for the name.

## Installing from a release (for testers)

```bash
tar -xzf kavach-0.1.0-alpha.N-aarch64-apple-darwin.tar.gz
cd kavach-0.1.0-alpha.N-aarch64-apple-darwin
xattr -d com.apple.quarantine kavach kavach-evidence   # macOS: the binaries are not notarized
./kavach --version
```
