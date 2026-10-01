# Security policy

Kavach is security infrastructure, so we take reports seriously and handle them privately.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). Please include:

- the affected component and version or commit;
- steps to reproduce, or a proof of concept;
- the impact you expect (for example, an agent acting without a valid mandate, a credential replay, evidence tampering, personal data exposure).

**Never include real personal data** (real phone numbers, account numbers, Aadhaar or PAN) in a report. Use synthetic values.

## What to expect

- Acknowledgement within 5 working days.
- An initial assessment within 15 working days.
- A fix, an advisory and credit (if you want it) once a release is available. We ask for coordinated disclosure: please give us up to 90 days before publishing.

## Scope

In scope: everything in this repository, in particular the guarantees in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md). A guarantee that does not hold as written is a vulnerability.

Out of scope: deployments using `--insecure-dev`, the protocol fixtures (`kavach-mock-provider`, the reference resolver fixture) used as if they were production components, and findings that need an already-compromised host or signing key.

## Supported versions

Kavach is pre-release. Fixes go to `main`; there are no maintained release branches yet.
