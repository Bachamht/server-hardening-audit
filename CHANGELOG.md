# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## [Unreleased] — 0.1.0

First version.

### Added

- `audit`: 25 controls across access, network, patching, detection,
  resilience and baseline, run read-only on the host with evidence and a
  sha256 manifest; `--replay` re-evaluates saved evidence.
- Default-deny allowlists for commands and file reads; derived-only evidence
  for sensitive sources; loopback-only TLS checks.
- `list`: every command and file each control may use.
- `report`: Markdown and JSON, with `--attest` for attestations and risk
  acceptances and `--framework` for Essential Eight Maturity Level One and
  ISO/IEC 27001:2022 Annex A views.
- `probe`: external view from the operator's machine — ports per address
  family, SSH authentication methods without offering credentials, TLS —
  and attestations for NET-04, NET-05 and ACC-01.
- `diff`: verdict changes, listener changes and Lynis score between runs.
- `scrub`: publishable copies with placeholders and documentation
  addresses, refusing output that leaks.
- `redact-check`: secret scanner for anything about to be published.
- Agent skill (`skills/server-hardening-audit/SKILL.md`).
- Single-file distribution: `server-hardening-audit.pyz`, Python 3.10+,
  no dependencies.
