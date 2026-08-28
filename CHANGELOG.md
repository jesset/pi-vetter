# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `/vet` and `/vet-install` now emit a done notification with verdict counts (`N vetted: X ALLOW, Y ASK, Z DENY`) and an aborted notification with the failure reason; reports are batched into one verdict-ordered summary at the end instead of streamed per package (the progress widget covers process visibility)

### Fixed

- VirusTotal upload+poll flow is bounded by a total deadline (`pollDeadlineMs`, defaulting to the scanner timeoutMs) — previously only individual requests were bounded, letting a stuck analysis stall a package for up to ~30 minutes

## [0.1.1] - 2026-08-28

### Added

- `/vet` command: read-only multi-source security evaluation of pending extension updates or explicit `npm:<pkg>[@<version>]` specs
- `/vet-install` command: evaluation plus interactive selection (TUI checkbox, grouped-confirm fallback) and gated install of approved versions
- Rule-driven ALLOW/ASK/DENY verdicts with fail-closed capping on incomplete evidence (ADR-0001/0002)
- Scanners: registry metadata (maintainer snapshots, package age, release cadence), OSV (CVE + GHSA + OpenSSF MAL-, including new dependencies), npm provenance conflict detection, static pattern analysis (credential access, obfuscation, prompt-injection markers), and old-vs-new version diff (lifecycle scripts, dependencies, child_process, outbound endpoints)
- In-memory tarball parsing with sha512 integrity verification (no disk extraction of untrusted content)
- TOCTOU guard: registry integrity re-checked before every install; installs use pinned `npm:<pkg>@<version>` specs that `pi update --extensions` skips (ADR-0003)
- Config (`~/.pi/agent/pi-vetter/config.json`) with per-scanner and per-rule toggles; result cache with configurable TTL

### Fixed

- Per-package streaming reports, concurrent package evaluation (3 workers) and network-wide timeouts (`network.timeoutMs`, default 30s) — previously a full run could appear frozen for minutes
- Static eval-family hits render as info evidence (no rule mapped) instead of a misleading fail marker; multi-package reports ordered DENY > ASK > ALLOW
- Per-package registry failures degrade to notes instead of aborting the whole evaluation

### Added (post-verification)

- Full sigstore provenance verification: attestations are verified against a vendored public TrustedRoot (refreshable via scripts/fetch-trusted-root.ts); verified bundles produce `provenance:verified` (pass), substantive signature failures produce `provenance:conflict`, and bundles signed with keys outside the public root (npm's publish-attestation key) are reported as informational
- Immediate command feedback: `/vet` and `/vet-install` acknowledge instantly (before any network request), and in TUI mode show a live progress widget (`Vetting (2/4) → pkg`) that is cleared on completion; non-TUI keeps the instant acknowledgement
- VirusTotal scanner (L3, opt-in via API key): hash-first report lookup, upload-on-miss of the exact vetted tarball bytes, async analysis polling; ≥2 engine detections → DENY (`vt-detections`); quota/timeout failures cap the verdict at ASK; hash-report results cached forever
- Socket.dev scanner (L3, opt-in via API key + org slug): purl-based package alerts; high-risk alerts (gptMalware, installScripts, obfuscatedFile, typosquatting) → ASK (`socket-flagged`), minor alerts informational; quota exhaustion maps to fail-closed capping
