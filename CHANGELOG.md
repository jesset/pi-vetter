# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `/vet` command: read-only multi-source security evaluation of pending extension updates or explicit `npm:<pkg>[@<version>]` specs
- `/vet-install` command: evaluation plus interactive selection (TUI checkbox, grouped-confirm fallback) and gated install of approved versions
- Rule-driven ALLOW/ASK/DENY verdicts with fail-closed capping on incomplete evidence (ADR-0001/0002)
- Scanners: registry metadata (maintainer snapshots, package age, release cadence), OSV (CVE + GHSA + OpenSSF MAL-, including new dependencies), npm provenance conflict detection, static pattern analysis (credential access, obfuscation, prompt-injection markers), and old-vs-new version diff (lifecycle scripts, dependencies, child_process, outbound endpoints)
- In-memory tarball parsing with sha512 integrity verification (no disk extraction of untrusted content)
- TOCTOU guard: registry integrity re-checked before every install; installs use pinned `npm:<pkg>@<version>` specs that `pi update --extensions` skips (ADR-0003)
- Config (`~/.pi/agent/pi-vetter/config.json`) with per-scanner and per-rule toggles; result cache with configurable TTL
