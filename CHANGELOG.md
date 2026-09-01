# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT `LICENSE` file at the repo root (the license was declared in package.json but the text was missing); README badge row (npm version / downloads / license / node) in both READMEs; GitHub topics expanded for discoverability

### Added

- Dynamic code execution escalates to ASK by default: eval/new Function/vm-family hits and dynamic module resolution (concatenated, base64-decoded, or variable require/import) map to a new `dynamic-code-execution` rule — a hard signal in the install scenario, and behavior-change-gated (new hits fail, pre-existing hits stay info) in updates; disable via config for legitimate minified bundles (#40)
- Transitive dependency findings follow a severity ladder: credential/obfuscation/prompt-injection/dynamic-code hits inside scanned dependency tarballs escalate to a new `transitive-risk` ASK rule attributed per dependency; ordinary Node.js API usage stays informational (#41)
- Policy visibility: rules disabled via config are disclosed in the report Notes (mirroring the scanner-gap disclosure), and ALLOW reports carry the qualifier that no enabled rule detected a known risk (#42)
- `/vet-install` fails closed when the install registry (`npm config get registry`) diverges from the vetting registry (`PI_VETTER_NPM_REGISTRY`): packages are skipped with guidance instead of proceeding on an unverifiable chain (#43)
- Configurable `provenance.required` policy: missing npm attestations stay informational by default, escalate to a `provenance-missing` ASK rule when enabled (#44)
- Adversarial E2E suite fixing the audit's evasion shapes (concatenated/base64 require, dynamic import, credential exfiltration, transitive downgrade) as regression guards (#45)

### Fixed

- Baseline tarballs are integrity-verified against the registry `dist.integrity` before entering diff analysis; a tampered or unattested baseline now fails the package evaluation (fail-closed) instead of serving as the behavioral reference (#36)
- Scanner cache identity is bound to the baseline version and the candidate artifact digest; baseline-aware scanners (diff/static/osv) no longer reuse results across install-vs-update scenarios or different baselines (#37)
- OSV dependency queries use the version npm would actually resolve (highest published in-range version) instead of the range's lower bound, so vulnerabilities affecting only higher in-range versions are no longer missed; composite ranges stay at the lower bound (never an out-of-range `dist-tags.latest`), resolution failures degrade to the lower bound with an informational evidence disclosure, and unparseable ranges keep the version-less query. Resolution adds one registry packument fetch per queried dependency (#38)

### Changed

- npm keywords expanded (`audit`, `cli`, `osv`, `sigstore`, `typosquatting`) for better registry search hits

## [0.3.1] - 2026-08-31

### Added

- README demo GIF (`docs/demo.gif`, ~9s, recorded via `scripts/demo.tape` with [vhs](https://github.com/charmbracelet/vhs)): a full `/vet npm:@narumitw/pi-statusline` run in the Pi TUI — from the update-available banner through the resolving/vetting progress widget to the complete report (verdict, risk score, full evidence list); embedded above the install section in both READMEs, referenced by absolute URL so npm/pi.dev rendering can resolve it

### Changed

- Scanner failures are diagnosable from the report: the `errored` incomplete evidence now carries the underlying reason (e.g. `errored: Socket purl scan failed: HTTP 502`) instead of a bare "errored"; timeout/quota-exhausted wording unchanged (#35)

## [0.3.0] - 2026-08-30

### Added

- E2E test harness (#26): npm registry / downloads API / OSV API endpoints and the data dir are overridable via environment variables (`PI_VETTER_NPM_REGISTRY`, `PI_VETTER_DOWNLOADS_API`, `PI_VETTER_OSV_API`, `PI_VETTER_DATA_DIR`) — also usable for private registries/mirrors; vitest is split into unit and e2e projects, and the first end-to-end scenario (clean update → ALLOW) runs the full chain against an in-memory fake registry served over real HTTP
- The agent dir (`~/.pi/agent`, read for the installed-package inventory and written on install/unpin) is overridable via `PI_VETTER_AGENT_DIR` (#30)
- Live E2E suite (#31): `LIVE_E2E=1 npx vitest run --project live` vets fixed quiet packages (left-pad@1.3.0, ms@2.1.3) against the real npm registry/OSV endpoints, asserting invariants (verdict present, uncapped, full scanner chain, sha512 integrity) rather than specific verdicts; a non-blocking nightly GitHub Actions workflow runs it on schedule. `npm test` runs unit + e2e only; the one-off `scripts/smoke.ts` is gone (the live suite replaces it)

### Changed

- A scanner enabled without its credentials (VirusTotal `apiKey`, Socket `apiKey`/`orgSlug`) is no longer silently unregistered: `/vet` and `/vet-install` warn at start and disclose each skipped scanner in the report Notes, including the free-key registration hint; `enabled: false` stays fully silent (#33)
- Progress widget (#18): per-package checklist rows (`·` pending / `…` in-flight / `✓` done) during both the resolving and vetting phases, replacing the single `(done/total) → current` counter whose "current package" line was unstable under concurrent evaluation; rows carry no verdicts — conclusions stay in the final batched report

### Fixed

- Non-npm sources (git/local) are no longer silently skipped: a no-argument `/vet` now discloses every skipped source in the report notes (`- git:github.com/a/b: not an npm source, out of scope`), and a report consisting only of skipped sources shows that disclosure instead of the empty-state message (#23)

## [0.2.3] - 2026-08-28

### Added

- CI: tests/typecheck/lint on every branch and PR; v* tags now release fully automatically (GitHub Release + npm publish via Trusted Publishing with provenance)

### Fixed

- Deep-scan review fixes (#7 follow-up): dependency versions now resolve to the highest published version inside the declared range instead of always `latest` (scanned tarball ≈ what npm would install; fallback to `latest` disclosed in READMEs); dependency tarballs are integrity-verified against `dist.integrity`; fetch/verify failures are counted and disclosed in the evidence instead of silently shrinking the sample; dependency packuments are no longer fetched twice

## [0.2.0] - 2026-08-28

### Changed

- Deep dependency scanning (#7): the transitive dependency closure (BFS from registry metadata, bounded by depth 2 / 20 packages by default, configurable and switchable via `dependencies.*`) is downloaded in-memory and statically scanned; hits surface as informational evidence attributed per dependency (`undici@8.10.0: obfuscation x2`) without affecting the verdict in this phase
- Install-scenario false-positive reduction (#12): with no baseline to diff against, credential-access and obfuscation static hits stay informational (a package's legitimate nature, e.g. API-key readers) while prompt-injection remains a hard signal; update-scenario behaviour unchanged
- Responsibility rebalance (#16): pinned packages are now evaluated on every `/vet` (marked "baseline is pinned" — the previous behaviour skipped them entirely); `install.pinOnInstall` defaults to **false**, so approved installs no longer silently rewrite the settings entry to a pinned spec — the install result shows the exact pin command for users who want it. ADR-0003 revised accordingly
- `/vet` and `/vet-install` now emit a done notification with verdict counts (`N vetted: X ALLOW, Y ASK, Z DENY`) and an aborted notification with the failure reason; reports are batched into one verdict-ordered summary at the end instead of streamed per package (the progress widget covers process visibility)

### Fixed

- VirusTotal upload+poll flow is bounded by a single deadline budget (`pollDeadlineMs`, configurable per scanner, defaulting to the scanner timeoutMs) — previously only individual requests were bounded, letting a stuck analysis stall a package for up to ~30 minutes; poll requests are additionally bounded by the remaining budget so a single slow response cannot overshoot

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
