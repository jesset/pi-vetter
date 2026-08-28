# pi-vetter

[简体中文](./README.zh-cn.md)

Security vetting for [Pi](https://pi.dev) extension packages — an evidence-driven gate before you install or update.

Pi installs extension packages with full user permissions and runs their `postinstall` scripts; the built-in updater only tells you that updates exist. pi-vetter evaluates each candidate version against multiple evidence sources and reports an **ALLOW / ASK / DENY** verdict with the full evidence list, so you decide *what* to install — then installs exactly the versions you approved, leaving the update policy in your hands.

> pi-vetter can only show that **no risk signal was found** — it can never prove a package is safe. Read the evidence, not just the verdict.

## Install

```bash
pi install git:github.com/jesset/pi-vetter
```

(requires Node ≥ 22.19.0; no API keys needed — all default scanners are free)

## Usage

| Command | What it does |
|---|---|
| `/vet` | Read-only evaluation. No arguments = all installed packages with available updates; or pass specs: `/vet npm:foo npm:bar@1.2.3` |
| `/vet-install` | Same evaluation, then an interactive multi-select (TUI) or grouped confirms (non-TUI) and installs only what you approve |

Approved packages are installed via `pi install npm:<pkg>@<version>` — the exact vetted version, guarded by an integrity re-check before every install (TOCTOU). By default the settings entry is then restored to an unpinned spec (ADR-0003, revised): deciding to keep a package out of `pi update --extensions` is yours, not the evaluator's — the install result shows the exact pin command if you want it (`install.pinOnInstall: true` restores the legacy always-pin behaviour). Pinned packages are still evaluated on every `/vet` and marked as such in the report.

### Verdict model

- **ALLOW** — no risk signal found from enabled scanners
- **ASK** — a rule fired (e.g. new lifecycle script, new outbound endpoint, maintainer change) or evidence is incomplete
- **DENY** — hard evidence of malice/contradiction (OpenSSF malicious-package advisory, provenance conflict, VirusTotal detections)

Fail-closed: if any **enabled** scanner fails or times out, the verdict is capped at ASK — never a silent ALLOW (ADR-0002). An earned DENY is never downgraded. Verdicts are rule-driven; the 0–100 risk score is display-only (ADR-0001).

### Scanners (Phase 1)

| Layer | Scanner | Source |
|---|---|---|
| L0 | `metadata` | npm registry packument: maintainers (local snapshot diff), package age, release cadence, deprecation, downloads |
| L1 | `osv` | osv.dev querybatch — covers CVE + GitHub Advisories (GHSA) + OpenSSF malicious packages (MAL-); new dependencies are queried too |
| L1 | `provenance` | npm attestations: full sigstore signature-chain verification against a vendored public TrustedRoot, plus declared-repo conflict detection; verified bundles yield `provenance:verified` |
| L2 | `static` | pattern scan of code files: credential access, obfuscation, prompt-injection markers, eval family; pre-existing hits are info, new hits are findings; in the install scenario (no baseline) credential/obfuscation hits stay informational while prompt-injection remains a hard signal |
| L2 | `diff` | old-vs-new tarball comparison: new lifecycle scripts, new dependencies, new child_process usage, new outbound endpoints |
| L3 | `virustotal` | hash-first lookup, upload on miss (uploads of new files do not consume the daily quota); ≥2 engine detections → DENY. Disabled by default; enable with an API key |
| L3 | `socket` | Socket.dev package alerts (gptMalware, installScripts, obfuscatedFile, typosquatting...); high-risk alerts → ASK (`socket-flagged`). Disabled by default — note the free tier allows only ~5 purl scans/hour, so expect routine quota-exhaustion (which caps verdicts at ASK) if enabled |

Optional L3 engines are disabled by default and enabled per API key in the config file. When an enabled engine hits its quota or fails, the verdict is capped at ASK (fail-closed) and the evidence states why.

### Rules

Rules map evidence to verdicts and can be toggled individually in the config file (`ask.new-lifecycle-script: false` etc.). Current DENY rules: `malicious-package`, `provenance-conflict`, `vt-detections`. Current ASK rules: `known-vulnerability`, `new-lifecycle-script`, `maintainer-change`, `new-dependency-flagged`, `new-network-endpoint`, `new-child-process`, `credential-access`, `obfuscation`, `prompt-injection-marker`, `young-package`, `rapid-release`, `deprecated-candidate`.

## Configuration

`~/.pi/agent/pi-vetter/config.json` (created with defaults on first run; see [`config.example.json`](./config.example.json)):

```jsonc
{
  "scanners": { "osv": { "enabled": true, "timeoutMs": 10000 }, "virustotal": { "enabled": false, "apiKey": "" } },
  "rules": { "deny": {}, "ask": { "young-package": true } },
  "cache": { "enabled": true, "ttlHours": 24 },
  "score": { "weights": {} },
  "network": { "timeoutMs": 30000 },
  "install": { "pinOnInstall": false }
}
```

Scan results are cached per `scanner + pkg@version` under `~/.pi/agent/pi-vetter/cache/`; VirusTotal hash lookups are cached forever. Caching can be disabled entirely.

## Caveats

- Approving an install still executes the package's install scripts — Pi does not install with `--ignore-scripts`; pi-vetter warns but cannot prevent this.
- pi-vetter scans the package itself, not every transitive dependency tarball (deep scanning is Phase 2).
- Bootstrap supply chain: pi-vetter's own runtime dependencies (`@sigstore/bundle`, `@sigstore/verify`, `tar-stream`) are npm packages too and carry the same theoretical poisoning risk as anything it vets — the evaluator cannot lift itself above its own supply chain. Audit its lockfile like any other tool you grant full permissions.
- Non-npm sources (git/local) are out of scope for MVP.

## Development

```bash
npm install
npm run typecheck && npm test && npm run lint
node --experimental-strip-types scripts/smoke.ts npm:<pkg>   # real end-to-end vet
```

Design docs: [`docs/design.md`](./docs/design.md), ADRs in [`docs/adr/`](./docs/adr/), research in [`research/`](./research/).

## License

MIT
