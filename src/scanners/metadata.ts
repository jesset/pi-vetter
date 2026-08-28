import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";

export interface MaintainerSnapshotStore {
  read(name: string): Promise<string[] | null>;
  write(name: string, ids: string[]): Promise<void>;
}

export function createMetadataScanner(
  snapshots: MaintainerSnapshotStore | null = null,
  now = Date.now(),
): SecurityScanner {
  return {
    name: "metadata",
    layer: 0,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      const { candidate, artifacts } = ctx;
      const packument = artifacts.candidatePackument;
      const evidences: Evidence[] = [];

      const created = packument.time?.created ? Date.parse(packument.time.created) : NaN;
      const ageDays = Number.isFinite(created) ? (now - created) / 86_400_000 : null;
      if (ageDays !== null && ageDays < 7) {
        evidences.push({
          scanner: "metadata",
          key: "metadata:young-package",
          status: "fail",
          detail: `package created ${Math.max(0, Math.floor(ageDays))} day(s) ago`,
        });
      }

      const releaseTimes = Object.entries(packument.time ?? {})
        .filter(([k]) => k !== "created" && k !== "modified")
        .map(([, v]) => Date.parse(v))
        .filter((t) => Number.isFinite(t))
        .sort((a, b) => b - a);
      const dayAgo = now - 86_400_000;
      if (releaseTimes.filter((t) => t >= dayAgo).length >= 3) {
        evidences.push({
          scanner: "metadata",
          key: "metadata:rapid-release",
          status: "fail",
          detail: `${releaseTimes.filter((t) => t >= dayAgo).length} releases within 24h`,
        });
      }

      const versionMeta = packument.versions[candidate.version];
      if (versionMeta?.deprecated) {
        evidences.push({
          scanner: "metadata",
          key: "metadata:deprecated",
          status: "fail",
          detail: `candidate version is deprecated: ${versionMeta.deprecated}`,
        });
      }

      if (snapshots) {
        const ids = (packument.maintainers ?? []).map((m) => m.username ?? m.name ?? m.email ?? "");
        const known = await snapshots.read(packument.name);
        if (known !== null && known.length > 0) {
          const added = ids.filter((id) => !known.includes(id));
          if (added.length > 0) {
            evidences.push({
              scanner: "metadata",
              key: "metadata:maintainer-change",
              status: "fail",
              detail: `new maintainer(s) since last vet: ${added.join(", ")}`,
              data: { known, current: ids },
            });
          } else {
            evidences.push({
              scanner: "metadata",
              key: "metadata:maintainers-stable",
              status: "pass",
              detail: `maintainers unchanged: ${ids.join(", ")}`,
            });
          }
        } else {
          evidences.push({
            scanner: "metadata",
            key: "metadata:maintainers-recorded",
            status: "info",
            detail: `first vet for this package; maintainers recorded: ${ids.join(", ") || "(none listed)"}`,
          });
        }
        await snapshots.write(packument.name, ids);
      }

      evidences.push({
        scanner: "metadata",
        key: "metadata:downloads",
        status: "info",
        detail: `${artifacts.downloads} downloads in the last month; ${Object.keys(packument.versions ?? {}).length} versions published`,
      });

      return { scanner: "metadata", status: "ok", evidences };
    },
  };
}
