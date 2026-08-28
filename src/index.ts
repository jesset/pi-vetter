import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI): void {
  pi.registerCommand("vet", {
    description: "Evaluate pending extension updates or a specific package (read-only)",
    handler: async () => {},
  });

  pi.registerCommand("vet-install", {
    description: "Evaluate, then interactively install approved packages",
    handler: async () => {},
  });
}
