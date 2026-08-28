import { writeFileSync } from "node:fs";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { getTrustedRoot } from "@sigstore/tuf";

const root = await getTrustedRoot();
writeFileSync(
  new URL("../src/scanners/trusted-root.json", import.meta.url),
  `${JSON.stringify(TrustedRoot.toJSON(root), null, 2)}\n`,
);
console.error("trusted root dumped");
