import { afterEach, describe, expect, it, vi } from "vitest";
import { DATA_DIR, dataDir } from "../src/config.ts";
import { downloadsApiBase, npmRegistryBase } from "../src/npm/registry.ts";
import { osvApiBase } from "../src/scanners/osv.ts";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("endpoint env overrides", () => {
  it("defaults to the public endpoints when unset", () => {
    expect(npmRegistryBase()).toBe("https://registry.npmjs.org");
    expect(downloadsApiBase()).toBe("https://api.npmjs.org/downloads/point/last-month");
    expect(osvApiBase()).toBe("https://api.osv.dev");
    expect(dataDir()).toBe(DATA_DIR);
  });

  it("reads overrides lazily at call time (private registries/mirrors, E2E)", () => {
    vi.stubEnv("PI_VETTER_NPM_REGISTRY", "https://mirror.example.com");
    vi.stubEnv("PI_VETTER_DOWNLOADS_API", "https://mirror.example.com/downloads/point/last-month");
    vi.stubEnv("PI_VETTER_OSV_API", "http://127.0.0.1:9/v1");
    vi.stubEnv("PI_VETTER_DATA_DIR", "/tmp/pi-vetter-test");
    expect(npmRegistryBase()).toBe("https://mirror.example.com");
    expect(downloadsApiBase()).toBe("https://mirror.example.com/downloads/point/last-month");
    expect(osvApiBase()).toBe("http://127.0.0.1:9/v1");
    expect(dataDir()).toBe("/tmp/pi-vetter-test");
    // precedence: explicit argument still wins over the environment
    expect(dataDir("/explicit/dir")).toBe("/explicit/dir");
  });
});
