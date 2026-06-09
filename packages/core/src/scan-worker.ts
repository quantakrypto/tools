/**
 * Worker-thread entry for {@link scanParallel}. Built to `dist/scan-worker.js`
 * and spawned by `parallel.ts`. Each worker reads its assigned files and runs
 * the SAME pure detector pipeline as the serial scan (`detectFile`), returning
 * `{ findings, filesScanned }` per chunk. No shared mutable state.
 *
 * This file performs side effects (wires up message handlers) only when it is
 * actually running inside a worker thread, so importing it from the main thread
 * (e.g. for coverage) is harmless.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { parentPort, workerData } from "node:worker_threads";

import type { Finding } from "./types.js";
import { defaultRegistry } from "./registry.js";
import { detectFile } from "./scan.js";
import { looksMinified } from "./walk.js";
import { isManifestFile } from "./dependencies.js";

interface WorkerToggles {
  source: boolean;
  config: boolean;
  deps: boolean;
  scanMinified: boolean;
}

interface ChunkRequest {
  index: number;
  files: string[];
}

if (parentPort) {
  const data = (workerData ?? {}) as { baseDir: string; toggles: WorkerToggles };
  const baseDir = data.baseDir;
  const toggles = data.toggles;
  const dets = defaultRegistry.all();
  const port = parentPort;

  port.on("message", (req: ChunkRequest) => {
    try {
      const findings: Finding[] = [];
      let filesScanned = 0;
      const scannedNames: string[] = [];

      for (const rel of req.files) {
        const abs = path.join(baseDir, ...rel.split("/"));
        let content: string;
        try {
          content = readFileSync(abs, "utf8");
        } catch {
          continue; // vanished / unreadable — skip.
        }
        if (!toggles.scanMinified && !isManifestFile(rel) && looksMinified(content)) {
          continue;
        }
        filesScanned += 1;
        scannedNames.push(rel);
        findings.push(
          ...detectFile(rel, content, dets, {
            source: toggles.source,
            config: toggles.config,
            deps: toggles.deps,
          }),
        );
      }

      port.postMessage({
        index: req.index,
        files: scannedNames,
        result: { findings, filesScanned },
      });
    } catch (err) {
      port.postMessage({
        index: req.index,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });
}
