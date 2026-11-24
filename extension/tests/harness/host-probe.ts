/**
 * Liveness probe for the real WP1 host binary.
 *
 * `FP_HOST=auto` runs this before choosing a host: a binary that does not
 * answer `ping` (for example the WP1 scaffold that only prints a TODO) is not
 * used, and the Node stub host takes over instead. `FP_HOST=real` turns a
 * failed probe into a clear test failure.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import { FrameDecoder, encodeFrame } from "./frames.mjs";

export interface HostProbe {
  ok: boolean;
  frame?: Record<string, unknown>;
  error?: string;
  stderr?: string;
}

export async function probeHostBinary(
  binary: string,
  options: { timeoutMs?: number; env?: Record<string, string> } = {},
): Promise<HostProbe> {
  if (!fs.existsSync(binary)) {
    return { ok: false, error: `host binary not found at ${binary}` };
  }

  const timeoutMs = options.timeoutMs ?? 2500;
  const child = spawn(binary, [], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ...options.env },
  });

  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr = `${stderr}${chunk.toString("utf8")}`.slice(-4096);
  });

  return await new Promise<HostProbe>((resolve) => {
    let settled = false;
    const decoder = new FrameDecoder();
    const finish = (probe: HostProbe) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
      resolve({ ...probe, stderr });
    };

    const timer = setTimeout(() => {
      finish({ ok: false, error: `no ping response within ${timeoutMs} ms` });
    }, timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      for (const decoded of decoder.push(chunk)) {
        if (decoded.type === "error") {
          finish({ ok: false, error: decoded.error });
          return;
        }
        if (decoded.value.action === "ping") {
          finish({ ok: true, frame: decoded.value });
          return;
        }
      }
    });

    child.on("error", (error) => {
      finish({ ok: false, error: String(error) });
    });
    child.on("exit", (code, signal) => {
      finish({
        ok: false,
        error: `host exited before answering ping (code ${code}, signal ${signal})`,
      });
    });

    try {
      child.stdin?.write(encodeFrame({ action: "ping" }));
    } catch (error) {
      finish({ ok: false, error: String(error) });
    }
  });
}
