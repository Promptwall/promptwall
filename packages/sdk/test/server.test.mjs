// Against a real Promptwall server with the check API. Runs when
// PROMPTWALL_BIN names a promptwall binary (CI builds one).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";

import { Promptwall } from "../index.js";
import { POLICY } from "./policy.mjs";

const bin = process.env.PROMPTWALL_BIN;

async function freePort() {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  return port;
}

test("checks through the check API of a real server", { skip: !bin && "PROMPTWALL_BIN not set" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "pw-sdk-"));
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, POLICY);
  const port = await freePort();
  const child = spawn(bin, ["--policy", policy, "--listen", `127.0.0.1:${port}`, "--check-api"], {
    env: { ...process.env, PROMPTWALL_CHECK_TOKEN: "t0k" },
    stdio: "ignore",
  });
  try {
    const url = `http://127.0.0.1:${port}`;
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${url}/healthz`)).ok) break;
      } catch {}
      if (i > 100) throw new Error("the server did not start");
      await new Promise((r) => setTimeout(r, 100));
    }
    const pw = await Promptwall.load({ policy: POLICY, server: { url, token: "t0k" } });
    const v = await pw.check("mail jane@corp.io");
    assert.equal(v.action, "redact");
    assert.equal(v.text, "mail [REDACTED:EMAIL]");
    assert.deepEqual(v.models, []);
    assert.equal(v.unchecked, undefined, "the server answered");

    const remote = await pw.remoteCheck("key AKIAIOSFODNN7EXAMPLE", "default", "input");
    assert.equal(remote.action, "block");

    const wrong = await Promptwall.load({ policy: POLICY, server: { url, token: "nope" } });
    await assert.rejects(wrong.check("hello", { route: "closed" }), /bearer token/);
  } finally {
    child.kill();
  }
});
