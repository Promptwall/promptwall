// Builds the engine as WebAssembly (crates/wasm) and copies it, and the
// licence, next to the JavaScript. Needs Rust with the wasm32-unknown-unknown target:
//   rustup target add wasm32-unknown-unknown
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
execFileSync(
  "cargo",
  ["build", "--locked", "-p", "promptwall-wasm", "--target", "wasm32-unknown-unknown", "--profile", "wasm"],
  { cwd: root, stdio: "inherit" },
);
const from = new URL("../../../target/wasm32-unknown-unknown/wasm/promptwall_wasm.wasm", import.meta.url);
const to = new URL("../wasm/promptwall.wasm", import.meta.url);
mkdirSync(new URL("../wasm/", import.meta.url), { recursive: true });
copyFileSync(from, to);
copyFileSync(new URL("../../../LICENSE", import.meta.url), new URL("../LICENSE", import.meta.url));
console.log(`wasm/promptwall.wasm: ${Math.round(statSync(to).size / 1024)} KiB`);
