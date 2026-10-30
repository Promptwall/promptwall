// Promptwall for JavaScript: the pattern checks of a Promptwall policy, run
// in-process as WebAssembly (the same Rust code as the proxy), plus the
// model checks of your own Promptwall server when you point it at one.

const SEVERITY = { flag: 1, redact: 2, block: 3 };

/** Raised when a policy blocks a prompt or an answer. */
export class PromptwallBlockedError extends Error {
  constructor(verdict, direction) {
    const labels = Object.keys(verdict.findings).join(", ");
    super(`Promptwall blocked the ${direction === "output" ? "answer" : "prompt"}${labels ? ` (${labels})` : ""}`);
    this.name = "PromptwallBlockedError";
    this.verdict = verdict;
    this.direction = direction;
  }
}

/** Raised when a check cannot be done: a bad policy, or a server that fails. */
export class PromptwallError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "PromptwallError";
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let modulePromise;

/** Compiles the WebAssembly module once per process. */
function compiledModule(source) {
  if (source instanceof WebAssembly.Module) return Promise.resolve(source);
  if (source) return WebAssembly.compile(source);
  modulePromise ??= (async () => {
    const url = new URL("./wasm/promptwall.wasm", import.meta.url);
    if (url.protocol === "file:") {
      const { readFile } = await import("node:fs/promises");
      return WebAssembly.compile(await readFile(url));
    }
    const resp = await fetch(url);
    if (!resp.ok) throw new PromptwallError(`cannot load ${url}: ${resp.status}`);
    return WebAssembly.compile(await resp.arrayBuffer());
  })();
  return modulePromise;
}

/** One instance of the engine: its memory and its JSON call. */
class Engine {
  constructor(instance) {
    this.exports = instance.exports;
  }

  call(request) {
    const e = this.exports;
    const bytes = encoder.encode(JSON.stringify(request));
    const ptr = e.pw_alloc(bytes.length);
    new Uint8Array(e.memory.buffer, ptr, bytes.length).set(bytes);
    const status = e.pw_call(ptr, bytes.length);
    // Read the memory only now: the call may have grown it.
    const out = decoder.decode(new Uint8Array(e.memory.buffer, e.pw_out_ptr(), e.pw_out_len()));
    if (status !== 0) throw new PromptwallError(out);
    return JSON.parse(out);
  }
}

/** The stronger of two actions; `null` means nothing was found. */
export function strongest(a, b) {
  return (SEVERITY[b] ?? 0) > (SEVERITY[a] ?? 0) ? b : (a ?? null);
}

export class Promptwall {
  /**
   * Loads a policy: `policy` (YAML text) or, in Node, `policyFile` (a path).
   * `server` adds the model checks of a Promptwall server started with
   * `--check-api`.
   */
  static async load(options = {}) {
    let { policy } = options;
    if (policy === undefined && options.policyFile !== undefined) {
      const { readFile } = await import("node:fs/promises");
      policy = await readFile(options.policyFile, "utf8");
    }
    if (typeof policy !== "string") {
      throw new PromptwallError("pass the policy as YAML text (policy) or a file (policyFile)");
    }
    const module = await compiledModule(options.wasm);
    const engine = new Engine(await WebAssembly.instantiate(module, {}));
    const loaded = engine.call({ op: "load", policy });
    return new Promptwall(engine, loaded, options);
  }

  constructor(engine, loaded, options) {
    this.engine = engine;
    this.handle = loaded.handle;
    /** `sha256:` and the hash of the policy text, as in the proxy's decision log. */
    this.digest = loaded.digest;
    /** The policy's routes: name, fail_mode, shadow, and which checks they have. */
    this.routes = loaded.routes;
    this.defaultRoute = options.route;
    this.server = options.server ? normalizeServer(options.server) : undefined;
    this.fetch = options.fetch ?? globalThis.fetch;
  }

  /** The route a call uses: the one asked for, the default one, or the first. */
  route(name = this.defaultRoute) {
    const route = name === undefined
      ? (this.routes.find((r) => r.name === "default") ?? this.routes[0])
      : this.routes.find((r) => r.name === name);
    if (!route) throw new PromptwallError(`no route named ${JSON.stringify(name ?? "default")}`);
    return route;
  }

  /**
   * Checks a prompt (`direction: "input"`, the default) or an answer
   * (`"output"`) with the patterns only, in-process.
   */
  checkLocal(text, options = {}) {
    const route = this.route(options.route);
    const direction = options.direction ?? "input";
    const v = this.engine.call({ op: "check", handle: this.handle, route: route.name, direction, text });
    return verdict(v, route, direction);
  }

  /**
   * Checks a prompt or an answer: the patterns in-process and then, if the
   * route uses models and a server is set, the models on the server.
   */
  async check(text, options = {}) {
    const local = this.checkLocal(text, options);
    if (local.action === "block" || !this.server || local.models.length === 0) return local;
    let remote;
    try {
      remote = await this.remoteCheck(local.text, local.route, local.direction);
    } catch (err) {
      if (this.route(local.route).fail_mode === "closed") {
        throw new PromptwallError(`model check failed: ${err.message}`, { cause: err });
      }
      return { ...local, unchecked: local.models };
    }
    const findings = { ...local.findings };
    for (const [label, n] of Object.entries(remote.findings ?? {})) {
      findings[label] = Math.max(findings[label] ?? 0, n);
    }
    const action = strongest(local.action, remote.action ?? null);
    return {
      ...local,
      action,
      findings,
      // The server checked the locally redacted text, so its text has both.
      text: action === "redact" ? remote.text : text,
      models: [],
    };
  }

  async remoteCheck(text, route, direction) {
    const headers = { "content-type": "application/json" };
    if (this.server.token) headers.authorization = `Bearer ${this.server.token}`;
    const resp = await this.fetch(this.server.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ route, direction, text }),
      signal: AbortSignal.timeout(this.server.timeoutMs),
    });
    const body = await resp.json().catch(() => null);
    if (!resp.ok) throw new Error(body?.error?.message ?? `server answered ${resp.status}`);
    return body;
  }

  /**
   * Checks a whole request body (an object or JSON text) the way the proxy
   * does, patterns only: `{action, findings, body}`, where `body` is the
   * redacted request, if anything was redacted.
   */
  inspectRequest(body, options = {}) {
    const route = this.route(options.route);
    const json = typeof body === "string" ? body : JSON.stringify(body);
    const v = this.engine.call({ op: "inspect", handle: this.handle, route: route.name, body: json });
    return {
      action: v.action ?? null,
      findings: v.findings,
      body: v.body == null ? undefined : JSON.parse(v.body),
      route: route.name,
      shadow: route.shadow,
      models: v.models,
    };
  }

  /** Runs the policy's `tests`; tests on routes that need a model are skipped. */
  test() {
    return this.engine.call({ op: "test", handle: this.handle });
  }

  /** Frees the policy. */
  close() {
    this.engine.call({ op: "drop", handle: this.handle });
  }
}

function verdict(v, route, direction) {
  return {
    action: v.action ?? null,
    findings: v.findings,
    text: v.text,
    route: route.name,
    direction,
    shadow: route.shadow,
    models: v.models,
  };
}

function normalizeServer(server) {
  const s = typeof server === "string" ? { url: server } : { ...server };
  const url = new URL(s.url);
  if (url.pathname === "/" || url.pathname === "") url.pathname = "/promptwall/v1/check";
  return { url: url.toString(), token: s.token, timeoutMs: s.timeoutMs ?? 2000 };
}

/**
 * What a wrapper does with a verdict: throws when it blocks, returns the text
 * to use otherwise. In shadow mode nothing is changed. `onVerdict` sees every
 * verdict with findings.
 */
export function enforce(v, onVerdict) {
  if (v.action) onVerdict?.(v);
  if (v.shadow) return undefined;
  if (v.action === "block") throw new PromptwallBlockedError(v, v.direction);
  return v.action === "redact" ? v.text : undefined;
}
