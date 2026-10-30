export type Action = "flag" | "redact" | "block";
export type Direction = "input" | "output";

/** What a route does with one prompt or answer. */
export interface Verdict {
  /** The most severe action, or `null` when nothing was found. */
  action: Action | null;
  /** Finding labels, such as `pii.email`, and how often each was found. Never the values. */
  findings: Record<string, number>;
  /** The text as it would be sent on, with redactions. */
  text: string;
  route: string;
  direction: Direction;
  /** In shadow mode the wrappers only report; they block and redact nothing. */
  shadow: boolean;
  /** Model checks the route asks for that did not run (no server set). */
  models: string[];
  /** Model checks that failed on the server and were skipped (fail_mode: open). */
  unchecked?: string[];
}

export interface RouteInfo {
  name: string;
  fail_mode: "open" | "closed";
  shadow: boolean;
  /** Whether the route checks prompts. */
  input: boolean;
  /** Whether the route checks answers. */
  output: boolean;
  /** Tier 2 model checks per direction, such as `prompt_injection` or `pii`. */
  models: { input: string[]; output: string[] };
}

export interface ServerOptions {
  /** A Promptwall server started with `--check-api`, such as `http://promptwall:8080`. */
  url: string;
  /** The server's `PROMPTWALL_CHECK_TOKEN`, if it has one. */
  token?: string;
  /** Default 2000. */
  timeoutMs?: number;
}

export interface LoadOptions {
  /** The policy as YAML text, in the format of the proxy (docs/specs/policy-format.md). */
  policy?: string;
  /** Node only: a path to the policy file. */
  policyFile?: string;
  /** The route to use when a call names none. Default: `default`, or else the first. */
  route?: string;
  /** Runs the route's model checks on this server, after the pattern checks here. */
  server?: string | ServerOptions;
  /** The WebAssembly module, for runtimes that cannot load `wasm/promptwall.wasm` themselves. */
  wasm?: WebAssembly.Module | BufferSource;
  /** Used for calls to the server. Default: `globalThis.fetch`. */
  fetch?: typeof fetch;
}

export interface CheckOptions {
  route?: string;
  /** Default `input`. */
  direction?: Direction;
}

export interface RequestOutcome {
  action: Action | null;
  findings: Record<string, number>;
  /** The redacted request, if anything was redacted. */
  body?: unknown;
  route: string;
  shadow: boolean;
  models: string[];
}

export interface TestResult {
  name: string;
  failure?: string | null;
  skipped?: string;
}

export declare class Promptwall {
  static load(options: LoadOptions): Promise<Promptwall>;
  /** `sha256:` and the hash of the policy text. */
  readonly digest: string;
  readonly routes: RouteInfo[];
  route(name?: string): RouteInfo;
  /** Pattern checks only, in-process and synchronous (tens of microseconds). */
  checkLocal(text: string, options?: CheckOptions): Verdict;
  /** Pattern checks here, then the route's model checks on the server, if one is set. */
  check(text: string, options?: CheckOptions): Promise<Verdict>;
  /** Checks a whole request body the way the proxy does, patterns only. */
  inspectRequest(body: unknown, options?: { route?: string }): RequestOutcome;
  /** Runs the policy's `tests`; tests that need a model are skipped. */
  test(): TestResult[];
  /** Frees the policy. */
  close(): void;
}

export declare class PromptwallBlockedError extends Error {
  readonly verdict: Verdict | RequestOutcome;
  readonly direction: Direction;
}

export declare class PromptwallError extends Error {}

/** The stronger of two actions. */
export declare function strongest(a: Action | null, b: Action | null): Action | null;

/**
 * Applies a verdict: throws `PromptwallBlockedError` when it blocks, returns
 * the redacted text when it redacts, `undefined` otherwise or in shadow mode.
 */
export declare function enforce(
  verdict: Verdict,
  onVerdict?: (verdict: Verdict) => void,
): string | undefined;
