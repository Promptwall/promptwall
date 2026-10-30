import type { Promptwall, Verdict, RequestOutcome } from "./index.js";
export { PromptwallBlockedError } from "./index.js";

export interface WrapOptions {
  /** The policy route to apply. Default: `default`, or else the first. */
  route?: string;
  /** Called for every check that found something, also in shadow mode. */
  onVerdict?: (verdict: Verdict | RequestOutcome) => void;
}

/**
 * The client with `chat.completions.create` checked by Promptwall: the
 * request before it is sent (blocked with `PromptwallBlockedError`, or
 * redacted), the answer before it is returned. Streamed answers are held
 * back until complete, then checked.
 */
export declare function wrapOpenAI<T extends { chat: { completions: { create: (...args: any[]) => any } } }>(
  client: T,
  promptwall: Promptwall,
  options?: WrapOptions,
): T;
