import type { Promptwall, Verdict } from "./index.js";

export interface MiddlewareOptions {
  /** The policy route to apply. Default: `default`, or else the first. */
  route?: string;
  /** Called for every check that found something, also in shadow mode. */
  onVerdict?: (verdict: Verdict) => void;
}

/**
 * Middleware for `wrapLanguageModel` of the Vercel AI SDK. Typed loosely so
 * that it fits the middleware versions of AI SDK 4 and 5 alike.
 */
export declare function promptwallMiddleware(
  promptwall: Promptwall,
  options?: MiddlewareOptions,
): {
  transformParams: (options: { params: any; type?: string }) => Promise<any>;
  wrapGenerate: (options: { doGenerate: () => Promise<any>; params?: any }) => Promise<any>;
  wrapStream: (options: { doStream: () => Promise<any>; params?: any }) => Promise<any>;
};
