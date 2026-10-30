// The OpenAI client with Promptwall in front: `chat.completions.create`
// checks the request before it is sent and the answer before it is returned.

import { enforce, PromptwallBlockedError } from "./index.js";

/** Roles whose messages come from users or tools rather than from the app. */
const UNTRUSTED = new Set(["user", "tool", "function"]);

/**
 * Wraps an OpenAI client (the `openai` package, or any client with the same
 * `chat.completions.create`). Other methods pass through unchanged.
 */
export function wrapOpenAI(client, promptwall, options = {}) {
  const completions = client.chat.completions;
  const create = completions.create.bind(completions);
  const wrapped = {
    create: (params, requestOptions) => guardedCreate(create, promptwall, options, params, requestOptions),
  };
  const chat = new Proxy(client.chat, {
    get: (target, prop, receiver) => (prop === "completions" ? withMethods(completions, wrapped) : Reflect.get(target, prop, receiver)),
  });
  return new Proxy(client, {
    get: (target, prop, receiver) => (prop === "chat" ? chat : Reflect.get(target, prop, receiver)),
  });
}

function withMethods(target, methods) {
  return new Proxy(target, {
    get: (t, prop, receiver) => (prop in methods ? methods[prop] : Reflect.get(t, prop, receiver)),
  });
}

async function guardedCreate(create, pw, options, params, requestOptions) {
  const route = pw.route(options.route);
  params = await checkRequest(pw, route, options, params);
  const result = await create(params, requestOptions);
  if (!route.output) return result;
  if (params.stream) return checkStream(pw, route, options, result);
  for (const choice of result.choices ?? []) {
    const content = choice.message?.content;
    if (typeof content !== "string" || content === "") continue;
    const v = await pw.check(content, { route: route.name, direction: "output" });
    const text = enforce(v, options.onVerdict);
    if (text !== undefined) choice.message.content = text;
  }
  return result;
}

/** Checks the request body as the proxy would; returns the one to send. */
async function checkRequest(pw, route, options, params) {
  if (!route.input) return params;
  const outcome = pw.inspectRequest(params, { route: route.name });
  // Throws when it blocks; the redacted body then replaces the request.
  enforce({ ...outcome, direction: "input" }, options.onVerdict);
  if (outcome.action === "redact" && !outcome.shadow) params = outcome.body;
  if (!pw.server || outcome.models.length === 0) return params;
  // The models run on the server, one message part at a time.
  const messages = structuredClone(params.messages ?? []);
  const jobs = [];
  for (const message of messages) {
    if (!UNTRUSTED.has(message.role)) continue;
    if (typeof message.content === "string") {
      jobs.push(checkPart(pw, route, options, message.content, (t) => (message.content = t)));
    } else if (Array.isArray(message.content)) {
      for (const part of message.content) {
        if (part?.type === "text" && typeof part.text === "string") {
          jobs.push(checkPart(pw, route, options, part.text, (t) => (part.text = t)));
        }
      }
    }
  }
  await Promise.all(jobs);
  return { ...params, messages };
}

async function checkPart(pw, route, options, text, set) {
  const v = await pw.check(text, { route: route.name });
  const replaced = enforce(v, options.onVerdict);
  if (replaced !== undefined) set(replaced);
}

/**
 * Streams are held back until the answer is complete, then checked whole:
 * a block throws instead of the first chunk, a redaction sends the redacted
 * text in the first chunk of each choice.
 */
async function* checkStream(pw, route, options, stream) {
  const chunks = [];
  const texts = new Map();
  for await (const chunk of stream) {
    chunks.push(chunk);
    for (const choice of chunk.choices ?? []) {
      const delta = choice.delta?.content;
      if (typeof delta === "string") texts.set(choice.index, (texts.get(choice.index) ?? "") + delta);
    }
  }
  const replaced = new Map();
  for (const [index, text] of texts) {
    if (text === "") continue;
    const v = await pw.check(text, { route: route.name, direction: "output" });
    const t = enforce(v, options.onVerdict);
    if (t !== undefined) replaced.set(index, t);
  }
  const first = new Set();
  for (const chunk of chunks) {
    for (const choice of chunk.choices ?? []) {
      if (!replaced.has(choice.index) || typeof choice.delta?.content !== "string") continue;
      choice.delta.content = first.has(choice.index) ? "" : replaced.get(choice.index);
      first.add(choice.index);
    }
    yield chunk;
  }
}

export { PromptwallBlockedError };
