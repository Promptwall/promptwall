// Promptwall as middleware for the Vercel AI SDK:
//
//   const model = wrapLanguageModel({ model: openai("gpt-4o"), middleware: promptwallMiddleware(pw) });
//
// Prompts are checked before the model sees them and answers before the app
// does, with generateText and streamText alike.

import { enforce } from "./index.js";

export function promptwallMiddleware(promptwall, options = {}) {
  const route = () => promptwall.route(options.route);
  return {
    transformParams: async ({ params }) => {
      const r = route();
      if (!r.input) return params;
      const prompt = structuredClone(params.prompt);
      const jobs = [];
      const check = (text, set) =>
        jobs.push(
          promptwall.check(text, { route: r.name }).then((v) => {
            const t = enforce(v, options.onVerdict);
            if (t !== undefined) set(t);
          }),
        );
      for (const message of prompt) {
        if (!Array.isArray(message.content)) continue; // the app's own system prompt
        for (const part of message.content) {
          if (message.role === "user" && part.type === "text") {
            check(part.text, (t) => (part.text = t));
          } else if (message.role === "tool" && part.type === "tool-result" && part.output?.type === "text") {
            check(part.output.value, (t) => (part.output.value = t));
          }
        }
      }
      await Promise.all(jobs);
      return { ...params, prompt };
    },

    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      const r = route();
      if (!r.output) return result;
      const answer = (text) => promptwall.check(text, { route: r.name, direction: "output" });
      if (Array.isArray(result.content)) {
        for (const part of result.content) {
          if (part.type !== "text" || !part.text) continue;
          const t = enforce(await answer(part.text), options.onVerdict);
          if (t !== undefined) part.text = t;
        }
      } else if (typeof result.text === "string" && result.text) {
        const t = enforce(await answer(result.text), options.onVerdict);
        if (t !== undefined) result.text = t;
      }
      return result;
    },

    // The answer is held back until it is complete, then checked whole; a
    // block ends the stream with an error, a redaction sends the redacted text
    // in the first delta.
    wrapStream: async ({ doStream }) => {
      const result = await doStream();
      const r = route();
      if (!r.output) return result;
      const parts = [];
      const reader = result.stream.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
      }
      const texts = new Map();
      for (const part of parts) {
        if (part.type !== "text-delta") continue;
        const id = part.id ?? "";
        texts.set(id, (texts.get(id) ?? "") + (part.delta ?? part.textDelta ?? ""));
      }
      let error;
      const replaced = new Map();
      try {
        for (const [id, text] of texts) {
          if (!text) continue;
          const v = await promptwall.check(text, { route: r.name, direction: "output" });
          const t = enforce(v, options.onVerdict);
          if (t !== undefined) replaced.set(id, t);
        }
      } catch (err) {
        error = err;
      }
      const sent = new Set();
      const stream = new ReadableStream({
        start(controller) {
          if (error) {
            controller.enqueue({ type: "error", error });
            controller.close();
            return;
          }
          for (const part of parts) {
            const id = part.id ?? "";
            if (part.type === "text-delta" && replaced.has(id)) {
              const text = sent.has(id) ? "" : replaced.get(id);
              sent.add(id);
              controller.enqueue("delta" in part ? { ...part, delta: text } : { ...part, textDelta: text });
            } else {
              controller.enqueue(part);
            }
          }
          controller.close();
        },
      });
      return { ...result, stream };
    },
  };
}
