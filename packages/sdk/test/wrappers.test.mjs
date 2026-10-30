import { test } from "node:test";
import assert from "node:assert/strict";

import { Promptwall, PromptwallBlockedError } from "../index.js";
import { wrapOpenAI } from "../openai.js";
import { promptwallMiddleware } from "../ai.js";
import { POLICY } from "./policy.mjs";

/** A stand-in for the OpenAI client that answers with `answer`. */
function fakeOpenAI(answer) {
  const sent = [];
  const client = {
    apiKey: "sk-test",
    chat: {
      completions: {
        async create(params) {
          sent.push(params);
          if (!params.stream) {
            return { choices: [{ index: 0, message: { role: "assistant", content: answer } }] };
          }
          return (async function* () {
            for (const piece of answer.match(/.{1,4}/gs)) {
              yield { choices: [{ index: 0, delta: { content: piece } }] };
            }
            yield { choices: [{ index: 0, delta: {}, finish_reason: "stop" }] };
          })();
        },
      },
    },
  };
  return { client, sent };
}

const ask = (content, extra = {}) => ({
  model: "gpt-4o",
  messages: [{ role: "user", content }],
  ...extra,
});

test("openai: redacts prompts and answers, blocks secrets", async () => {
  const pw = await Promptwall.load({ policy: POLICY });
  const { client, sent } = fakeOpenAI("Sure, I wrote to bob@corp.io.");
  const seen = [];
  const openai = wrapOpenAI(client, pw, { onVerdict: (v) => seen.push(v.action) });
  assert.equal(openai.apiKey, "sk-test");

  const res = await openai.chat.completions.create(ask("mail jane@corp.io"));
  assert.equal(sent[0].messages[0].content, "mail [REDACTED:EMAIL]");
  assert.equal(res.choices[0].message.content, "Sure, I wrote to [REDACTED:EMAIL].");
  assert.deepEqual(seen, ["redact", "redact"]);

  await assert.rejects(
    openai.chat.completions.create(ask("my key is AKIAIOSFODNN7EXAMPLE")),
    (err) => err instanceof PromptwallBlockedError && err.direction === "input",
  );
  assert.equal(sent.length, 1, "a blocked prompt is never sent");
});

test("openai: checks streamed answers whole", async () => {
  const pw = await Promptwall.load({ policy: POLICY });
  const openai = wrapOpenAI(fakeOpenAI("Write to bob@corp.io today").client, pw);
  let text = "";
  for await (const chunk of await openai.chat.completions.create(ask("hi", { stream: true }))) {
    text += chunk.choices[0].delta.content ?? "";
  }
  assert.equal(text, "Write to [REDACTED:EMAIL] today");

  const leaky = wrapOpenAI(fakeOpenAI("the key is AKIAIOSFODNN7EXAMPLE").client, pw);
  const stream = await leaky.chat.completions.create(ask("hi", { stream: true }));
  await assert.rejects(async () => {
    for await (const _ of stream);
  }, (err) => err instanceof PromptwallBlockedError && err.direction === "output");
});

test("openai: shadow mode reports but changes nothing", async () => {
  const pw = await Promptwall.load({ policy: POLICY, route: "shadow" });
  const { client, sent } = fakeOpenAI("ok");
  const seen = [];
  const openai = wrapOpenAI(client, pw, { onVerdict: (v) => seen.push(v.action) });
  await openai.chat.completions.create(ask("key AKIAIOSFODNN7EXAMPLE"));
  assert.equal(sent[0].messages[0].content, "key AKIAIOSFODNN7EXAMPLE");
  assert.deepEqual(seen, ["block"]);
});

test("ai sdk: middleware checks prompts, answers and streams", async () => {
  const pw = await Promptwall.load({ policy: POLICY });
  const mw = promptwallMiddleware(pw);
  const params = {
    prompt: [
      { role: "system", content: "Be brief." },
      { role: "user", content: [{ type: "text", text: "mail jane@corp.io" }] },
    ],
  };
  const sent = await mw.transformParams({ params, type: "generate" });
  assert.equal(sent.prompt[1].content[0].text, "mail [REDACTED:EMAIL]");
  assert.equal(params.prompt[1].content[0].text, "mail jane@corp.io", "the caller's params stay as they were");

  await assert.rejects(
    mw.transformParams({
      params: { prompt: [{ role: "user", content: [{ type: "text", text: "AKIAIOSFODNN7EXAMPLE" }] }] },
    }),
    PromptwallBlockedError,
  );

  const generated = await mw.wrapGenerate({
    doGenerate: async () => ({ content: [{ type: "text", text: "bob@corp.io" }], finishReason: "stop" }),
  });
  assert.equal(generated.content[0].text, "[REDACTED:EMAIL]");
  const v4 = await mw.wrapGenerate({ doGenerate: async () => ({ text: "bob@corp.io" }) });
  assert.equal(v4.text, "[REDACTED:EMAIL]");

  const parts = [
    { type: "text-start", id: "1" },
    { type: "text-delta", id: "1", delta: "write to bo" },
    { type: "text-delta", id: "1", delta: "b@corp.io now" },
    { type: "text-end", id: "1" },
    { type: "finish", finishReason: "stop" },
  ];
  const streamed = await mw.wrapStream({
    doStream: async () => ({ stream: ReadableStream.from(parts) }),
  });
  const out = [];
  for await (const part of streamed.stream) out.push(part);
  assert.equal(out.filter((p) => p.type === "text-delta").map((p) => p.delta).join(""), "write to [REDACTED:EMAIL] now");
  assert.equal(out.at(-1).type, "finish");

  const blocked = await mw.wrapStream({
    doStream: async () => ({
      stream: ReadableStream.from([{ type: "text-delta", textDelta: "AKIAIOSFODNN7EXAMPLE" }]),
    }),
  });
  const first = (await blocked.stream.getReader().read()).value;
  assert.equal(first.type, "error");
  assert.ok(first.error instanceof PromptwallBlockedError);
});
