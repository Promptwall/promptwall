# @promptwall-ai/sdk

[Promptwall](https://github.com/Promptwall/promptwall) in your JavaScript app: the same YAML policy and the same checks as the Promptwall proxy, compiled from the same Rust code to WebAssembly. Prompts are checked before they reach the model and answers before they reach your app: secrets and personal data are redacted or blocked, prompt injection is blocked, and custom patterns and keyword lists apply as in the proxy.

- **No proxy, no cloud.** Checks run in your process, in about 40 µs for a short prompt. Nothing is sent anywhere.
- **Runs where JavaScript runs:** Node 18+, Vercel and Supabase functions, Cloudflare Workers, Deno, Bun, browsers. No native modules.
- **Model checks when you want them.** The pattern checks (Tier 1) run here; the model checks (Tier 2: the prompt-injection classifier, content safety, topics, names and addresses) need CPU and model files, so they run on your own Promptwall server through its [check API](#check-api).

## Install

```sh
npm install @promptwall-ai/sdk
```

## Use

Write a policy (`promptwall init` asks a few questions and writes one, and the [policy format](https://github.com/Promptwall/promptwall/blob/main/docs/specs/policy-format.md) describes it all), or start with this:

```yaml
version: 1
upstreams:
  openai: { url: "https://api.openai.com" }   # used by the proxy; the package ignores it
routes:
  - name: default
    upstream: openai
    input:
      - { detector: prompt_injection, action: block }
      - { detector: secrets, action: block }
      - { detector: pii, action: redact }
    output:
      - { detector: secrets, action: block }
      - { detector: pii, entities: [email, credit_card, iban], action: redact }
```

### OpenAI

```js
import OpenAI from "openai";
import { Promptwall, PromptwallBlockedError } from "@promptwall-ai/sdk";
import { wrapOpenAI } from "@promptwall-ai/sdk/openai";

const pw = await Promptwall.load({ policyFile: "promptwall.yaml" });
const openai = wrapOpenAI(new OpenAI(), pw);

try {
  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Mail jane@corp.io the report" }],
  });
  // The model saw "Mail [REDACTED:EMAIL] the report".
} catch (err) {
  if (err instanceof PromptwallBlockedError) {
    console.log(err.direction, err.verdict.findings);   // "input", { "secret.aws_access_key": 1 }
  } else throw err;
}
```

`chat.completions.create` is checked; everything else on the client passes through. The request is checked as a whole, the way the proxy checks it: user and tool messages, not the app's own system prompt. Streamed answers are held back until complete and then checked, so a redaction or a block is never too late; the text then arrives in one piece.

### Vercel AI SDK

```js
import { generateText, streamText, wrapLanguageModel } from "ai";
import { openai } from "@ai-sdk/openai";
import { Promptwall } from "@promptwall-ai/sdk";
import { promptwallMiddleware } from "@promptwall-ai/sdk/ai";

const pw = await Promptwall.load({ policy: process.env.PROMPTWALL_POLICY });
const model = wrapLanguageModel({ model: openai("gpt-4o-mini"), middleware: promptwallMiddleware(pw) });

const { text } = await generateText({ model, prompt: "Mail jane@corp.io the report" });
```

`generateText` and `streamText` are both checked. A block throws `PromptwallBlockedError` (in a stream, as an error part).

### Any text

```js
const v = pw.checkLocal("my key is AKIAIOSFODNN7EXAMPLE");
// { action: "block", findings: { "secret.aws_access_key": 1 }, text: "...", route: "default", ... }

const answer = await pw.check(modelAnswer, { direction: "output" });   // with model checks, if a server is set
if (answer.action === "redact") show(answer.text);
```

`action` is `null` when nothing was found, else `flag`, `redact` or `block`. `findings` has labels and counts, never the values. `pw.inspectRequest(body)` checks a whole request body like the proxy; `pw.test()` runs the `tests` in the policy file.

### Options

| `Promptwall.load` option | Meaning |
| --- | --- |
| `policy` | The policy as YAML text |
| `policyFile` | Node only: a path to the policy file |
| `route` | The route to apply when a call names none. Default: the route named `default`, else the first |
| `server` | A Promptwall server for the model checks: a URL, or `{ url, token, timeoutMs }` |
| `wasm` | The WebAssembly module (a `WebAssembly.Module` or bytes), for runtimes that cannot load `@promptwall-ai/sdk/wasm/promptwall.wasm` themselves |

`wrapOpenAI(client, pw, options)` and `promptwallMiddleware(pw, options)` take `route` and `onVerdict`, a function called with every verdict that found something, for your own logging. Routes with `shadow: true` only report through `onVerdict`; nothing is blocked or changed.

## Check API

For the model checks, run the Promptwall server with the check API on and the same policy file (so the route names match), and point the package at it:

```sh
PROMPTWALL_CHECK_TOKEN=$(openssl rand -hex 32) \
  promptwall --policy promptwall.yaml --check-api --injection-model models/injection
```

```js
const pw = await Promptwall.load({
  policyFile: "promptwall.yaml",
  server: { url: "http://promptwall:8080", token: process.env.PROMPTWALL_CHECK_TOKEN },
});
```

The patterns run in-process first. Only when they let the text pass and the route uses a model does the package call the server, with the already redacted text. When the server cannot be reached, the route's `fail_mode` decides: `open` keeps the local verdict and lists the skipped checks in `unchecked`, `closed` throws.

The API is one call, which other languages can use too:

```http
POST /promptwall/v1/check
Authorization: Bearer <PROMPTWALL_CHECK_TOKEN>
Content-Type: application/json

{"route": "default", "direction": "input", "text": "Mail jane@corp.io the report"}
```

```json
{"action": "redact", "findings": {"pii.email": 1}, "text": "Mail [REDACTED:EMAIL] the report", "route": "default"}
```

`route` is optional (the route named `default`, else the first) and `direction` is `input` (a prompt, the default) or `output` (an answer). A blocked text is still a successful call (200). Errors: 401 without the right token, 404 for an unknown route, 400 for a malformed request. The API is off unless `--check-api` (or `PROMPTWALL_CHECK_API=true`) is set; without a token, keep the port off the public network. Calls are counted in `promptwall_checks_total`.

## Build from source

Needs Rust with the WebAssembly target and Node 18+:

```sh
rustup target add wasm32-unknown-unknown
cd packages/sdk
npm run build    # builds crates/wasm into wasm/promptwall.wasm
npm test         # PROMPTWALL_BIN=path/to/promptwall also tests against a real server
```

## Licence

Apache-2.0
