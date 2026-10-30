// The policy the tests load.
export const POLICY = `
version: 1
upstreams:
  openai: { url: "https://api.openai.com" }
routes:
  - name: default
    upstream: openai
    input:
      - { detector: secrets, action: block }
      - { detector: prompt_injection, action: block }
      - { detector: pii, entities: [email], action: redact }
    output:
      - { detector: pii, entities: [email], action: redact }
      - { detector: secrets, action: block }
  - name: shadow
    upstream: openai
    shadow: true
    input:
      - { detector: secrets, action: block }
  - name: closed
    upstream: openai
    fail_mode: closed
    input:
      - { detector: prompt_injection, action: block }
tests:
  - name: email
    route: default
    input: "mail jane@corp.io"
    expect: { action: redact, text: "mail [REDACTED:EMAIL]" }
`;
