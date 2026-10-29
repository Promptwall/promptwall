# Contributing to Promptwall

Thanks for your interest in Promptwall. The project is in its design phase, so the most useful contributions right now are reviews of the specs in [`docs/specs`](docs/specs).

## Contributor Licence Agreement

All contributions require a signed Contributor Licence Agreement (CLA) before they can be merged. The CLA lets the project be relicensed or offered commercially alongside the open source edition while you keep the copyright to your work. A bot will ask you to sign on your first pull request.

> **TODO:** choose the CLA text (for example the Apache Individual and Corporate CLAs) and set up CLA Assistant before the repository becomes public.

## How changes flow

- This repository is the single source of truth for the engine, the open rules and detectors, the policy format and the plugin interface.
- Commercial modules live in a separate private repository. They depend on a pinned release of this one and never modify its code or rules. Changes to anything shared always land here first.

## Pull requests

- Keep each pull request focused on one change.
- Specs and docs use plain, short sentences.
- Once code exists, every change must pass the benchmark gate described in [`docs/specs/benchmark.md`](docs/specs/benchmark.md).
