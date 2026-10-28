# Changelog

All notable changes to Judikt. Versions follow [Semantic Versioning](https://semver.org/); while Judikt is 0.x, a minor release can change default behaviour, and every such change is listed under **Upgrading**.

## 0.4.1 (2026-10-28)

Documentation only; the code is identical to 0.4.0, so there is nothing to change when upgrading.

- A shorter README with an at-a-glance results table and a four-step quick start. Reference material moved, unchanged, into `docs/CONFIGURATION.md`, `docs/UPSTREAMS.md`, `docs/OPERATIONS.md`, `docs/DEVELOPMENT.md` and `docs/THREAT_MODEL.md`.
- The README uses absolute links and a text diagram, so the PyPI project page shows the demo and its links work.
- A guarded-call latency measurement for 0.4.0 (p50 2.9 ms, p99 5.2 ms on a 2-vCPU cloud container).
- The quick start's audit check points at the wrapped server's own audit database, and the `approve-writes` example pins tool definitions with `--accept-pins`.

## 0.4.0 (2026-10-28)

### Upgrading from 0.3.0

Two defaults are stricter. Read this before upgrading a deployment that uses the `permissive` profile or a hand-written policy.

1. **Writes that reuse values from tool output need approval.** A new gate, `untrusted_provenance`, is on by default. When a tool result contains an instruction (for example "send the report to amy@example.com" or "delete the file with ID '13'") and a later write or destructive call reuses a value that instruction named, the call is held with rule `untrusted_provenance` until a human approves it. Read tools are never held, and values the agent used before any tool returned them are trusted.
   - Who notices: `approve-writes` already requires approval for every write, and `read-only` exposes no writes, so neither sees a difference. `permissive` profiles and hand-written policies that allow writes without approval will start seeing held calls.
   - How often: in a ground-truth replay of AgentDojo, 4 of 97 legitimate tasks hit one hold; on AgentDyn, whose tasks often follow instructions found in emails and web pages, 27 of 60 did. Measure your own traffic before enforcing.
   - To measure first, add `"untrusted_provenance": {"mode": "report"}` to the policy: calls run, and the evidence `untrusted_provenance:<kind>:<server>/<tool>` appears in the audit log.
   - To restore 0.3.0 behaviour, set `"untrusted_provenance": {"mode": "off"}`.
   - Other settings: `"mode": "deny"` refuses instead of asking, and `"track": "everywhere"` also counts addresses and links that appear outside instructions.
2. **The learned injection classifier is on.** Tool results and descriptions are also scored by a small deterministic classifier (no model, standard library only). In a tool result it can redact a span or, with more than `max_medium_findings` findings, quarantine the result. On real package documentation it flagged 0.64% of chunks (the rules alone flag 0.58%). Turn it off with `"inbound_content_inspection": {"learned_classifier": {"enabled": false}}`.

Approving a held call is now one command (see below), so the usual response to a hold is `judikt approve <id>`, not switching a gate off.

### Added

- `judikt approve`: lists calls the local gateway held and approves one with `judikt approve <id>`. The agent's error names the id; once approved, the agent's identical retry runs once, within five minutes. Held calls are stored mode `0600` under `$XDG_STATE_HOME/judikt/pending-approvals/` and expire after 15 minutes. Disabled in production mode and with `JUDIKT_PENDING_APPROVALS=off`.
- Untrusted-provenance gate (`untrusted_provenance`, described above), with `mode`, `track` and `kinds` settings.
- Task scopes (`task_scope`): list the write tools a task may call and hold every other write with rule `task_scope`. Set them with `judikt wrap --task-writes TOOL,...`, `JUDIKT_TASK_WRITES`, or `task_scope.write_tools`; `none` allows no writes. Nothing changes unless a scope is declared.
- Experimental: `task_scope.mode: "agent"` exposes `judikt_declare_task`, which the agent calls once, before its first read, to declare the writes the user's request needs; the first tool result seals the declaration. No real agent has been evaluated with it yet.
- Learned prompt-injection classifier for tool results and descriptions, shipped as weights in the wheel.
- Incident summaries from OpenAI, Anthropic, Gemini and any OpenAI-compatible endpoint, as well as Groq, selected with `JUDIKT_LLM_PROVIDER`. With it unset, only a Groq key enables summaries, as before.
- Benchmarks: an InjecAgent worst-case replay through a real `judikt wrap` session, and a ground-truth replay of AgentDojo and AgentDyn, with evidence under `docs/evidence/`.
- CI surfaces release-qualification failures as annotations.

### Changed

- Tool names in camelCase are split into words before the mutation-verb check, so `deleteRepo` is classified like `delete_repo`.
- An unchanged tool catalog is no longer re-inspected on every call (258 ms to 41 ms per call on a 330-tool catalog).
- Tools that may need approval under the new gates advertise the optional `approval_token` argument.

### Fixed

- `judikt wrap --policy` with a `--name` that matches no server in the policy now warns instead of silently exposing no tools.

### Measured results (ground-truth replay, no language model)

All figures replay each benchmark's own correct tool calls and assume an agent that obeys every injection; they are not end-to-end agent results. Details and caveats are in the README.

- InjecAgent (1,054 cases): 0 harmful actions executed under `read-only` or `approve-writes`; 223 under `permissive` with the provenance gate (1,054 with it off); 0 with a task scope.
- AgentDyn (never used during development; attacker calls pre-registered): 67.8% of attacks held by provenance, 94.8% with provenance and a task scope; 27 of 60 legitimate tasks would hit one hold.
- AgentDojo (used while designing the gate, so not an independent test): 96.6% held by provenance, 99.8% with a task scope; 4 of 97 legitimate tasks would hit one hold.
- Detection on an external holdout: BIPIA 54.8%, InjecAgent 7.6%, 0% false positives.

Correction: an earlier README figure for the permissive InjecAgent replay (680 of 1,054 executed) came from a fixture bug that showed most cases another case's injection; the corrected figure is 223.

## 0.3.0 and earlier

See the [GitHub releases](https://github.com/gaurav-gs7/Judikt/releases).
