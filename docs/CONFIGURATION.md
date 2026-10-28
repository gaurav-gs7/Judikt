# Configuring Judikt

How to wrap upstreams, what generated policies contain, how approvals and the write gates work, and how content inspection behaves. Back to the [README](../README.md).

## Wrapping an upstream

Wrap any stdio MCP server with one command. Judikt discovers `tools/list`, creates an annotation-derived starter policy (read-only by default), and exposes only its authorized catalog over stdio:

```bash
judikt wrap -- npx -y @modelcontextprotocol/server-filesystem /absolute/safe/path
```

Judikt starts stdio upstreams with a minimal environment (`PATH`, temp and locale variables), so your shell's secrets never reach them by accident. Pass anything an upstream genuinely needs with `--env NAME`, which forwards that one variable from your shell. Behind a corporate proxy, `npx`-launched servers need the proxy and CA settings, or they hang until the initialize timeout:

```bash
judikt wrap --env HTTPS_PROXY --env NODE_EXTRA_CA_CERTS -- npx -y @modelcontextprotocol/server-filesystem /absolute/safe/path
```

`judikt init` takes the same option. The variable names (never their values) become part of the upstream's state key, and `judikt pins accept` relaunches the upstream with them.

The same entry point wraps a remote Streamable HTTP upstream. HTTPS is required except for localhost; local/private addresses additionally require explicit operator consent:

```bash
judikt wrap --url https://mcp.example.com/mcp
judikt wrap --url http://127.0.0.1:9000/mcp --allow-private-network
```

Use this command directly in an MCP client configuration:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "judikt",
      "args": [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/absolute/safe/path"
      ]
    }
  }
}
```

To review and customize a persistent annotation-derived starter policy first, generate one from the upstream's actual catalog:

```bash
judikt init \
  --name filesystem \
  --output judikt-policy.json \
  -- npx -y @modelcontextprotocol/server-filesystem /absolute/safe/path

judikt wrap \
  --policy judikt-policy.json \
  --name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /absolute/safe/path
```

## Generated policies

The packaged default policy is deliberately neutral and fail-closed. `judikt init` and policy-free `judikt wrap` classify discovered tools from their names and MCP annotations. Annotations are self-reported by the upstream, are not trusted security facts, and can only make the generated policy stricter than the name check. Every generated policy is a starting point that must be reviewed. Anonymous callers receive no permissions, and `judikt init` refuses to overwrite an existing file unless `--force` is supplied.

Generated-policy profiles:

| Profile | Generated behavior |
| --- | --- |
| `read-only` (default) | Advertise and allow only tools with `readOnlyHint: true` whose names contain no mutation segment. |
| `approve-writes` | Allow all discovered tools, but require a signed approval token for every write or destructive tool. |
| `permissive` | Allow every discovered tool without generated approval gates and print a warning to stderr on every generated-policy start. |

`approve-writes` gates write and destructive tools in two steps. Accepting a tool's definition is a one-time pin decision: until then the tool is pin-pending and hidden, so a first run looks read-only, and the gateway prints one line such as `4 approval-gated tools are hidden until their definitions are accepted: judikt pins accept <state-key> --tool update_issue --tool delete_repo ...`. After that, every call still requires its own signed approval token. To pin the reviewed catalog while generating a persistent policy, run `judikt init --profile approve-writes --accept-pins -- <upstream command>`; it shows the classification, asks for confirmation (`--yes` skips the prompt), and pins every discovered definition in the state that `judikt wrap` with the same command uses.

Tools without annotations are destructive by default. A read-only annotation that conflicts with a mutation-like name such as `delete_cache` is also classified as destructive. The generated policy records every decision under `tool_classification`; tool pinning uses that tier for first-use approval. Pass `--profile` to `judikt init` or policy-free `judikt wrap`. When `judikt wrap --policy ...` is used, Judikt uses that explicit policy as-is and does not reclassify it.

Risk is deterministic and policy-driven under the `risk` key. `tier_scores` sets the read, write, and destructive baselines; `annotation_modifiers` may only add risk; `tool_rules` supports glob and regex matches; and `argument_rules` supports `in`, `prefix`, and `regex` conditions. `levels` maps scores to severity, while optional `risk_actions` can require approval for a severity such as `high` or `critical`. Live MCP annotations can raise a tool's tier but cannot lower the tier implied by reviewed `tool_classification` data or a mutation-like tool name. Every matched rule's evidence is retained in the decision and audit event.

When neither `--audit-db` nor `JUDIKT_AUDIT_DB` is set, each wrapped upstream gets private state under `$XDG_STATE_HOME/judikt/upstreams/<display-name>-<fingerprint>/` (or `~/.local/state/judikt/upstreams/...`). The fingerprint binds the resolved command, working directory, and configured environment-variable names without storing their values. Its `audit.db`, findings database, and tool-pin file are therefore isolated from unrelated upstreams and concurrent writers.

Tool pins use schema v2: an overall digest, upstream fingerprint, safely quoted launch command, pin time, and per-tool digests for the complete definition plus `description`, `inputSchema`, `annotations`, and `outputSchema`. The default `tool_pinning.first_use` policy auto-pins read tools while write and destructive tools remain pending, unadvertised, and uncallable with rule `pin_pending` until explicitly accepted. The gateway prints one safe acceptance command per pending tool.

Pin updates use a sibling `flock` file plus atomic replacement, so concurrent Judikt processes cannot overwrite one another. Pin files are created mode `0600` in mode-`0700` directories and rejected when ownership or write permissions are unsafe. Every server entry is HMAC-protected by `JUDIKT_PINS_HMAC_SECRET` or a private sibling `pins.key`; AWS Secrets Manager and Vault sources use the corresponding `_ARN`, `_VAULT_PATH`, and `_JSON_KEY` variables. A MAC mismatch fails closed as tool drift. Legacy unsigned entries are accepted once with a warning and signed after successful verification.

Review and explicitly accept pending or changed tools with:

```bash
judikt pins list
judikt pins show <state-key>
judikt pins accept <state-key> --tool <tool-name> --yes
# Omit --tool to accept the complete current catalog; omit --yes for confirmation.
```

The drift report lists tools awaiting first-use approval under `Pending approval`, separately from genuinely new `Added tools`. `pins accept` prints a JSON summary: `accepted_tools` (what this call accepted), `pinned_count` and `pending_count` (the stored pin state after the call), and `upstream_tool_count` (the size of the catalog the upstream advertised).

`JUDIKT_TOOL_PIN_MODE=refresh` remains available for compatibility but warns because it re-trusts every server in the selected pin file.

## Approving a held call

Approving a held call takes one command. When a call needs approval (rule `approval_required`, `untrusted_provenance` or `task_scope`), the local gateway records it and the agent's error says which id to approve:

```text
Judikt blocked this call: 'send_email' is not one of the writes declared for this task; a human must approve
this exact call (rule: task_scope, correlation: ...) To approve, a human runs `judikt approve af409cb1` in a
terminal; then retry this exact call unchanged.
```

```bash
judikt approve            # list calls waiting for approval
judikt approve af409cb1   # show the exact call and approve it once (--yes skips the prompt, --deny discards it)
```

`judikt approve` signs an ordinary single-use approval token bound to that call's exact arguments and stores it for five minutes. When the agent retries the same call unchanged, the gateway attaches the token itself; a changed argument is held again. Held calls live under `$XDG_STATE_HOME/judikt/pending-approvals/` (mode `0600`, expiring after 15 minutes) and contain the call's arguments, so treat that directory like `approval.key`. Run `judikt approve` as the same OS user, with the same `XDG_STATE_HOME` and `JUDIKT_APPROVAL_SECRET`, as the gateway. Production mode and `JUDIKT_PENDING_APPROVALS=off` disable the store; remote deployments use their configured approval workflow. `judikt issue-approval` remains for scripted approvals. As with `approval.key`, this protects against injected calls arriving through MCP, not against an agent that can run shell commands as the same OS user: such an agent could run `judikt approve` itself, so give agents with shell access a separate OS user or a remote approval workflow.

## Untrusted provenance

When writes are allowed without approval, Judikt still notices a write that reuses something only untrusted tool output told the agent to use. It splits every result it returns into lines, paragraphs and serialised fields, and in each segment that instructs (second person, a request, a question, or a sentence starting with a command verb) it records the email addresses, URLs and domains, IBANs, long account and phone numbers, crypto addresses and @handles, plus identifiers (tokens with digits, snake_case names, paths, #channels), quoted strings and capitalised multi-word names. A later write or destructive call whose arguments reuse one is held under rule `untrusted_provenance` until a human approves that exact call. A value the agent used before any tool returned it counts as the user's and stays trusted. An address sitting in a plain data field, such as a meeting participant, is not tracked; set `untrusted_provenance.track` to `everywhere` to track addresses and links wherever they appear. `untrusted_provenance.mode` is `require_approval` (the default), `deny`, `report` or `off`.

## Task scope

Some injections carry nothing to trace: "unlock the front door" names no address, account or identifier. What gives them away is that the user's task never needed that write. A task scope lists the write and destructive tools a task may call, and any other write is held under rule `task_scope`. The operator sets it with `judikt wrap --task-writes send_email,create_calendar_event` (or `JUDIKT_TASK_WRITES`, or `task_scope.write_tools` in the policy; `none` allows no writes). With `task_scope.mode: "agent"` (experimental: no real agent has been evaluated with it yet) the gateway also exposes `judikt_declare_task`: the agent declares the writes from the user's request before it reads anything, the first tool result seals the declaration, and an agent that never declared is sealed with no writes. Without a declared scope nothing changes. Read tools are never limited, and no model is involved.

## Content inspection

Judikt treats MCP arguments, tool definitions, and tool results as untrusted content. Each inspected string is checked directly and through normalized variants that remove invisible controls, map common lookalike and leetspeak characters, and collapse spaced-letter obfuscation. Candidate base64, hex, and URL-encoded payloads are decoded and rescanned, while strings from the same object are also joined for a bounded pass that catches instructions split across JSON fields.

Tool results and tool descriptions are also scored by a learned classifier: a logistic regression over word and character n-gram TF-IDF features, shipped as weights and scored with the standard library only. It is deterministic and calls no model. It runs only where the rules found nothing, scores text with code, block quotes and quoted examples blanked out, and flags 600-character windows. A flagged window that contains an instruction (second person, a request, a question, or a sentence starting with a command verb) is a medium finding; one that only describes is reported and never redacts. Set `inbound_content_inspection.learned_classifier` to `{"enabled": false}` to turn it off. Tool arguments are not scored: they are the agent's own actions and stay with policy.

Findings carry `low`, `medium`, or `high` severity plus their surface. The default `inbound_content_inspection.thresholds` block tool descriptions and arguments at medium, while tool results block at high, redact only the affected span at medium, and record low findings. More than `max_medium_findings` (default `3`) quarantines the whole result. Fenced code, inline code, and quoted lines are scanned only for high-severity signals. Oversized results scan both ends of the configured byte budget and record `scan_limit_exceeded`; oversized tool metadata still fails closed. Findings contain rule names, JSON paths, and evidence hashes, never matched text.

This is defense in depth, not a claim of complete semantic detection. The multilingual rules cover a deliberately small set of high-value phrases, and novel paraphrases can evade both the rules and the classifier. An optional model-based detector is scoped in [docs/SEMANTIC_DETECTOR.md](SEMANTIC_DETECTOR.md); it is not implemented or enabled.

## Identity

Unauthenticated stdio sessions take their identity only from `local_stdio_identity` in the policy file; authenticated remote sessions use the validated subject. Tool arguments are forwarded unchanged for policy evaluation, approval hashing, auditing, and upstream execution. The `identity_argument_fields` policy key is a list of argument names that may act as identity claims only when no trusted identity exists; its default is `[]`, while the demo policy opts into `["actor"]`. When a trusted identity exists, a conflicting value in an opted-in field is denied with `identity_mismatch`. Use a separate local policy file when different MCP client installations need different principals.
