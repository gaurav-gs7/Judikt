---
name: judikt-mcp-security
description: Set up, configure, connect, smoke-test, troubleshoot, or assess MCP servers protected by Judikt. Use when a user asks to wrap an stdio MCP upstream, generate an annotation-derived starter policy (read-only by default) from tools/list, add Judikt to an MCP client, validate local or authenticated remote controls, or produce an evidence-based MCP security assessment. Requires a separately installed Judikt runtime; this skill does not bundle Judikt.
---

# Judikt MCP Security

Compatibility: Requires a separately installed Judikt runtime and Python 3.11 or newer. This skill does not install or bundle Judikt.

Use Judikt as a policy and security boundary between an MCP client and an operator-selected upstream. Keep discovery read-only, make every mutation visible, and distinguish configuration from verified behavior.

## Required Workflow

1. **Detect the environment.** Run `python3 scripts/diagnose.py` from this skill directory. This reads local version, executable, and candidate client-config metadata only. Do not install software, start an upstream, or change files during detection.
2. **Plan setup.** Read [references/setup.md](references/setup.md). Report detected Python, Judikt, MCP client, upstream command, intended policy path, and intended audit path. Ask for explicit consent before any installation or file change.
3. **Configure the upstream.** Prefer `judikt init` so an annotation-derived starter policy (read-only by default) is generated from the upstream's real `tools/list` response. Treat annotations as self-reported and the policy as a starting point to review. Show the exact command, profile, and destination first. Treat launching the upstream and writing the policy as consent-requiring actions.
4. **Connect the client.** Read [references/mcp-configuration.md](references/mcp-configuration.md). Identify the exact client configuration file, show a minimal proposed diff, preserve unrelated entries, and obtain consent before editing it. Never place credentials in client configuration.
5. **Run a smoke test.** Reload the client, initialize the MCP connection, and request `tools/list`. Call only a clearly read-only tool when the user authorizes that call. Do not use a mutating tool merely to prove connectivity.
6. **Produce an assessment.** Report each control as `verified`, `configured-not-verified`, `not-configured`, or `not-applicable`. Include sanitized evidence, unresolved gaps, and the exact scope tested. Never infer a passing control from configuration alone.

For startup failures caused by tool metadata or pin drift, follow [references/troubleshooting.md](references/troubleshooting.md). Never accept a changed pin automatically.

Stop and ask when the upstream command, client configuration location, intended identity, or authorization boundary cannot be determined safely.

## Safety Rules

- Operate read-only by default.
- Obtain explicit user authorization before destructive, mutating, privileged, billable, or externally visible operations.
- Obtain consent before installing Judikt or dependencies, creating a policy, editing an MCP client configuration, or enabling an integration.
- Never invent, replay, expose, or bypass approval tokens. Never weaken authentication, authorization, policy, response scanning, or TLS requirements to make a test pass.
- Treat direct approval issuance as sensitive defense in depth. Judikt also requires `JUDIKT_ALLOW_DIRECT_APPROVAL` and applies administrator authorization to authenticated remote callers; these runtime controls do not replace user authorization.
- Never print secrets, bearer tokens, JWTs, approval tokens, environment values, secret-file contents, or unredacted sensitive tool output.
- Never pass a caller credential through to an upstream. Use operator-owned, least-privilege upstream credentials.
- Keep smoke tests on `tools/list` and explicitly identified read-only tools. Do not assume a tool is safe from its name alone; inspect its description and schema.
- Do not broaden actor wildcards, disable approvals, enable unauthenticated remote access, or set permissive content-guard modes as a troubleshooting shortcut.
- Separate verified controls from controls that are only configured or documented.
- For unauthenticated stdio, explain that identity comes only from `local_stdio_identity` and tool arguments are forwarded unchanged, but Judikt cannot distinguish multiple callers sharing that local policy. Authenticated remote identity comes from the validated subject.
- For remote deployment, require authentication and HTTPS outside loopback. Treat static bearer authentication as a constrained single-operator mode, not user-level identity.

## Network And Data Disclosure

The bundled diagnostic script is read-only and makes no network or socket calls. It does not invoke Judikt, launch an upstream, inspect environment-variable values, or modify client configuration.

The separately installed Judikt runtime communicates with the selected MCP upstream. When explicitly configured, it may also contact an LLM provider for incident summaries (Groq, OpenAI, Anthropic, Gemini, or an OpenAI-compatible endpoint), Slack, AWS services, SIEM/webhook or Splunk endpoints, Redis, Vault, an OIDC/JWKS provider, an OTLP collector, or an incident-management endpoint. These integrations are optional and inactive until configured. Read [references/security.md](references/security.md) before enabling any of them.

## Assessment Format

Return a compact table with these columns:

| Control | Status | Sanitized evidence | Gap or next action |
|---|---|---|---|
| Runtime availability | verified/configured-not-verified/not-configured | Version and executable path | Action |
| Upstream allowlist | status | Policy path and tool-name count | Action |
| Client connection | status | Transport and catalog count | Action |
| Identity boundary | status | Local identity or authenticated subject mode | Action |
| Approval boundary | status | Gate observed without revealing a token | Action |
| Response inspection | status | Test or configuration evidence | Action |
| Tool pinning | status | First-use mode, pending count, and integrity status | Action |
| Audit evidence | status | Sanitized event/correlation evidence | Action |

Conclude with the tested boundary, untested integrations, and whether any files were changed.
