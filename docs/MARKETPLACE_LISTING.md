# Judikt MCP Security Skill

## Listing Metadata

**Name:** Judikt MCP Security<br>
**Category:** Developer Tools / AI Security<br>
**Runtime version:** `0.3.0`<br>
**License:** Apache-2.0<br>
**GitHub:** https://github.com/gaurav-gs7/Judikt

**Short description:** Safely wrap, configure, smoke-test, and assess MCP servers protected by the separately installed Judikt runtime.

## Description

The Judikt MCP Security skill guides an agent through a consent-based security onboarding workflow for Model Context Protocol servers. It detects the local environment without changing it, generates a least-privilege policy from the upstream server's real `tools/list`, configures a supported MCP client, performs a read-only smoke test, and produces an evidence-based assessment that separates verified controls from configuration alone.

Judikt itself is installed separately. The runtime sits between an MCP client and an operator-selected tool server, applying deterministic policy, local or authenticated identity, argument and response inspection, tool-definition pinning, approval controls, rate limits, kill switches, redaction, and tamper-evident audit evidence. The skill does not bundle the runtime, silently install dependencies, edit client configuration without consent, or invent privileged approval tokens.

## Use Cases

- Wrap a local stdio MCP server with `judikt wrap -- <upstream command>`.
- Discover an upstream's actual tool catalog and generate a reviewable starter policy with `judikt init`.
- Add a Judikt-protected server to Claude Code or Cursor without overwriting unrelated MCP entries.
- Smoke-test MCP initialization, `tools/list`, and one explicitly authorized read-only call.
- Verify an allowed call, a policy denial, actor-spoofing protection, and signed audit-chain evidence.
- Assess an existing local or authenticated remote Judikt deployment without treating untested integrations as passing.
- Troubleshoot policy, connection, identity, approval, response-inspection, and audit failures without weakening security.

## Screenshots

### Product And Runtime Walkthrough

![Judikt product and live terminal walkthrough](assets/judikt-demo.gif)

The walkthrough combines architecture context with captured commands, guarded MCP calls, policy outcomes, backend results, quarantine, metrics, and signed audit verification.

### Control-Plane Overview

![Judikt control-plane overview showing AI agent, Judikt, MCP tool, and signed evidence](assets/judikt-demo-poster.png)

## Supported Platforms

| Area | Support |
| --- | --- |
| Host operating systems | macOS and Linux |
| Runtime | Python 3.11 or newer; Judikt installed separately |
| Local transport | MCP JSON-RPC over stdio |
| Remote transport | Authenticated MCP Streamable HTTP when the separately operated runtime is configured |
| Qualified clients | Claude Code `2.1.308`; Cursor Agent `2026.10.19-6bbf2c4` |
| Client configuration | Claude Code `.mcp.json`; Cursor `.cursor/mcp.json`; other clients accepting standard `mcpServers` stdio definitions may work but are not claimed as qualified |
| Deployment options | Local process, Docker, Kubernetes via Helm, AWS EC2, and AWS serverless control-plane components |

## Safety And Privacy

- Read-only discovery is the default.
- Installation, upstream launch, policy creation, client configuration changes, and external calls require user consent.
- Destructive, privileged, billable, or externally visible actions require explicit authorization.
- The skill never asks an agent to fabricate approval tokens, disable authentication, or broaden policy to make a test pass.
- The bundled diagnostic reads executable/version metadata only. It does not make network calls, launch the upstream, read environment values or client configuration contents, or modify files.
- The separate runtime may contact the chosen upstream and, only when configured, Groq, Slack, AWS, SIEM/Splunk, Redis, Vault, an OIDC/JWKS provider, an OTLP collector, or an incident-management endpoint.

## Verification

The [acceptance record](SKILL_ACCEPTANCE.md) covers positive and negative activation fixtures, a fresh-wheel installation, Claude Code and Cursor connection checks, allowed and blocked calls, signed audit evidence, and refusal of approval issuance to a non-admin subject. The distributable ZIP is generated and validated from the same runtime version in release CI.

## Installation Boundary

Install the Judikt runtime from its trusted distribution first, then install the version-matched `judikt-mcp-security` skill ZIP. The skill's compatibility statement is intentionally explicit: **Requires a separately installed Judikt runtime.**
