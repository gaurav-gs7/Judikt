# Judikt Skill Acceptance

The Judikt MCP security skill has an executable acceptance suite rather than a documentation-only checklist. Run it with:

```bash
./scripts/run_skill_acceptance.sh
```

The runner builds the current wheel, creates an empty temporary home and virtual environment, installs the wheel without dependencies, and executes the skill contract against that installed runtime. It does not use the source package through `PYTHONPATH`.

## Automated Acceptance Matrix

| Requirement | Evidence | Pass condition |
| --- | --- | --- |
| Positive activation | Four direct Judikt setup, connection, assessment, and troubleshooting prompts | Every prompt matches both an MCP/Judikt target and an action declared by the skill metadata |
| Negative activation | Four adjacent but unrelated protocol, Kubernetes, Python, and AWS prompts | No prompt matches the activation contract |
| Fresh setup | Wheel installed in a new virtual environment and diagnosed with an empty `HOME` | Python is supported, installed Judikt is detected, and diagnosis writes no files |
| Claude Code configuration | `.mcp.json` shape launches the exact `judikt wrap` command | Guarded `tools/list` returns only `external.fetch_issue` |
| Cursor configuration | `.cursor/mcp.json` shape launches the exact `judikt wrap` command | Guarded `tools/list` returns only `external.fetch_issue` |
| Allowed call | `external.fetch_issue(issue_id="INC-42")` | Upstream result is returned through Judikt |
| Blocked call | Sensitive `.ssh/id_rsa` argument | Judikt denies before upstream execution |
| Audit evidence | Read both resulting SQLite events through `AuditStore` | Ordered allow/deny outcomes, no spoofed actor, valid two-event HMAC chain |
| Unauthorized privileged action | Call `judikt.issue_approval` without an authenticated admin context | `admin_authorization` denial and no approval token |

The activation cases are deterministic metadata tests, not a claim that every model or marketplace uses the same activation algorithm. They define the intended trigger boundary and catch descriptions that become too broad or too narrow.

## Client Qualification Record

The same local stdio definition was also checked with real client CLIs on 2026-10-22:

| Client | Version | Client-native result |
| --- | --- | --- |
| Claude Code | `2.1.308` | `claude mcp get` and `claude mcp list` reported `Connected` |
| Cursor Agent | `2026.10.19-6bbf2c4` | Approval was required first; after `agent mcp enable`, `agent mcp list` reported `ready` and `agent mcp list-tools` returned `external.fetch_issue(issue_id)` |

The clients were installed under isolated temporary homes, and no personal client configuration was read or changed. Client-native checks prove process startup, MCP negotiation, approval handling, and catalog discovery. Allowed/blocked invocation and audit assertions use Judikt's protocol client against the identical command because these vendor CLIs do not expose a stable unauthenticated noninteractive tool-invocation command.

## Scope

This suite qualifies local stdio onboarding and its safety boundary. Authenticated Streamable HTTP, JWT/OIDC, Redis, Slack, SIEM, observability, and AWS deployment remain covered by the runtime release suite; they are not silently counted as verified by this skill acceptance run.

## Release Contract

`python scripts/build_skill_release.py` validates the skill metadata, folder name, relative references, archive paths, and generated-file exclusions. It creates a deterministic `judikt-mcp-security-v<runtime-version>.zip`. GitHub release CI rejects a tag that does not exactly match `v<project.version>`, keeps the Python artifacts separate from the skill ZIP, and attaches the ZIP to the GitHub release.
