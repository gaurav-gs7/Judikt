# Tool Integrity Troubleshooting

Judikt exits wrap and MCP-server startup with status `3` when tool metadata is quarantined or a pinned tool definition changes. The diagnostic is written to stderr so stdio stdout remains a JSON-RPC-only channel. Drift output contains tool names and changed field names, never untrusted descriptions or schema contents.

List the isolated upstream states and inspect the named state key:

```bash
judikt pins list
judikt pins show <state-key>
```

Schema-v2 pins contain the upstream fingerprint, safely quoted launch command, pin time, overall digest, and per-tool digests for the complete definition, `description`, `inputSchema`, `annotations`, and `outputSchema`. A matching legacy digest-only entry is upgraded automatically; a drifting legacy entry reports that a per-tool diff is unavailable.

After independently reviewing the upstream release or source and obtaining explicit user consent, accept one changed tool:

```bash
judikt pins accept <state-key> --tool <tool-name>
```

Omit `--tool` only when the complete current catalog was reviewed. `--yes` suppresses the confirmation prompt and should be used only in an already authorized, auditable workflow. Never invoke pin acceptance automatically. `JUDIKT_TOOL_PIN_MODE=refresh` is compatibility-only and re-trusts every server in the pin file.

## Upstream Timeouts, Exits, and Errors

Agent-visible denials such as `MCP upstream '<name>' timed out during 'tools/call' after 30s` or `MCP upstream '<name>' returned an error (code -32000)` are deliberately generic. Judikt never forwards upstream stderr, upstream JSON-RPC error messages, or remote transport exception text to the agent, because that text is attacker-controllable.

To diagnose, use the correlation ID from the denial and read the redacted operator diagnostic:

```bash
sqlite3 <audit-db> "SELECT seq, rule, diagnostic FROM audit_events WHERE correlation_id = '<correlation-id>'"
```

The same diagnostic is written to the gateway's stderr (the MCP client's server log) as a `Judikt upstream diagnostic` line. Do not set `expose_error_messages` merely to debug; it shows inspected upstream error messages to agents and should be enabled only for upstreams whose error text is useful to the agent.

## Hung Upstreams and the Catalog Cache

A timed-out request triggers a liveness `ping` (default deadline 5 seconds, `liveness_timeout_seconds` per upstream). A stdio upstream that does not answer is terminated and restarted on the next request within its restart budget; a remote session is recreated. Pins are re-verified after either. If `judikt_upstream_liveness_failures_total` keeps rising, the upstream is hanging repeatedly: inspect its diagnostics rather than raising timeouts. Once the restart budget is exhausted, calls fail with `upstream_error` until Judikt restarts.

Tool catalogs are cached for `catalog_ttl_seconds` (default 30). A definition change without `notifications/tools/list_changed` is detected only after the TTL expires; set `catalog_ttl_seconds` to `0` for upstreams that must be re-checked on every call. Repeated `upstream_timeout` denials that mention `tools/list` mean the catalog refresh itself is failing; the circuit breaker opens after the configured threshold.

