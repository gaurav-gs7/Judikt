# MCP Client Configuration

## Choose A Mode

Use the stdio wrapper for a local MCP client and stdio upstream. Use authenticated Streamable HTTP only when a separately operated Judikt server already exists.

Do not guess the client's configuration path or overwrite its configuration. Detect candidate paths, identify the active client, show the proposed change, and obtain consent before writing.

## Local Stdio With A Reviewed Policy

Prefer absolute paths for the Judikt executable, policy, upstream executable, and upstream filesystem roots:

```json
{
  "mcpServers": {
    "judikt-protected-upstream": {
      "command": "/absolute/path/to/judikt",
      "args": [
        "wrap",
        "--policy",
        "/absolute/path/to/judikt-policy.json",
        "--name",
        "upstream-name",
        "--",
        "/absolute/path/to/upstream",
        "--stdio"
      ]
    }
  }
}
```

Claude Code reads project-scoped servers from `.mcp.json`. Cursor reads project-scoped servers from `.cursor/mcp.json`. Both accept the `mcpServers` object shown above. Project-scoped servers may require an explicit trust or approval action before the client starts them; preserve that prompt rather than bypassing it.

Some clients place global options more reliably before the subcommand. This equivalent form is valid:

```json
{
  "command": "/absolute/path/to/judikt",
  "args": [
    "--policy",
    "/absolute/path/to/judikt-policy.json",
    "wrap",
    "--name",
    "upstream-name",
    "--",
    "/absolute/path/to/upstream",
    "--stdio"
  ]
}
```

For a disposable evaluation only, omit `--policy` and let `judikt wrap` discover an ephemeral exact-tool policy. State clearly that the policy was generated at startup and was not operator-reviewed.

## Upstream Credentials

Do not embed secrets in MCP client JSON. For persistent multi-upstream operation, use `JUDIKT_UPSTREAM_CONFIG` and reference operator-owned credentials with Judikt's `from_env`, `from_aws_secret`, or `from_vault` sources. Never forward the MCP caller's bearer token or JWT to an upstream.

## Authenticated Streamable HTTP

For a remote Judikt resource server, configure the MCP client with the operator-provided HTTPS `/mcp` URL and its supported OAuth/JWT flow. Do not put bearer tokens in versioned files or command arguments. Judikt validates access tokens; the external authorization server owns login, consent, client registration, authorization code flow, and PKCE.

Use static bearer authentication only for a constrained single-operator environment. It authenticates possession of one shared secret and does not provide distinct user identity.

## Safe Merge Procedure

1. Locate the active client configuration and identify its format.
2. Read only the minimum content needed to preserve existing entries; never echo secret values.
3. Prepare a minimal addition under a unique server name.
4. Show a redacted diff and request consent.
5. Preserve file permissions and unrelated configuration.
6. Parse or validate the resulting JSON/TOML before asking the user to reload the client.
7. Restore from the pre-change content if validation fails; do not leave a partially written file.

## Connection Evidence

A successful process start alone is not enough. Record sanitized evidence for:

- MCP initialization and negotiated transport;
- guarded `tools/list` count and expected names;
- the configured local identity or authenticated subject mode;
- one authorized read-only call, when available;
- an audit event or correlation identifier;
- any configured control that was not exercised.
