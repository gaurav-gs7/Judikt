# Community MCP Interoperability

Judikt includes a versioned harness for proving its gateway controls against independently maintained MCP servers. It does not treat a synthetic in-repository fixture as third-party evidence.

## Pinned Profiles

| Profile | Implementation | Version | Safe proof | Credentials |
| --- | --- | ---: | --- | --- |
| `modelcontextprotocol-filesystem` | Official MCP filesystem server | `2026.7.10` | Read one fixture file from a disposable directory | None |
| `modelcontextprotocol-memory` | Official MCP memory server | `2026.7.4` | Read an empty graph stored in a disposable file | None |
| `github-official-readonly` | GitHub's official MCP server | `0.31.0` | Call `get_me` with read-only mode and limited toolsets | Operator-provided GitHub token |

The source of truth is [`config/interop_profiles.json`](../config/interop_profiles.json). Package versions and container tags are explicit; `latest` is not used.

## What The Harness Proves

For each profile, the harness:

1. Creates a disposable sandbox and starts the external server without inheriting the gateway process environment.
2. Supplies only explicitly configured operator-brokered variables.
3. Discovers the complete paginated tool catalog and rejects duplicate tool names.
4. Scans all tool metadata and creates a SHA-256 pin.
5. Lists tools again and verifies that the definition has not drifted.
6. Reconnects through `JudiktOpsRuntime`, where allowlist, risk, rate-limit, redaction, tracing, and audit controls are active.
7. Executes one read-only safe call and scans the complete response before returning it.
8. Verifies the tamper-evident audit chain.

The JSON report retains hashes and decisions, not raw third-party output. A failed profile records an exception type and hash without copying untrusted server text into CI artifacts.

## Run Credential-Free Profiles

```bash
make interop-community
```

Profiles fetch their servers with `npx` at run time. When `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (or their lowercase forms), `NODE_EXTRA_CA_CERTS`, or `SSL_CERT_FILE` is set, the harness forwards it to the profile's upstream so the run works behind a proxy. No other variables are forwarded, and a value a profile defines itself is never overridden.

The report is written to `build/community-interop.json`. The same command runs in the `community-interop` GitHub Actions job and uploads the JSON evidence as a workflow artifact.

## Run GitHub's Official Server

Use a short-lived fine-grained token with the smallest useful read permissions:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN="..."
./scripts/run_community_interop.sh \
  --profile github-official-readonly \
  --output build/github-community-interop.json
```

The token is selected explicitly through `from_env`, passed only to the GitHub MCP process, rejected if supplied by an MCP caller, and never written to the evidence report.

## Honest Evidence Status

The in-repository harness and synthetic protocol tests run without downloading community code. The pinned community profiles become verified evidence only after the corresponding package or image has actually executed successfully. Do not present a configured-but-unexecuted profile as a compatibility result.
