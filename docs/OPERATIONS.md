# Operating Judikt

Controls, audit evidence, kill switches, rate limits, incident summaries, the dashboard API, containers, the remote MCP server, AWS and tracing. Back to the [README](../README.md).

## Controls

Judikt includes:

- MCP gateway proxying over JSON-RPC stdio
- Official MCP SDK Streamable HTTP server for production-facing clients
- Operator-configured proxying to independently built stdio and Streamable HTTP MCP servers
- Versioned interoperability harness for official Filesystem, Memory, and GitHub MCP servers
- Minimal subprocess environments that expose only explicitly brokered upstream credentials
- Brokered remote headers, HTTPS enforcement, redirect refusal, DNS-rechecked SSRF controls, and bounded responses
- Recursive tool-description and JSON Schema inspection before trust
- SHA-256 tool-definition pinning and fail-closed rug-pull detection
- Deterministic direct and indirect prompt-injection inspection across tool arguments, metadata, and results
- Evasion-resistant scanning for base64, hex, URL encoding, invisible Unicode, confusables, leetspeak, spaced-letter payloads, and injections split across JSON fields
- A deterministic, dependency-free learned injection classifier for tool results and descriptions, trained only on sources disjoint from its evaluation sets
- An InjecAgent worst-case replay benchmark: with read-only or approve-writes policies, 0 of 1,054 hijacked-agent attacks executed
- An untrusted-provenance gate that holds writes reusing values an instruction in tool output named, and per-task write scopes declared by the operator or, before any read, by the agent
- Narrow multilingual rules for common instruction-override and role-reassignment phrases in Spanish, French, German, Portuguese, Chinese, and Russian
- Quarantine envelopes that do not return malicious text to the agent
- Policy-as-code allowlists and blocked argument patterns
- JWT/OIDC resource-server authentication with issuer, audience, group, and scope validation
- Authenticated-subject binding that rejects caller actor spoofing
- Trusted-context identity from `local_stdio_identity` or an authenticated subject, with tool arguments forwarded unchanged except for Judikt's own control arguments
- OAuth protected-resource metadata and caller-token passthrough denial
- Scoped OAuth challenges and exact HTTP Origin validation
- HMAC-signed, single-use approval tokens for restart and rollback operations
- Approval tokens (`approval_token`, and demo-only `approved`) are consumed by Judikt and stripped before any upstream call; approval-gated tools advertise an optional `approval_token` property, and an upstream tool that declares either name itself is refused with rule `control_argument_collision`
- Slack button approvals with signed callbacks, approver allowlists, deduplication, and replay protection
- Rollback-plan enforcement before production-impacting actions execute
- Dry-run-only and shadow-mode outcomes for safe agent evaluation
- Deterministic risk scoring for production actions
- Secret redaction for audit logs and agent-visible responses
- Per-tool rate limits and immediate kill switches
- Optional Redis-backed distributed rate limits for multi-replica deployments
- Atomic multi-key GCRA limits with retry metadata and privacy-preserving Redis keys
- Circuit breakers for repeated upstream tool failures
- Concurrent stdio and remote upstream requests with deadlines and cancellation, plus bounded stderr capture, restart budgets, and post-restart pin verification for subprocesses
- Native MCP result passthrough, metadata preservation, protocol-version negotiation, and live `tools/listChanged` pin enforcement
- Hash-chained, HMAC-signed local audit evidence (signed by default; local mode creates a private key on first use)
- Fail-closed audit signing and full-chain startup verification for production mode
- JSONL, S3, generic HTTPS SIEM, or Splunk HEC audit shipping plus individually signed DynamoDB serverless events
- Reusable AWS Secrets Manager and Vault KV secret brokerage across runtime credentials
- Correlation IDs, Prometheus metrics, OpenInference/OpenTelemetry traces, and AWS X-Ray
- Docker Compose observability stack with Prometheus, Grafana, Tempo, Jaeger, and Redis
- Helm chart for Kubernetes deployment
- Optional LLM incident summaries from Groq, OpenAI, Anthropic, Gemini, or any OpenAI-compatible endpoint, with an offline fallback
- Optional OpenInference-compatible traces exported through OpenTelemetry
- MCP-38 coverage matrix and adversarial policy regression suite
- MCP-AttackBench-compatible dataset adapter with per-category metrics and privacy-safe reports
- Reproducible full-pipeline latency, overhead, throughput, and audit-integrity benchmark
- Durable blocked-finding export that creates deduplicated incidents in Argus's RCA pipeline
- AWS Secrets Manager, X-Ray tracing, IAM review, SLOs, runbooks, and failure-mode tests

## Audit Integrity

Local audit events are appended in one SQLite `BEGIN IMMEDIATE` transaction under WAL mode. Each database has a stable random chain ID and a gapless sequence; every new event includes the preceding hash and is HMAC-signed by default. When no audit key is configured for local use, Judikt atomically creates `$XDG_STATE_HOME/judikt/audit.key` (or `~/.local/state/judikt/audit.key`) with mode `0600` inside a mode-`0700` directory. Authenticated remote and production modes require a configured key from the environment, AWS Secrets Manager, or Vault, and reject keys shorter than 32 bytes.

Judikt signs checkpoints after 100 events, after 60 seconds while events are arriving, and on clean shutdown. Verify the complete chain and its locally recorded checkpoints with `judikt audit verify --full`; add `--checkpoint <file|s3://bucket/key>` to detect a database head that has fallen behind externally retained evidence. Local checkpoints detect accidental loss, but a local attacker with filesystem access can truncate both the event and checkpoint tables. Evidence against that attacker requires exporting checkpoints to an append-only destination such as S3 Object Lock or a SIEM. To capture the current head on demand, run `judikt audit checkpoint --output <file|s3://bucket/key>`: it forces a signed checkpoint at the head inside the normal audit transaction, writes it to the destination (S3 writes use server-side encryption and require the optional `aws` dependencies and credentials), and prints `{chain_id, seq, head_hash}`.

Sink delivery uses a durable SQLite outbox committed in the same transaction as each event or checkpoint. `judikt audit status` reports pending count and oldest age; `judikt audit reconcile` retries pending deliveries. Prometheus exposes `judikt_audit_outbox_pending`, `judikt_audit_outbox_oldest_age_seconds`, and `judikt_audit_delivery_failures_total`. Configure `audit.backpressure` in policy with positive `max_pending` and `max_age_seconds` values plus `mode: "warn"` or `"deny"`; the default mode is `warn` locally and `deny` in production. Deny mode returns rule `audit_backpressure` while still recording the refusal locally.

Immediately before an authorized upstream execution, Judikt appends an `execution_started` intent containing a correlation ID and a hash of already-redacted arguments. The outcome event references that intent sequence. Verification reports an unmatched intent as `status: "incomplete"`, separately from cryptographic errors (`status: "tampered"`). Startup verification is enabled by default and resumes after the last fully verified signed checkpoint; production refuses to start on failure, while local mode writes a warning to stderr and dispatches an `audit_integrity` finding when a finding sink is configured.

## Shared Kill Switches

Local processes share durable kill-switch state through `$XDG_STATE_HOME/judikt/control.db` (or `~/.local/state/judikt/control.db`) using SQLite WAL transactions and a monotonic version. Configure `kill_switches.backend` as `sqlite` or `redis`, `kill_switches.cache_ttl_seconds` from `0` through `1`, and `kill_switches.on_store_failure` as `last_known` or `deny`. The failure default is `last_known` locally and `deny` in production. Redis uses `JUDIKT_REDIS_URL`; the AWS serverless path uses the existing DynamoDB `KILL_SWITCH` records. Every mutation records a signed `kill_switch_change` audit event with actor, reason, and state version.

```bash
judikt kill tool platform.restart_deployment --reason "contain active incident"
judikt kill server platform-ops --reason "upstream integrity investigation"
judikt kill status
judikt unkill tool platform.restart_deployment --reason "incident resolved"
```

The CLI, local dashboard, stdio gateway, and authenticated HTTP admin tools all read the same configured store. Remote mutations still require the control-plane `admin` role.

## Atomic Shared Rate Limits

Local and Redis backends use the same GCRA token-bucket-equivalent algorithm. A call checks its tool, actor/tool, production-environment/tool, and global budgets atomically: every budget is charged, or none is. Quota denials include `retry_after_seconds` in decision evidence and MCP `_meta`.

Configure `rate_limits.backend` as `local`, `redis`, or `redis_required`; `rate_limits.on_backend_failure` as `local_fallback` or `deny`; and `rate_limits.max_local_keys` to bound local memory (default `100000`). `JUDIKT_PRODUCTION=true` forces `redis_required`, as does setting both `JUDIKT_REDIS_URL` and `JUDIKT_REDIS_REQUIRED=true`. Production startup fails when required Redis is unavailable. A runtime Redis outage either returns `rate_limiter_unavailable` or warns on stderr and uses the bounded local fallback, while `judikt_rate_limiter_fallback_total` records both outcomes.

Each `rate_limits_per_minute` value may be a number, where burst defaults to that rate, or an object such as `{"rate": 60, "burst": 5}`. Redis evaluates every hashed logical key in one Lua script; local mode uses one lock and a two-phase decision. Local state evicts fully refilled idle keys and applies an LRU hard cap.

## Optional LLM Incident Summaries

The dashboard's incident summary is deterministic and local by default. To have a model write it instead, choose a provider explicitly:

```bash
export JUDIKT_LLM_PROVIDER=anthropic        # groq | openai | anthropic | gemini | openai-compatible | none
export ANTHROPIC_API_KEY="your-key"
./scripts/run_demo.sh
```

| Provider | `JUDIKT_LLM_PROVIDER` | Key variable | Default model |
| --- | --- | --- | --- |
| Groq | `groq` | `GROQ_API_KEY` | `openai/gpt-oss-20b` |
| OpenAI | `openai` (or `chatgpt`) | `OPENAI_API_KEY` | `gpt-6-luna` |
| Anthropic | `anthropic` (or `claude`) | `ANTHROPIC_API_KEY` | `claude-haiku-5-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `gemini-3.5-flash-lite` |
| Ollama, vLLM, LM Studio, LiteLLM and other OpenAI-compatible servers | `openai-compatible` | `JUDIKT_LLM_API_KEY` (optional) | none; set `JUDIKT_LLM_MODEL` |

- `JUDIKT_LLM_MODEL` overrides the default model, and `GROQ_MODEL` still works for Groq.
- `JUDIKT_LLM_API_KEY` overrides the provider's own key variable. Every key variable also accepts the `_SECRET_ARN`, `_VAULT_PATH`, and `_JSON_KEY` forms used elsewhere in Judikt, for example `ANTHROPIC_API_KEY_SECRET_ARN`.
- For `openai-compatible`, set `JUDIKT_LLM_BASE_URL` to the server's API root, for example `http://localhost:11434/v1` for Ollama. It must use HTTPS unless the host is loopback or `JUDIKT_LLM_ALLOW_INSECURE_HTTP=true` is set, and it must not contain credentials or a query string.
- `JUDIKT_LLM_TIMEOUT_SECONDS` (default `15`, at most `300`) gives slower self-hosted models more time.

Providers are opt-in. When `JUDIKT_LLM_PROVIDER` is unset, Judikt uses Groq only if a Groq key is configured, which was the behaviour before multi-provider support. An `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` already present in your shell never starts sending audit data on its own. Setting a provider explicitly without its key, naming an unknown provider, or giving an unsafe base URL stops startup with a one-line error. `JUDIKT_LLM_PROVIDER=none` turns summaries off even when a Groq key is present.

What is sent: at most 30 recent audit events and 256 KB, with secret-like keys and values redacted and operator diagnostics, which can contain upstream-controlled text, removed. Groq, OpenAI, Anthropic, and Gemini use fixed HTTPS endpoints. Any request failure, timeout, oversized response, or empty answer returns the local summary with a warning. The gateway keeps working if the provider is unavailable, and policy evaluation never depends on the model.

## Dashboard API

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Readiness check |
| `GET /api/tools` | List upstream MCP tools |
| `GET /api/events` | Read recent correlated audit events |
| `GET /api/kill-switches` | Read disabled tools and servers |
| `GET /api/telemetry` | Read OpenInference tracing mode and OTLP endpoint |
| `GET /api/audit-integrity` | Verify the local audit hash chain and signatures |
| `GET /metrics` | Prometheus-style counters |
| `POST /api/call` | Invoke a guarded tool |
| `POST /api/approval` | Issue a short-lived approval token |
| `POST /api/kill-switch` | Enable or disable a tool or server |
| `POST /api/analyze` | Summarize recent audit evidence |

Example:

```bash
curl -s http://127.0.0.1:8080/api/call \
  -H 'Content-Type: application/json' \
  -d '{"server":"platform-ops","tool":"platform.health","arguments":{"service":"payments-api"}}'
```

Issue a signed approval token for a rollback:

For local single-machine use, Judikt creates `$XDG_STATE_HOME/judikt/approval.key` (or `~/.local/state/judikt/approval.key`) atomically with mode `0600` inside a mode-`0700` directory. All local commands for the same OS user share that key. Judikt refuses incorrectly owned or group/world-readable key files and rejects approval secrets shorter than 32 bytes. Remote bindings, serverless deployments, and `JUDIKT_PRODUCTION=true` require an explicitly configured shared secret through `JUDIKT_APPROVAL_SECRET`, AWS Secrets Manager, or Vault; they never fall back to the per-machine key.

Approval tokens are single-use. Judikt records the token's hashed identifier atomically immediately before upstream execution; dry-run and shadow-mode evaluations do not consume it, while an attempted call remains consumed if the upstream later fails. Local single-instance gateways use SQLite. Remote and production gateways require Redis through `JUDIKT_REDIS_URL`, unless the operator explicitly declares `JUDIKT_SINGLE_INSTANCE=true`; the serverless gateway uses DynamoDB.

Remote control-plane authorization uses explicit `read`, `execute`, `approve`, and `admin` roles mapped to JWT scopes or groups. Static bearer authentication defaults to the `execute` role through `JUDIKT_HTTP_BEARER_ROLE`; granting `admin` is explicit and produces a startup warning. A static bearer token carries no user identity, so its callers are evaluated as `anonymous` unless `JUDIKT_HTTP_BEARER_SUBJECT` binds them to a policy identity. With a policy generated by `judikt init` or `judikt wrap`, set it to that policy's `local_stdio_identity` (default `local-operator`); otherwise the starter policy grants the HTTP caller no tools. The dashboard always requires `JUDIKT_API_TOKEN` for approval issuance and kill-switch changes, including on loopback.

```bash
TOKEN=$(./scripts/python.sh -m judikt.cli issue-approval \
  --actor gaurav \
  --reason "rollback after elevated 5xx rate" \
  --server platform-ops \
  --tool platform.rollback_deployment \
  --arguments '{"service":"payments-api","version":"payments-api@2026.05.2","actor":"gaurav","rollback_plan":"verify service health and restore previous release if errors increase"}')

curl -s http://127.0.0.1:8080/api/call \
  -H 'Content-Type: application/json' \
  -d "{\"server\":\"platform-ops\",\"tool\":\"platform.rollback_deployment\",\"arguments\":{\"service\":\"payments-api\",\"version\":\"payments-api@2026.05.2\",\"actor\":\"gaurav\",\"rollback_plan\":\"verify service health and restore previous release if errors increase\",\"approval_token\":\"$TOKEN\"}}"
```

## Docker

Build and run the production-facing real MCP container:

```bash
make docker-build
docker run --rm -p 8080:8080 \
  -v judikt-data:/app/data \
  -e JUDIKT_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)" \
  -e JUDIKT_APPROVAL_SECRET="$(openssl rand -hex 32)" \
  -e JUDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)" \
  -e JUDIKT_SINGLE_INSTANCE=true \
  judikt:local
```

The container binds to `0.0.0.0`, so it runs in remote mode and fails closed at startup unless all of these hold:

- bearer or JWT authentication is configured (or `JUDIKT_ALLOW_UNAUTHENTICATED_REMOTE=true` is set for an isolated lab);
- `JUDIKT_APPROVAL_SECRET` and an independent `JUDIKT_AUDIT_HMAC_SECRET` are set, each at least 32 bytes;
- approval tokens can be made single-use: set `JUDIKT_REDIS_URL` for more than one instance, or `JUDIKT_SINGLE_INSTANCE=true` for exactly one.

The image keeps all state (audit chain, approval replay store, kill switches, pins) under `/app/data`. Mount a volume there to keep it across restarts.

The container defaults to the official MCP Streamable HTTP server:

```text
GET  /healthz
GET  /metrics
POST /mcp
GET  /mcp
```

To run the dashboard container instead:

```bash
docker run --rm -p 8080:8080 \
  -v judikt-data:/app/data \
  -e JUDIKT_MODE=dashboard \
  -e JUDIKT_API_TOKEN="$(openssl rand -hex 24)" \
  judikt:local
```

Dashboard API clients must send `Authorization: Bearer $JUDIKT_API_TOKEN`.
The health endpoint and dashboard page remain unauthenticated; dashboard APIs
and `/metrics` are protected.

## Real MCP Server

Judikt now includes an official MCP SDK server using Streamable HTTP. It exposes production-operations tools through the same policy, risk, approval, redaction, audit, metrics, kill-switch, rate-limit, and circuit-breaker controls used by the rest of the project.

Run locally:

```bash
export JUDIKT_HTTP_BEARER_TOKEN="local-dev-token"
./scripts/run_real_mcp_http.sh --host 127.0.0.1 --port 8080
```

MCP endpoint:

```text
http://127.0.0.1:8080/mcp
```

Drive that endpoint through the repository's official Streamable HTTP client:

```bash
export JUDIKT_MCP_URL="http://127.0.0.1:8080/mcp"
./scripts/mcp_client.sh list
./scripts/mcp_client.sh call platform.health \
  --arguments '{"service":"payments-api"}'
```

The client reads bearer authentication from `JUDIKT_HTTP_BEARER_TOKEN`, prints the exact request and structured response, recursively hides sensitive response keys, and supports mode-`0600` files for approval tokens so they do not enter shell history or terminal output.

Production-style tools exposed by the MCP server:

- `platform.health`
- `platform.read_config`
- `platform.read_logs`
- `platform.run_diagnostic`
- `platform.restart_deployment`
- `platform.rollback_deployment`
- `kubernetes.get_pod`
- `kubernetes.restart_pod`
- `kubernetes.rollout_status`
- `incident.create`
- `incident.attach_evidence`
- `incident.timeline`
- `judikt.issue_approval`
- `judikt.request_approval`
- `judikt.approval_status`
- `judikt.call_upstream`
- `judikt.set_tool_enabled`
- `judikt.set_server_enabled`
- `judikt.runtime_state`

## AWS Free-Tier Deployment

The primary complete AWS path is Terraform-managed EC2 running the official Streamable HTTP MCP container, with ECR, IAM, Secrets Manager, SSM Session Manager, and encrypted EBS. The Lambda/API Gateway/DynamoDB/EventBridge/SQS stack is a separate serverless control-plane lab with CloudWatch and X-Ray; it exercises stronger AWS serverless skills but exposes an HTTP tool API rather than claiming to be the official MCP transport. The free-tier EC2 path is a restricted-CIDR lab endpoint, not a TLS-terminated public production endpoint.

Start with [docs/AWS_FREE_TIER_DEPLOY.md](AWS_FREE_TIER_DEPLOY.md) for the EC2 deployment path.

For JWT auth, Redis-backed rate limits, Grafana/Tempo/Jaeger, and Helm usage, see [docs/PRODUCTION_ENHANCEMENTS.md](PRODUCTION_ENHANCEMENTS.md).

Recommended serverless command shape:

```bash
export AWS_REGION=us-east-1
export JUDIKT_API_TOKEN="$(openssl rand -hex 24)"
export JUDIKT_APPROVAL_SECRET="$(openssl rand -hex 32)"
export JUDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_serverless.sh
```

Destroy the serverless deployment after demos:

```bash
./scripts/aws/destroy_serverless.sh
```

EC2 Terraform command shape:

```bash
export AWS_REGION=us-east-1
export JUDIKT_ALLOWED_CIDR="$(curl -s https://checkip.amazonaws.com)/32"
export JUDIKT_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)"
export JUDIKT_APPROVAL_SECRET="$(openssl rand -hex 32)"
export JUDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_terraform.sh
```

Destroy the Terraform deployment after demos:

```bash
./scripts/aws/destroy_terraform.sh
```

CloudFormation fallback:

```bash
export AWS_REGION=us-east-1
IMAGE_URI=$(./scripts/aws/build_push_ecr.sh)
./scripts/aws/deploy_ec2.sh "$IMAGE_URI"
```

Delete the CloudFormation stack after demos:

```bash
./scripts/aws/delete_stack.sh
```

## Optional OpenInference Tracing

The default demo has no third-party runtime dependencies. For AI-aware distributed traces, install the observability profile:

```bash
python3 -m pip install -e '.[observability]'
```

Print OpenInference-compatible spans to the terminal:

```bash
JUDIKT_TELEMETRY=console ./scripts/run_demo.sh
```

Export spans over OTLP HTTP to a local Phoenix instance or another OTLP-compatible backend:

```bash
export JUDIKT_TELEMETRY=otlp
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:6006/v1/traces
./scripts/run_dashboard.sh
```

The trace hierarchy is intentionally security-aware:

```text
judikt.call_tool                 CHAIN
  judikt.policy.evaluate         GUARDRAIL
  mcp.platform.health               TOOL       # only created for forwarded calls
llm.incident_summary                LLM        # only created when an LLM provider is called
```

Arguments and outputs are redacted before they are attached to spans. The remote server uses the official MCP Python SDK, while Judikt emits explicit policy, tool, and LLM spans so security decisions have stable attributes independent of auto-instrumentation. External stdio upstreams remain separate processes and do not yet propagate trace context across that process boundary.

## Demo Adapters

`judikt demo` includes three separate simulated tool servers for a deterministic walkthrough. They are not loaded by normal gateway commands:

- `platform-ops`: production service health, sanitized config, logs, allowlisted diagnostics, rolling restart, and deployment rollback.
- `kubernetes`: pod status, guarded pod restart, and rollout status. It uses a safe simulator by default and can be pointed at `kubectl` with `JUDIKT_KUBERNETES_MODE=kubectl` for a controlled lab.
- `incident`: create incidents, attach correlated evidence, and read timelines.

## Kubernetes Restart Safety

`kubernetes.restart_pod` models the same guarded workflow in simulator and `kubectl` modes. It validates DNS-1123 namespace and pod names, requires an explicit `kubernetes.context` for `kubectl`, resolves a ReplicaSet to its Deployment (or accepts a direct StatefulSet/DaemonSet owner), checks the workload availability floor, and refuses a matching PDB with zero allowed disruptions. Bare pods fail with `unowned_pod`; unsafe capacity fails with `would_cause_downtime`; blocked disruption budgets fail with `pdb_blocks`. A single-replica workload requires an explicit `allow_downtime: true`, which remains covered by approval argument hashing.

Production targets require `idempotency_key`. Judikt stores the exact result and returns it for a repeated key without evicting twice. The action uses the Kubernetes Eviction API; delete fallback is disabled unless `kubernetes.allow_delete_fallback` is explicitly enabled. It then waits for a different Ready pod under the same direct owner and for workload availability to recover to its pre-action level. Results use `status: verified`, `already_restarted`, `timed_out`, or `failed` and include `old_pod`, `new_pod`, `owner`, phase durations, and checks. Timeout and failure results are MCP errors and emit findings through the existing durable outbox.

```json
{
  "kubernetes": {
    "context": "production-us-east-1",
    "allow_delete_fallback": false,
    "subprocess_timeout_seconds": 20,
    "verification_timeout_seconds": 180,
    "poll_interval_seconds": 3
  }
}
```

`dry_run: true` still performs ownership, availability, and PDB preflight, then submits the eviction with `--dry-run=server`; it does not mutate the workload. Every `kubectl` invocation uses the configured `--context`, a fixed argument vector without a shell, and a bounded subprocess timeout.
