# Production Enhancements

This document covers the higher-signal production features added on top of the free-tier Judikt path.

## OAuth 2.1 Resource Server And JWT Auth

The real MCP HTTP server supports two authentication modes:

- Static bearer token for simple demos.
- JWT validation for production-style identity.

For remote JWT mode, Judikt acts as the protected resource server. The authorization server or IdP owns user login, authorization code flow, PKCE, client registration, and consent. Judikt validates the resulting access token and advertises protected-resource metadata at `/.well-known/oauth-protected-resource`.

Local HS256 JWT mode:

```bash
export JUDIKT_JWT_HS256_SECRET="local-jwt-secret"
export JUDIKT_JWT_ISSUER="https://issuer.example.test"
export JUDIKT_RESOURCE_URI="http://127.0.0.1:8080/mcp"
export JUDIKT_JWT_AUDIENCE="http://127.0.0.1:8080/mcp"
export JUDIKT_AUTHORIZATION_SERVER="https://issuer.example.test"
export JUDIKT_REQUIRED_SCOPES="mcp:tools"
export JUDIKT_JWT_REQUIRED_GROUP="sre"
export JUDIKT_ADMIN_SCOPE="mcp:admin"
export JUDIKT_ADMIN_GROUP="mcp-admin"
./scripts/run_real_mcp_http.sh
```

OIDC/Cognito-style RS256 mode uses JWKS and the optional `auth` dependency:

```bash
export JUDIKT_JWT_JWKS_URL="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>/.well-known/jwks.json"
export JUDIKT_JWT_ISSUER="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>"
export JUDIKT_JWT_AUDIENCE="<resource-audience-issued-by-your-idp>"
export JUDIKT_RESOURCE_URI="https://judikt.example.com/mcp"
export JUDIKT_AUTHORIZATION_SERVER="https://your-authorization-server.example.com"
export JUDIKT_REQUIRED_SCOPES="mcp:tools"
export JUDIKT_JWT_REQUIRED_GROUP="sre"
```

JWT mode fails startup unless issuer, audience, canonical resource URI, and authorization-server discovery are configured. Unauthorized responses advertise protected-resource metadata and required scopes. Requests that include an HTTP `Origin` header must match the canonical resource origin; set `JUDIKT_ALLOWED_ORIGINS` to a comma-separated allowlist when a separate browser application calls the MCP endpoint.

JWT identity is bound into policy evaluation. If a token subject is `readonly` and the tool arguments claim `actor=sre-oncall`, the call is denied with `identity_mismatch`. Fields such as `access_token`, `authorization`, and `upstream_token` are rejected recursively, so a caller token is never forwarded to an upstream service.

Static bearer mode remains useful for a single-user lab, but it is not presented as OAuth identity and cannot be enabled alongside JWT mode. Non-loopback binding fails at startup when neither mode is configured unless `JUDIKT_ALLOW_UNAUTHENTICATED_REMOTE=true` is explicitly set. Kill switches, direct approval administration, and audit runtime state require the `mcp:admin` scope or configured admin group for JWT callers.

## External MCP Servers And Credential Brokering

Set an upstream registry file:

```bash
export JUDIKT_UPSTREAM_CONFIG="$PWD/config/upstreams.example.json"
./scripts/run_mcp_gateway.sh
```

Each upstream command is started directly without a shell. Tool names must be globally unique, the complete definitions are scanned and pinned, and pins are rechecked before every call. Use `JUDIKT_TOOL_PIN_MODE=refresh` only during an intentional reviewed upgrade, then return to `enforce`.

Stdio upstreams use concurrent request correlation, continuously drain stderr into a bounded diagnostic buffer, and enforce 30-second initialization/list deadlines plus a 120-second call deadline. `JUDIKT_UPSTREAM_TIMEOUT_SECONDS` overrides all three globally. A registry entry can override them independently:

```json
{"timeouts": {"initialize": 30, "list": 30, "call": 120}}
```

On timeout, Judikt sends `notifications/cancelled` and audits `upstream_timeout`. Crashed or protocol-violating subprocesses restart with 1, 2, 4, 8, then 16-second backoff, no more than five times per five minutes. Tool definitions are re-verified against their pins after every restart and before the waiting call proceeds. Prometheus exports `judikt_upstream_timeouts_total`, `judikt_upstream_restarts_total`, and `judikt_upstream_protocol_violations_total` by server.

Secret-looking environment values cannot be literals in the registry. Use either:

```json
{"UPSTREAM_TOKEN": {"from_env": "OPERATOR_MANAGED_TOKEN"}}
```

or:

```json
{"UPSTREAM_TOKEN": {"from_aws_secret": "judikt/upstreams/github", "json_key": "token"}}
```

or a Vault KV v1/v2 path:

```json
{"UPSTREAM_TOKEN": {"from_vault": "secret/data/judikt/github", "json_key": "token"}}
```

The same broker resolves HTTP bearer, HS256 JWT, approval-signing, audit-signing, Slack, Argus, and SIEM credentials. Exactly one direct, AWS, or Vault source may be configured for each secret; ambiguous configuration fails startup. Vault requires HTTPS except on loopback, bounds responses to 1 MiB, supports namespaces, and normalizes errors without exposing response bodies or tokens.

```bash
export JUDIKT_VAULT_ADDR="https://vault.example.com"
export JUDIKT_VAULT_TOKEN_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:vault-client-token"
export JUDIKT_SLACK_SIGNING_SECRET_VAULT_PATH="secret/data/judikt/slack"
export JUDIKT_SLACK_SIGNING_SECRET_JSON_KEY="signing_secret"
```

`JUDIKT_VAULT_TOKEN` can be injected by a Vault Agent or workload runtime instead of being stored directly in shell history. For local-only Vault development, `JUDIKT_VAULT_ALLOW_INSECURE_HTTP=true` permits non-loopback HTTP deliberately; production should keep it unset.

Local source installs that use Secrets Manager or the S3 audit sink need the AWS profile:

```bash
python3 -m pip install -e '.[aws]'
```

The production container includes this profile. Lambda uses the AWS-managed `boto3` runtime dependency.

The official Streamable HTTP server exposes these configured servers through `judikt.call_upstream`; the stdio gateway transparently advertises their original tools.

## Slack Human Approval

Configure a Slack app with interactivity enabled and set its request URL to:

```text
https://<gate-host>/integrations/slack/actions
```

Set:

```bash
export JUDIKT_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export JUDIKT_SLACK_SIGNING_SECRET="..."
export JUDIKT_SLACK_APPROVER_IDS="U012345,U067890"
export JUDIKT_SLACK_MAX_PENDING_PER_REQUESTER=5
```

The webhook and signing secret can instead use `JUDIKT_SLACK_WEBHOOK_SECRET_ARN`, `JUDIKT_SLACK_SIGNING_SECRET_ARN`, or the corresponding `*_VAULT_PATH` settings described above.

The agent calls `judikt.request_approval`, an authorized engineer chooses Approve or Deny, and the original authenticated requester polls `judikt.approval_status`. Callback signatures and timestamps are verified, identical pending requests are deduplicated, and the issued token remains bound to the exact server, tool, argument digest, requester, and expiry. Direct token issuance through the remote tool is disabled unless `JUDIKT_ALLOW_DIRECT_APPROVAL=true` is deliberately set.

## Tamper-Evident Audit Shipping

Local records form a SHA-256 chain. Set `JUDIKT_AUDIT_HMAC_SECRET` to add an independent HMAC signature and verify it through `/api/audit-integrity` or `judikt.runtime_state`.

Production startup can require that key and verify all existing records before accepting traffic:

```bash
export JUDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
export JUDIKT_AUDIT_SIGNATURE_REQUIRED=true
export JUDIKT_AUDIT_VERIFY_ON_STARTUP=true
```

Missing signing material or a changed historical row then fails startup. The report distinguishes legacy unsigned events from sealed events.

Ship redacted envelopes to JSONL:

```bash
export JUDIKT_AUDIT_SINK=jsonl
export JUDIKT_AUDIT_JSONL_PATH=/var/log/judikt/audit.jsonl
```

Or S3:

```bash
export JUDIKT_AUDIT_SINK=s3
export JUDIKT_AUDIT_S3_BUCKET=<audit-bucket>
export JUDIKT_AUDIT_S3_PREFIX=judikt/audit
export JUDIKT_AUDIT_SINK_STRICT=true
```

The serverless deployment stores individually HMAC-signed envelopes in DynamoDB and reports verification of recent events in `/state`. S3 Object Lock is not provisioned by this repository, so the S3 sink is centrally durable but not automatically immutable.

Or a generic HTTPS SIEM/webhook receiver:

```bash
export JUDIKT_AUDIT_SINK=siem
export JUDIKT_SIEM_URL="https://siem.example.com/api/events"
export JUDIKT_SIEM_TOKEN_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:judikt-siem"
export JUDIKT_SIEM_HMAC_SECRET_VAULT_PATH="secret/data/judikt/siem"
export JUDIKT_SIEM_HMAC_SECRET_JSON_KEY="hmac"
export JUDIKT_AUDIT_SINK_STRICT=true
```

For Splunk HTTP Event Collector, set `JUDIKT_SIEM_PROTOCOL=splunk_hec` and point `JUDIKT_SIEM_URL` at `/services/collector/event`. Generic JSON uses bearer authentication; Splunk uses HEC authentication. Both contracts include a SHA-256 body digest, and `JUDIKT_SIEM_HMAC_SECRET` or its brokered equivalent adds `X-Judikt-Signature-256`. Non-loopback HTTP, URL credentials, query tokens, malformed protocols, and invalid timeouts fail closed.

Interview angle:

> Judikt separates transport authentication from tool authorization. JWT proves caller identity at the HTTP boundary; policy-as-code still decides which actor can run each tool.

## Redis-Backed Distributed Rate Limits

Local mode uses an in-process limiter. Production mode can use Redis:

```bash
export JUDIKT_REDIS_URL="redis://localhost:6379/0"
export JUDIKT_REDIS_REQUIRED=true
```

The policy engine applies rate limits by tool, actor/tool, production environment/tool, and optional global budget. Redis makes those counters shared across replicas.

The Redis operation uses one atomic Lua script for increment and expiry. Logical keys are SHA-256 hashed before storage, so actor names are not exposed in the Redis keyspace. CI starts Redis 7 and proves that two separate limiter instances consume the same limit.

## Argus Incident And RCA Integration

A security control is more useful when a malicious tool attempt enters the incident pipeline. Configure the real MCP runtime to send selected findings to Argus's actual Alertmanager ingestion endpoint:

```bash
export JUDIKT_ARGUS_URL="https://argus.example.com"
export JUDIKT_ARGUS_TOKEN_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:argus-service-token"
export JUDIKT_ARGUS_HMAC_SECRET="independent-proxy-verification-key"
```

For local Argus development, `JUDIKT_ARGUS_API_TOKEN` can hold the operator-managed service token directly. Caller JWTs, OAuth tokens, tool arguments, results, and raw injected text are never forwarded. The Alertmanager envelope contains policy metadata, correlation ID, risk score, and SHA-256 evidence hashes.

Flow:

```text
blocked MCP call
  -> signed Judikt audit record
  -> durable SQLite finding outbox
  -> authenticated Alertmanager POST
  -> Argus dedupe/grouping
  -> incident + signal + timeline
  -> Argus RCA and remediation workflow
```

Failed HTTP deliveries remain in the outbox and a background worker retries them with exponential backoff. Only an error hash is retained. Repeated instances of the same server/tool/rule are grouped into a five-minute dedupe window instead of creating one incident per request. `judikt.runtime_state` exposes pending, retrying, and delivered counts, while `judikt_findings_total` exposes initial delivery outcomes to Prometheus. Routine `approval_required` decisions and successful critical actions do not page on-call by default; security, integrity, identity, rate-limit, circuit, and kill-switch rules do. Override the denied-rule set with `JUDIKT_FINDING_RULES`, the dedupe window with `JUDIKT_FINDING_DEDUPE_WINDOW_SECONDS`, or deliberately include successful critical actions with `JUDIKT_FINDING_INCLUDE_ALLOWED_CRITICAL=true`.

Non-loopback HTTP is rejected by default. Use HTTPS in production. `JUDIKT_ARGUS_ALLOW_INSECURE_HTTP=true` exists only for a trusted internal lab network.

The AWS serverless deployment has the cloud-native equivalent: versioned, hash-only finding envelopes go to EventBridge and then SQS/DLQ.

## MCP-AttackBench-Compatible Evaluation

Run the bundled adapter smoke profile:

```bash
make attackbench-smoke
```

The smoke corpus proves parsing, classification, metrics, thresholds, and report privacy; it is deliberately not advertised as a score on the 70,448-sample independent corpus. See [ATTACKBENCH.md](ATTACKBENCH.md) for the full-corpus command, field mapping, CI evidence, and interpretation limits.

## Performance Evidence

Run the full in-process guarded-call benchmark:

```bash
make performance-smoke
./scripts/run_performance_benchmark.sh build/performance-local.json \
  --iterations 500 --warmup 50
```

It measures a direct built-in backend baseline and the complete Judikt pipeline: policy and authorization, risk scoring, local rate limiting, metadata pin verification, tool execution, inbound scanning, redaction, signed hash-chain SQLite audit, and metrics. HTTP/JWT, remote MCP latency, Redis, SIEM, Argus, S3, and OTLP are deliberately excluded and named in the report.

The dated local evidence and interpretation rules are in [PERFORMANCE.md](PERFORMANCE.md). CI runs a low-flake smoke gate and uploads the JSON report; do not present the local result as a networked or multi-replica production SLA.

## Observability Stack

Run the local observability stack:

```bash
make observability-up
```

Services:

- Judikt: http://127.0.0.1:8080
- Prometheus: http://127.0.0.1:9090
- Grafana: http://127.0.0.1:3000, admin/admin
- Tempo: http://127.0.0.1:3200
- Jaeger UI: http://127.0.0.1:16686
- Redis: 127.0.0.1:6379

Judikt emits Prometheus metrics at `/metrics` and OTLP traces to Tempo by default in this stack. Jaeger is included as an alternate trace UI/collector for demos that prefer Jaeger.

## Helm Chart

Render the chart:

```bash
make helm-template
```

Install into a lab cluster:

```bash
helm upgrade --install judikt ./charts/judikt \
  --set image.repository=<your-image-repo> \
  --set image.tag=<tag> \
  --set auth.bearerToken=<token> \
  --set auth.resourceUri=https://judikt.example.com/mcp \
  --set approvalSecret=<approval-secret> \
  --set audit.hmacSecret=<independent-audit-secret>
```

The chart fails during rendering when authentication, approval signing, audit signing, or the public MCP resource URI is missing. JWT/JWKS deployments additionally require `auth.jwtIssuer`, `auth.jwtAudience`, and `auth.authorizationServer` instead of `auth.bearerToken`.

Useful production values:

```bash
--set redis.url=redis://redis-master.default.svc.cluster.local:6379/0
--set telemetry.mode=otlp
--set telemetry.otlpEndpoint=http://tempo.default.svc.cluster.local:4318/v1/traces
--set serviceMonitor.enabled=true
```

Interview angle:

> The same real MCP server can run locally, on AWS EC2, or as a Kubernetes workload via Helm, with consistent policy, auth, metrics, tracing, and rate-limit behavior.
