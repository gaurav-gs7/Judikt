# Runtime Architecture

Judikt currently exposes three guarded execution paths: the local stdio gateway,
the authenticated Streamable HTTP server, and the AWS serverless gateway. This
document records their pre-unification behavior and the target runtime contract.

## Current parity matrix

| Control or component | stdio gateway (`JudiktRuntime`) | HTTP server (`JudiktOpsRuntime`) | serverless (`serverless.py`) |
| --- | --- | --- | --- |
| Authentication | Local process boundary; no network authentication | Bearer/JWT authentication in HTTP middleware | API bearer token |
| Identity resolution | Explicit `trusted_actor` from `local_stdio_identity` | Authenticated request subject | Request actor after API authentication |
| Kill switch | In-memory policy state; no runtime helper | In-memory policy state and admin tools | DynamoDB runtime state |
| Circuit breaker | Missing | In-memory per server/tool circuit | DynamoDB runtime state |
| Policy allowlist and argument rules | `PolicyEngine` | `PolicyEngine` | `ServerlessPolicy`, derived from `PolicyEngine` |
| Rate limiting | Local or Redis through `PolicyEngine` | Local or Redis through `PolicyEngine` | DynamoDB fixed-window counter |
| Approval verification | Signed, argument-bound approval | Signed, argument-bound approval | Signed, argument-bound approval |
| Slack approval workflow | Missing | Available | Missing |
| Tool integrity and pinning | Verified before execution and after restart | Verified before execution and after restart | Not implemented |
| Approval replay prevention | SQLite or Redis store | SQLite or Redis store | DynamoDB approval state |
| Intent audit | Durable local audit store | Durable local audit store | Not a distinct pre-execution record |
| Upstream execution | Managed stdio subprocess clients | In-process demo adapters and configured stdio clients | Tool Lambda invocation |
| Inbound content inspection | Deterministic content guard | Deterministic content guard | Deterministic content guard |
| Result redaction | MCP-aware policy redaction | MCP-aware policy redaction | Policy redaction |
| Outcome audit | Signed local audit chain and optional durable sink | Signed local audit chain and optional durable sink | Signed DynamoDB audit event |
| Finding dispatch | Local dispatcher with configured integrations | Local dispatcher with configured integrations and incident annotation | EventBridge |
| Metrics and tracing | Local metrics and OpenTelemetry | Local metrics and OpenTelemetry | CloudWatch metrics; no shared tracing pipeline |

“Present” in this table does not imply a shared implementation. Before the
unification, stdio and HTTP independently orchestrate most controls and can
therefore drift even when they use the same lower-level classes.

## Post-unification parity

| Control or component | stdio gateway | HTTP server | serverless |
| --- | --- | --- | --- |
| Canonical guarded-call pipeline | Shared `GuardedCallPipeline` | Shared `GuardedCallPipeline` | Separate Lambda handler |
| Trusted identity provider | Local stdio identity | Authenticated request subject | API-authenticated request actor |
| Kill-switch adapter | Shared component contract | Shared component contract | DynamoDB state |
| Circuit breaker | Shared in-memory store | Shared in-memory store | DynamoDB state |
| Policy, integrity, approval replay, intent audit, inspection, redaction, findings, metrics | Shared ordering and implementation | Shared ordering and implementation | Shared policy primitives with Lambda-specific orchestration |
| Upstream registry | Managed stdio subprocesses | In-process adapters and configured stdio subprocesses | Tool Lambda invocation |
| Optional Slack workflow | Available | Available | Not implemented |

The remaining serverless differences are deliberate deployment-boundary gaps,
not a second local runtime. Closing them requires DynamoDB/Lambda adapters for
the pipeline component contracts rather than another copy of call orchestration.

## Target design

`GuardedCallPipeline` is the sole local/HTTP orchestrator for guarded tool calls.
It receives explicit components instead of selecting an entry point internally:

- `IdentityProvider` resolves a trusted local identity or the authenticated
  request subject. Tool arguments are never an implicit trusted identity.
- `UpstreamRegistry` lists and executes tools. Implementations support managed
  stdio subprocesses and in-process operational adapters; HTTP upstreams can be
  added without changing the pipeline.
- `ApprovalWorkflow` is optional. HTTP can expose Slack-backed approval while a
  local runtime can deliberately use no external workflow.
- `CircuitBreakerStore`, `KillSwitchStore`, `RateLimiter`, `AuditStore`,
  `FindingDispatcher`, and `Telemetry` are injected control-plane components.

`JudiktRuntime` and `JudiktOpsRuntime` remain public compatibility wrappers.
They construct the pipeline with entry-point-specific identity and upstream
components, then delegate call, evaluation, state, audit, metrics, and shutdown
operations. Existing callers do not need to migrate.

The AWS handler keeps its Lambda/DynamoDB execution shell because its storage and
invocation model differ. It must continue using the same policy primitives and
the canonical ordering wherever the Lambda boundary permits. Remaining
serverless differences stay visible in the parity matrix rather than being
hidden behind a misleading abstraction.

## Canonical control order

Every guarded execution entry point follows this order:

1. Authentication
2. Identity resolution
3. Kill switch
4. Circuit breaker
5. Policy: allowlist, argument rules, rate limit, and approval verification
6. Tool integrity
7. Approval consumption
8. Intent audit record
9. Execute
10. Content inspection
11. Redaction
12. Outcome audit and finding dispatch
13. Metrics

Authentication remains outside the core pipeline when the transport owns it,
but the pipeline accepts only the trusted identity produced by that step.

## Refactor plan

1. Introduce component protocols and upstream registry implementations without
   changing either runtime's public behavior.
2. Move the common guarded-call orchestration into `GuardedCallPipeline`, using
   the canonical order above and preserving result and audit formats.
3. Convert both runtime classes into compatibility wrappers and add missing
   circuit-breaker and approval-workflow support to stdio.
4. Add a scenario-driven parity suite that exercises stdio and HTTP-facing
   runtime configurations and verifies identical decisions.
5. Keep serverless behavior explicit, reuse shared policy primitives, and update
   this matrix whenever a remaining difference is closed.

## Intended behavior changes

Runtime unification intentionally adds only these controls to stdio:

- circuit breaking after repeated upstream failures, including cooldown
  recovery;
- the same optional Slack approval workflow and runtime-state helpers exposed by
  the HTTP runtime.

All other decisions, result shapes, audit evidence, and execution semantics are
compatibility requirements for the refactor.
