# Judikt Design Notes

These notes capture the main engineering choices behind Judikt and are useful for interview walkthroughs.

## Core Boundary

Judikt is a gateway, not an agent. It does not try to make the LLM smarter. It constrains what the agent can do when it reaches for production tools.

The central rule is:

```text
deterministic policy before execution, redaction before observability, audit after every decision
```

## Why The LLM Is Not In The Enforcement Path

The LLM can summarize recent audit evidence, but it cannot approve tool calls. Authorization needs to be deterministic, explainable, testable, and available when a hosted model API is down.

## Approval Tokens

Destructive operations can be approved with an HMAC token bound to:

- server
- tool
- exact arguments
- actor
- reason
- expiration time

The demo still accepts `approved: true` for quick walkthroughs, but the signed token flow is the production-shaped path.

## Risk Scoring

Each request receives a deterministic risk score. The policy's `risk` section defines tier baselines, annotation modifiers, tool-name rules, argument rules, severity thresholds, and optional approval actions. MCP annotations are untrusted: they may raise risk, but cannot lower the baseline implied by reviewed classification or a mutation-like tool name. Matched evidence is included in both the decision and audit record, keeping enforcement explainable without putting a model in the decision path.

## Observability

Judikt emits three kinds of evidence:

- SQLite audit events for durable local evidence.
- Prometheus metrics for aggregate operational signals.
- OpenInference-compatible spans for request-level trace explanation.
- AWS CloudWatch metrics/logs and X-Ray traces for serverless deployments.
- DynamoDB audit/state records and EventBridge/SQS findings for AWS operations.

Those are deliberately separate. Traces may be sampled; audits should not be.

## Production Upgrade Path

The current project includes a real MCP Streamable HTTP server, a guarded Kubernetes adapter, Redis-backed distributed rate limits, central audit export, a free-tier friendly EC2/Docker deployment, and a serverless AIOps control-plane variant. The next real upgrades are managed OIDC identity, TLS termination for the EC2 endpoint, OPA/Cedar policies, deeper Prometheus/Kubernetes integrations, and signed release provenance.
