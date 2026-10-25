# AWS Tracing And Observability

Judikt has two tracing stories:

1. Local/OpenInference tracing for AI tool-governance spans.
2. AWS-native tracing for deployed services.

## Local OpenInference Tracing

Enable console spans:

```bash
JUDIKT_TELEMETRY=console ./scripts/run_demo.sh
```

Enable OTLP:

```bash
export JUDIKT_TELEMETRY=otlp
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:6006/v1/traces
./scripts/run_real_mcp_http.sh
```

Important spans:

- `judikt.call_tool`
- `judikt.real_mcp.call_tool`
- `judikt.policy.evaluate`
- `mcp.<tool_name>`
- `llm.incident_summary` (attributes `llm.provider` and `llm.model_name`)

## AWS Serverless Tracing

Terraform enables Lambda active tracing:

```text
tracing_config {
  mode = "Active"
}
```

Both gateway and tool Lambdas can publish traces to AWS X-Ray through `AWSXRayDaemonWriteAccess`.

Use traces to answer:

- Did API Gateway reach the gateway Lambda?
- Did the gateway invoke the tool Lambda?
- Was latency caused by cold start, DynamoDB, Secrets Manager, or tool execution?
- Did policy deny the call before the tool ran?

## Metrics

Serverless custom metrics:

- `AllowedCalls`
- `BlockedCalls`
- `HighRiskAllowedCalls`
- `ToolCallLatencyMs`
- `CircuitBreakerOpen`

Local/EC2 Prometheus-style metrics:

```bash
curl -H "Authorization: Bearer $JUDIKT_HTTP_BEARER_TOKEN" http://<host>:8080/metrics
```

## Design Rationale

> AI-aware tracing and cloud-native tracing are kept separate. OpenInference spans explain tool-governance decisions, while AWS X-Ray and CloudWatch explain infrastructure latency and failures.
