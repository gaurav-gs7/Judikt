# Judikt Runbooks

These runbooks cover the main failure modes for the real MCP server and AWS serverless control plane.

## Runbook: High Blocked-Call Rate

Signal:

- CloudWatch alarm `*-blocked-calls`
- metric `BlockedCalls` rising
- many audit entries with `allowed=false`

Triage:

```bash
./scripts/run_failure_tests.sh
./scripts/run_evals.sh
```

AWS checks:

```bash
aws logs tail /aws/lambda/judikt-serverless-gateway --since 30m
aws dynamodb scan --table-name judikt-serverless-audit --limit 20
aws sqs receive-message --queue-url <findings_queue_url> --max-number-of-messages 10
```

Actions:

- confirm whether calls are malicious, misconfigured, or expected policy denials
- if a tool is being abused, run `judikt kill tool <name> --reason "<incident>"`
- if a server is unsafe, run `judikt kill server <name> --reason "<incident>"`
- confirm shared state and version with `judikt kill status`
- preserve audit evidence before changing policy

## Runbook: High-Risk Action Approved

Signal:

- CloudWatch alarm `*-high-risk-allowed`
- audit entry where `risk_level` is `high` or `critical` and `allowed=true`

Triage:

- confirm the approval token actor, reason, target tool, and arguments
- verify the token was bound to exact arguments
- attach audit evidence to an incident

Actions:

- rotate approval secret if the approval was suspicious
- disable the destructive tool until review completes
- validate rollback/restart outcome

## Runbook: Circuit Breaker Open

Signal:

- metric `CircuitBreakerOpen`
- `judikt.runtime_state` shows open circuit

Triage:

```bash
./scripts/run_failure_tests.sh
```

Actions:

- inspect `last_error`
- validate upstream tool adapter health
- wait for cooldown or restart service after fixing the root cause
- do not bypass circuit breakers for destructive tools

## Runbook: Real MCP Server Unavailable On EC2

Checks:

```bash
aws ssm start-session --target <instance-id>
sudo docker ps
sudo docker logs judikt --tail 100
curl -s http://127.0.0.1:8080/healthz
```

Common fixes:

- verify ECR image pull succeeded
- verify Secrets Manager values were readable by the instance role
- verify security group allows only your IP on port `8080`
- restart the container only after checking logs

## Runbook: Secret Exposure Suspected

Actions:

- rotate `approval-secret`
- rotate HTTP/API bearer token
- disable destructive tools
- search audit table or SQLite audit DB for leaked patterns
- add a redaction pattern and regression test
- rerun `./scripts/run_evals.sh`
