# Failure Testing

Judikt includes a failure-mode harness so safety controls can be tested without waiting for real incidents.

Run:

```bash
./scripts/run_failure_tests.sh
```

Covered failure modes:

- destructive rollback without approval is blocked
- kill switch blocks a normally safe tool
- circuit breaker opens after repeated upstream failures
- secret-like config data is redacted
- per-tool rate limit blocks excessive calls

Expected output:

```json
{
  "passed": true,
  "case_count": 5,
  "passed_count": 5
}
```

How this is used:

- locally before demos
- in CI as a regression gate
- before enabling any new destructive tool
- after policy or redaction rule changes

Why this exists:

> Safety controls are tested in their failure modes, not only on the happy path. The harness exercises approval gates, kill switches, circuit breakers, redaction, and rate limits.
