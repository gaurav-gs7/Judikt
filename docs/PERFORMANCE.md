# Performance Evidence

Judikt includes a reproducible benchmark for the overhead added around one allowed built-in MCP tool call. The command writes machine-readable JSON and can enforce conservative p99 and throughput thresholds in CI.

```bash
./scripts/run_performance_benchmark.sh build/performance-local.json \
  --iterations 500 \
  --warmup 50 \
  --max-p99-ms 100 \
  --min-throughput 10
```

## Measured Scope

The guarded measurement includes:

- deterministic policy and actor authorization
- risk scoring and local rate limiting
- tool metadata inspection and pin-file verification
- built-in tool execution
- inbound prompt-injection scanning
- recursive redaction
- HMAC-signed, SHA-256-chained SQLite audit commit
- Prometheus metric accounting

The report excludes HTTP transport, JWT validation, external MCP/network latency, Redis, SIEM, Argus, S3, and OTLP exporters. Rate-limit budgets are raised in the temporary policy so the benchmark measures successful enforcement overhead rather than intentionally triggering throttling. Temporary databases, pins, policies, and secrets are isolated and removed after each run.

## Latest Result (0.4.0)

Measured on 2026-10-28 with 50 warm-ups and 500 measured calls on a 2-vCPU Linux x86_64 cloud container with CPython 3.12.3, after the learned classifier and the provenance gate were added: mean 3.150 ms, p50 2.917 ms, p95 4.379 ms, p99 5.242 ms, maximum 6.596 ms, 317.32 calls/second. Evidence: [evidence/performance-2026-10-28.json](evidence/performance-2026-10-28.json). It ran on different hardware from the result below, so the two are not a like-for-like comparison.

## Earlier Local Result

Measured on 2026-07-22 using CPython 3.14.0 on Darwin arm64. This was a local, single-process run with 50 warmups and 500 measured `platform.health` calls.

| Metric | Result |
| --- | ---: |
| Guarded mean latency | 0.704 ms |
| Guarded p50 latency | 0.684 ms |
| Guarded p95 latency | 0.922 ms |
| Guarded p99 latency | 1.022 ms |
| Maximum latency | 1.790 ms |
| Throughput | 1,419.49 calls/second |
| Verified signed audit events | 550/550 |

The direct in-memory backend baseline rounded to 0.000 ms at mean and p99, so the estimated guard overhead was 0.704 ms mean and 1.022 ms p99 for this run.

These numbers are evidence about this exact workload and environment, not a production SLA. A production report should add remote MCP workloads, concurrent clients, HTTP/JWT cost, Redis, enabled exporters, sustained soak time, and percentile history across repeated runs.

## CI Contract

GitHub Actions runs 25 measured calls after 5 warmups with deliberately loose smoke thresholds of 100 ms p99 and 10 calls/second. The goal is regression detection across shared runners, not marketing-grade performance comparison. The `judikt-ci-evidence` artifact contains both performance and attack-benchmark JSON.

The CLI exits nonzero when either configured threshold fails:

```bash
PYTHONPATH=src python3 -m judikt.cli performance \
  --max-p99-ms 25 \
  --min-throughput 100 \
  --output build/performance-report.json
```
