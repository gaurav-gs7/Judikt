# Developing and Testing Judikt

Running from a checkout, the demo and dashboard, and the test suites. Back to the [README](../README.md).

## Running from a checkout

The launch scripts automatically use `.venv/bin/python` when a project virtual environment exists. Otherwise, they use the system `python3`.

To use an isolated audit database for a run:

```bash
./scripts/run_demo.sh --audit-db /tmp/judikt-demo.db
```

```bash
./scripts/run_demo.sh
```

Common developer commands:

```bash
make test
make demo
make demo-explainer
make demo-recording
make eval
make attackbench-smoke
make performance-smoke
make failure-test
make interop-community
make trace
make observability-up
make helm-template
```

`make test` is the canonical release gate for all Tier 1, Tier 2, and Tier 3 work. It provisions isolated Redis and Vault containers, runs the complete unit/integration/end-to-end suite once, enforces aggregate and security-critical branch coverage, executes adversarial and failure drills, measures guarded-call performance, and verifies the pinned official Filesystem and Memory MCP servers. Existing Redis and Vault endpoints can be supplied through `JUDIKT_TEST_REDIS_URL`, `JUDIKT_TEST_VAULT_ADDR`, and `JUDIKT_TEST_VAULT_TOKEN`.

Start the dashboard:

```bash
./scripts/run_dashboard.sh
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080). The page includes buttons for allowed calls, blocked calls, an approved rollback drill, secret redaction, and kill-switch testing.

Loopback is the only unauthenticated mode. Binding to any other interface fails
closed unless `JUDIKT_API_TOKEN` is set. The browser asks for the token once
and keeps it in session storage.

To expose upstreams from a persistent [`config/upstreams.example.json`](../config/upstreams.example.json) configuration instead of the one-line wrapper:

```bash
./scripts/run_mcp_gateway.sh
```

For a checkout-based MCP client configuration, use:

```json
{
  "mcpServers": {
    "judikt": {
      "command": "/absolute/path/to/Judikt/scripts/run_mcp_gateway.sh"
    }
  }
}
```

## Tests

```bash
PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v
```

The suite exercises the actual subprocess MCP boundary as well as allow, deny, redaction, approval, kill-switch, circuit-breaker, audit, and fallback-analysis behavior.

Run the [skill acceptance suite](SKILL_ACCEPTANCE.md) against a fresh wheel installation:

```bash
./scripts/run_skill_acceptance.sh
```

Run the adversarial eval harness:

```bash
./scripts/run_evals.sh
```

The evals cover unsafe diagnostics, direct prompt injection, token passthrough, unapproved destructive actions, unknown tools, safe diagnostics, health checks, and audit redaction. The report also validates all 38 entries in [`config/mcp38_coverage.json`](../config/mcp38_coverage.json): currently 12 covered, 21 partial, and 5 explicitly not covered under the definition stored in that file.

The separate [MCP-AttackBench-compatible evaluator](ATTACKBENCH.md) reads JSONL, JSON, CSV, or optional Parquet datasets and reports accuracy, precision, recall, F1, false-positive/negative rates, per-category coverage, latency percentiles, throughput, and input/policy digests. Judikt publishes a pinned result for all 1,053 rows in GenTelLab's public development file and labels its low recall openly; the authors' 70,448-sample MCP-AttackBench corpus remains unreleased and is not claimed as evaluated.

Run the failure-mode harness:

```bash
./scripts/run_failure_tests.sh
```

It validates approval gates, kill switches, circuit breakers, redaction, and rate limits.
