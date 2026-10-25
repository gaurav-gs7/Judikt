# Judikt Demo Recordings

The repository ships two recordings with different jobs:

- **The two-minute explainer** in the README is for someone deciding whether Judikt matters to them. It runs the published package against a deliberately misbehaving MCP server.
- **The 150-second hybrid walkthrough** is the deep tour of the remote deployment: the Streamable HTTP server, bearer auth, incidents, metrics and qualification suites.

## Two-minute explainer (README)

![Judikt explainer poster](assets/judikt-demo-poster.png)

| File | What it is |
| --- | --- |
| `docs/assets/judikt-demo.gif` | README loop, 960 px wide, 8 fps |
| `docs/assets/judikt-explainer.mp4` | Full quality, 1920 x 1080, 30 fps, about two minutes |
| `docs/assets/judikt-demo-poster.png` | 1280 x 720 still of the control-plane scene |
| `docs/assets/judikt-demo-short.mp4` | 37-second cut for social posts, from an earlier capture of the same package. `make demo-explainer` does not regenerate it. |

### Structure

1. **Introduction:** what Judikt is, then agents moving from answering to acting, then the question: who decides what an agent with production access may do?
2. **Why it matters:** how MCP connects agents to tool servers; three failure modes: excessive agency (OWASP LLM06:2025), prompt injection (OWASP LLM01:2025), and missing accountability; and where Judikt sits.
3. **Live demo, nine steps:** read-only wrapping; reads allowed and deletes denied; human-signed approval tokens bound to their exact arguments; single use; an upstream that hangs after logging a token leaks nothing to the agent (OWASP LLM02); a live kill switch; tool-definition drift stopping startup; injection quarantine, framed as a tripwire; and signed audit verification catching a tampered row.
4. **Honest limits:** detection rates on independent benchmarks (0.8% BIPIA, 0% InjecAgent), where the guarantees really come from, and that this is a reference implementation.

### How it is made honest

`scripts/explainer/capture.py` drives `judikt wrap` over stdio against `scripts/explainer/github_mcp_fixture.py`. That is a scripted GitHub-like server which returns an injected README, logs a fake token and then hangs, and can change a tool description on request. Every Judikt component in the run is the real package; the fixture is the only scripted part. The script records each decision, along with the drift report and both audit verifications, in `scripts/explainer/capture.json`.

`scripts/explainer/render.py` draws the video from that file. Every terminal result line (rule names, results, error text, exit codes, verification output) is read from `capture.json`. The explanatory side panels, the `#` comment lines, timing, and the trimming of long strings are editorial. The committed capture came from `judikt 0.3.0` installed from PyPI. Correlation IDs aside, a capture from the source tree matches it exactly.

### Reproduce it

```bash
python3 -m pip install -e '.[media]'      # Pillow; also needs ffmpeg, fonts-inter and fonts-dejavu-core
make demo-explainer                        # capture from the source tree, then render into docs/assets
```

To film a published release instead, capture with that build and label it:

```bash
python3 scripts/explainer/capture.py --judikt "$(command -v judikt)" --source PyPI
python3 scripts/explainer/render.py
```

The capture uses a throwaway home directory and touches no network service. A full render takes about two minutes.

## Full 150-second hybrid walkthrough

The full walkthrough deliberately uses two visual modes:

- Polished product slides explain the problem, purpose, control model, trust boundaries, production operability, and conceptual architecture.
- Terminal slides are mandatory whenever real input, processing, backend execution, output, metrics, or audit evidence is shown.

This keeps the story understandable without disguising runtime behavior as a product mockup.

### Timeline

The generated GIF is exactly 150 seconds and loops automatically.

1. Product introduction: what Judikt is and where it sits.
2. Production problem: overreach, confused-deputy risk, poisoned results, and weak evidence.
3. Request governance: identity, policy, risk, approval, rate limits, and blast-radius controls.
4. Response defense: definition pinning, injection scanning, quarantine, and redaction.
5. Trust boundaries: caller, gateway, MCP server, brokered credentials, and evidence systems.
6. Production operability: observability, persistence, deployment automation, and qualification.
7. Conceptual flowchart: agent to request gate, MCP server, response gate, and evidence fan-out.
8. Explicit handoff from explanation to captured terminal proof.
9. Real server launch, readiness, bearer-auth rejection, and official MCP discovery commands.
10. Actual allow, redaction, denial, approval, approved execution, dry-run, quarantine, and kill-switch commands.
11. Signed audit-chain, tool-pin, finding-delivery, and Prometheus evidence commands.
12. Incident creation, correlated evidence attachment, and timeline retrieval commands.
13. Live rate-limit exhaustion and circuit-breaker opening commands.
14. Real failure-drill, AttackBench, performance, remote MCP, and JWT qualification commands.
15. Polished closing summary.

Major outcomes remain visible for at least five seconds.

### Terminal proof

`scripts/record_demo.py` starts the production-facing MCP server as a real process:

```bash
./scripts/run_real_mcp_http.sh --policy "$TMP/policy.json" --audit-db "$TMP/audit.db" \
  --host 127.0.0.1 --port "$PORT" --log-level warning
```

It then runs 26 separate shell commands against that live process or an isolated qualification harness. Representative commands include:

```bash
curl -fsS "$JUDIKT_BASE_URL/healthz"
./scripts/mcp_client.sh list
./scripts/mcp_client.sh call platform.health --arguments '{"service":"payments-api"}'
./scripts/mcp_client.sh call platform.rollback_deployment --arguments-file config/demo/rollback.json
./scripts/mcp_client.sh call judikt.call_upstream --arguments-file config/demo/external-poisoned-response.json
./scripts/mcp_client.sh call judikt.runtime_state --arguments '{"limit":2}' \
  --select audit_integrity.valid --select audit_integrity.checked_events
./scripts/run_failure_tests.sh
./scripts/run_attackbench.sh tests/fixtures/attackbench_smoke.jsonl "$TMP/attackbench.json"
./scripts/run_performance_benchmark.sh "$TMP/performance.json" --iterations 25 --warmup 5
```

Each command and its combined stdout/stderr are captured as a pair. The renderer adds the green `$` prompt only to the exact command it executed; command output is rejected if it contains a fabricated prompt. Generation also fails unless the captures prove:

1. The official Streamable HTTP MCP transport initialized and advertised the real tool catalog.
2. Missing bearer authentication received HTTP `401`.
3. A safe production health read executed and returned a backend result.
4. A returned API key was redacted.
5. Unsafe arguments were denied before upstream execution.
6. A production rollback returned `REQUIRE_APPROVAL`.
7. A mode-`0600` token file authorized only the exact approved rollback without printing the token.
8. Kubernetes remediation returned `DRY_RUN_ONLY` without mutation.
9. A controlled external MCP response was quarantined without unsafe-text exposure.
10. An operator kill switch blocked a normally allowed tool and was then restored.
11. Eight events passed HMAC-signed hash-chain verification and appeared in Prometheus counters.
12. External tool metadata remained pinned and verified.
13. An incident was created, given correlated evidence, and read back through its timeline.
14. The live remote server enforced its per-tool rate limit and opened a circuit after repeated upstream failures.
15. Approval, kill-switch, circuit-breaker, redaction, and rate-limit failure drills passed.
16. The eight-sample AttackBench-compatible CI smoke thresholds passed without raw payloads in its report.
17. The guarded performance smoke threshold passed with a valid signed audit chain.
18. The complete Streamable HTTP and JWT authorization end-to-end suites passed.

### Reproduce it

Run the compact local walkthrough directly:

```bash
./scripts/run_demo.sh --audit-db /tmp/judikt-demo.db
```

Regenerate the complete 150-second hybrid walkthrough:

```bash
python3 -m pip install -e '.[mcp,media]'
make demo-recording
```

This writes:

- `docs/assets/judikt-walkthrough.gif`: looping 1280 x 720 hybrid walkthrough.
- `docs/assets/judikt-walkthrough-poster.png`: static 1280 x 720 product cover.

These files are generated on demand and are not committed; the README uses the explainer above.

The renderer enforces an exact 150,000 ms duration and fails if the terminal sequence leaves insufficient room for the final five-second close.

### Safety and accuracy

The recorder creates a temporary policy, SQLite audit database, tool-definition pin store, bearer token, approval secret, independent audit-signing secret, and mode-`0600` approval-token file. The poisoned response comes from `tests/fixtures/external_mcp_server.py`, which runs as a separate JSON-RPC stdio process behind the real HTTP MCP server. No cloud, LLM API, or production endpoint is contacted, and all temporary state is deleted after capture.

The platform and Kubernetes operations use deterministic local adapters; Kubernetes remains non-mutating unless explicitly switched to `kubectl` mode. The official MCP transport, bearer boundary, policy outcomes, approval verification, external subprocess call, response inspection, redaction, kill switch, metrics, and signed audit path shown in the terminal are the real project implementation.

### Publishing caption

> Judikt in 150 seconds: product context and architecture first, followed by actual commands against a live Streamable HTTP MCP server, deterministic verdicts, backend results, poisoned-response quarantine, failure drills, metrics, and signed audit verification.
