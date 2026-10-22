# MCP-AttackBench Evaluation

Judikt includes a reproducible adapter for labeled MCP security datasets, including the input and metric shape needed to evaluate an acquired MCP-AttackBench corpus. The evaluator runs the same deterministic content and argument controls used in the gateway; it does not use an LLM judge.

The [MCP-AttackBench paper](https://arxiv.org/abs/2508.10991) reports 70,448 samples across jailbreak, prompt injection, cross-origin escalation, tool manipulation, command injection, data exfiltration, SQL injection, and related attacks. The [ACL Findings paper](https://aclanthology.org/2026.findings-acl.240/) defines accuracy, precision, recall, F1, and average latency as evaluation metrics.

## Published Results And Availability

As of 2026-10-22, the authors' official framework repository still marks release of the MCP-AttackBench data as incomplete. Its only public data file is `test_data/dev.csv`: 1,053 binary-labeled descriptions at commit `4bc97790256280480cf827c0a0fdb85e86754dfb`. The file has no attack-category or MCP-surface field, and the repository does not identify it as the complete corpus.

Judikt evaluated every row in that public file and publishes the reproducible result in [`docs/evidence/attackbench-gentellab-public-dev-2026-10-22.json`](evidence/attackbench-gentellab-public-dev-2026-10-22.json). The result is deliberately reported as an evaluation of the authors' public development file, not as MCP-AttackBench.

| Evidence | Samples | Precision | Recall | F1 | Claim |
| --- | ---: | ---: | ---: | ---: | --- |
| Tier 2 CI smoke profile | 8 | 1.0 | 1.0 | 1.0 | Parser, detector, metrics, threshold, and privacy regression only |
| GenTelLab public `dev.csv` | 1,053 | 1.0 | 0.004630 | 0.009217 | Complete run of the repository's public development file; broad unsafe-content labels, not the full benchmark |
| Full MCP-AttackBench | 70,448 expected | Not run | Not run | Not run | Corpus is not publicly released by its authors as of 2026-10-22 |

The low public-development recall is not hidden: Judikt detected 2 of 432 positive labels and produced no false positives. This shows that its deterministic MCP injection and exfiltration rules are not a general harmful-intent classifier. The result is useful negative evidence, but it cannot substitute for the categorized MCP benchmark promised by the paper.

CI stores the smoke JSON inside the `judikt-ci-evidence` artifact. A full result is publishable only when the report records `sample_count: 70448` and the input digest of the independently acquired corpus.

## Reproduce The Public Development Run

```bash
git clone https://github.com/GenTelLab/MCP-Guard /tmp/gentellab-mcp-guard
PYTHONPATH=src ./scripts/python.sh scripts/run_gentellab_public_eval.py \
  /tmp/gentellab-mcp-guard \
  --output build/attackbench-gentellab-public-dev.json
```

The script pins the upstream commit, SHA-256 digest, and expected 1,053 rows. It fails instead of publishing if any of those inputs drift.

## Run The Full Corpus When Released

JSON, JSONL, NDJSON, and CSV work without another dependency:

```bash
PYTHONPATH=src ./scripts/python.sh -m judikt.cli attackbench \
  /path/to/mcp-attackbench.jsonl \
  --dataset-id mcp-attackbench-2508.10991 \
  --expected-samples 70448 \
  --payload-field payload \
  --label-field label \
  --category-field category \
  --surface-field surface \
  --min-recall 0.90 \
  --output build/mcp-attackbench.json
```

Parquet streams records in 4,096-row batches and uses the optional benchmark profile:

```bash
python3 -m pip install -e '.[benchmark]'
```

Field arguments support dotted paths such as `sample.attack.payload`. Without explicit mappings, the adapter recognizes common names including `payload`, `text`, `label`, `is_attack`, `category`, and `surface`.

## Detection Path

For each record, the evaluator:

1. Canonicalizes the nested payload for a SHA-256 sample identifier.
2. Scans every string using the production `ContentGuard` rules.
3. On argument surfaces, also applies blocked argument patterns and recursive caller-credential detection.
4. Measures detector latency with a monotonic nanosecond timer.
5. Calculates TP, FP, TN, FN, accuracy, precision, recall, F1, FPR, and FNR.
6. Groups the metrics by attack category and MCP surface.
7. Writes only hashes and classification metadata for misses; raw prompts never enter the report.

`--expected-samples` prevents an incomplete subset from being mislabeled as a full result. `--min-precision`, `--min-recall`, and `--min-f1` turn the evaluator into a CI release gate.

## Interpretation

This adapter measures deterministic detection coverage, not the entire gateway. Some MCP-AttackBench scenarios require session context, caller identity, or a before/after tool definition. Those controls are tested separately by the OAuth, origin, metadata-pinning, and interoperability suites. A published report should therefore include both the benchmark output and the standard Judikt test evidence.
