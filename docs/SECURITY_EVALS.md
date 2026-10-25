# Security Evals And MCP-38 Coverage

Judikt maps its controls to the 38 threat categories in *MCP-38: A Comprehensive Threat Taxonomy for Model Context Protocol Systems (v1.0)*, arXiv:2603.18063.

The machine-readable source is [`config/mcp38_coverage.json`](../config/mcp38_coverage.json). `covered` means the primary mechanism has an implemented control and executable test. `partial` means a relevant control exists but material attack paths remain. `not_covered` is an explicit gap. Coverage is not a claim that a broad threat class has been eliminated.

Current generated totals:

| Status | Count |
| --- | ---: |
| Covered | 12 |
| Partial | 21 |
| Not covered | 5 |
| Total | 38 |

Run the policy regressions and matrix validation:

```bash
./scripts/run_evals.sh
```

Run every unit and integration proof:

```bash
PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v
```

High-value proofs include:

- `MCP-10` and `MCP-11`: poisoned descriptions and nested schema strings are rejected before pinning.
- `MCP-14`: duplicate cross-server tool names fail closed.
- `MCP-16`: a server that changes metadata after initial trust is blocked before execution.
- `MCP-20`: injected external tool output is quarantined without returning the malicious string.
- `MCP-22` and `MCP-23`: Slack callbacks are signed and allowlisted; duplicate requests are suppressed.
- `MCP-33`: local/Redis/DynamoDB limits, bounded scans, concurrency caps, and circuit breakers constrain abuse.
- `MCP-38`: audit mutation is detected and request decisions emit metrics and traces.

The five explicit gaps are multi-tenant isolation (`MCP-06`), general SSRF/XSS defense (`MCP-09`), privacy inference across aggregated data (`MCP-25`), planning drift (`MCP-35`), and multi-agent context hijacking (`MCP-36`). MCP-31 is partial: the HTTP boundary rejects untrusted `Origin` values, while complete deployment-edge Host validation remains future work.

`MCP-28` (man-in-the-middle / transport tampering) was previously listed as `not_covered`, which undercounted an existing control: the SIEM and Slack webhook egress paths already reject non-loopback `http://` URLs (`tests/test_audit_sink.py::test_rejects_unsafe_url_protocol_token_and_timeout`, `tests/test_slack_approval.py::test_configuration_rejects_unsafe_urls_and_invalid_limits`), and hosted LLM provider endpoints (Groq, OpenAI, Anthropic, Gemini) are hardcoded HTTPS, while a custom OpenAI-compatible base URL must use HTTPS unless it is loopback or insecure HTTP is explicitly allowed. It is now correctly listed as `partial` — outbound egress is TLS-enforced, but inbound HTTP transport TLS termination is still an operator/reverse-proxy responsibility and there is no certificate pinning.

`MCP-19` (direct prompt injection) and `MCP-12` (resource content poisoning) remain `partial`, not `covered`: the content-inspection layer in `src/judikt/content_guard.py` now also rescans base64/hex/URL-decoded payloads, normalizes homoglyph/leetspeak/spaced-letter obfuscation, checks a small non-English phrase set, and scans arguments concatenated together to catch injection split across fields. These close specific, well-known bypasses of plain-English `\b` regex matching. They do not add semantic understanding, so paraphrased or genuinely novel injection phrasing that doesn't match any fixed pattern will still get through — that gap is the honest reason both stay `partial`.

The independent attack fixture at [`tests/fixtures/external_mcp_server.py`](../tests/fixtures/external_mcp_server.py) is intentionally outside the `judikt` package. It implements MCP JSON-RPC itself and supports safe, text-only, paginated, server-request, result-injection, and rug-pull modes. This proves the protocol and security boundary against a separate process; it is not represented as a third-party production server.

Named third-party proof is handled separately by the versioned [community interoperability harness](COMMUNITY_INTEROP.md). Its credential-free profiles target the official MCP filesystem and memory servers; its opt-in profile targets GitHub's official server in read-only mode. The report records tool count, pin verification, guarded safe-call decisions, response hashes, and audit integrity without retaining raw third-party content.
