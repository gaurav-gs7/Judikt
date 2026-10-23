# Optional Semantic Detector Design

Judikt's active content guard is deterministic. A future semantic detector may be added only for findings already classified in the uncertain medium band, where literal patterns identify suspicious content but cannot confidently distinguish operational prose from agent-directed instructions.

## Enforcement Boundary

The semantic detector would be disabled by default and explicitly configured by an operator. It could only escalate a medium finding from record-only to span redaction or full-result quarantine. It could never allow content, downgrade a deterministic finding, override policy, authorize a tool, issue an approval, or bypass a kill switch.

No LLM belongs in Judikt's authorization path. Tool allowlists, identity, approvals, rate limits, argument controls, metadata pins, and deterministic high-severity findings must continue to work when the optional detector is unavailable, slow, or returns malformed output.

## Data And Failure Handling

Only the smallest redacted context window needed for classification should leave the runtime. Configuration must identify the provider, endpoint, retention policy, timeout, and data region. Prompts and responses must not contain credentials or raw audit records, and neither should be logged.

Timeouts, provider errors, invalid responses, and low-confidence classifications must preserve the deterministic decision. Operators should be able to run the detector in shadow mode, compare escalations against labelled traffic, and review precision, recall, false-positive rate, latency, and cost before enforcement is enabled.
