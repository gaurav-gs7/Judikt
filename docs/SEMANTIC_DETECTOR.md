# Optional Semantic Detector Design

Judikt's active content guard is deterministic. An earlier version of this design limited a future semantic detector to findings already in the uncertain medium band. That trigger is too narrow: on the external holdout (BIPIA and InjecAgent, see `tests/fixtures/content_guard/external/SOURCES.md`), 498 of 500 attacks produced no finding at all, so a detector that only reviews medium findings would never see them.

## Trigger

A semantic detector, if added, should review a tool result when either of these holds:

- the deterministic guard produced a medium finding; or
- the content contains a cheap structural or addressing signal that does not by itself justify a finding, for example any direct address of the agent (`_AGENT_ADDRESS` in `content_guard.py`), an imperative sentence that names a tool or a sensitive target, or instructions in a field whose schema type is data (an issue body, a file's contents, an email).

Operators should be able to sample a configurable fraction of results with no signal at all, in shadow mode only, to measure what the triggers miss. The external holdout and `scripts/measure_real_docs_fpr.py` are the yardsticks: report recall on the holdout and the false-positive rate on real documentation, never the project-authored regression split alone.

## Enforcement Boundary

The semantic detector would be disabled by default and explicitly configured by an operator. It could only escalate: from no finding or a record-only finding to span redaction, or from redaction to full-result quarantine. A model may only escalate, never allow. It could never allow content, downgrade a deterministic finding, override policy, authorize a tool, issue an approval, or bypass a kill switch.

No LLM belongs in Judikt's authorization path. Tool allowlists, identity, approvals, rate limits, argument controls, metadata pins, and deterministic high-severity findings must continue to work when the optional detector is unavailable, slow, or returns malformed output.

## Data And Failure Handling

Only the smallest redacted context window needed for classification should leave the runtime. Configuration must identify the provider, endpoint, retention policy, timeout, and data region. Prompts and responses must not contain credentials or raw audit records, and neither should be logged.

Timeouts, provider errors, invalid responses, and low-confidence classifications must preserve the deterministic decision. Operators should be able to run the detector in shadow mode, compare escalations against labelled traffic, and review precision, recall, false-positive rate, latency, and cost before enforcement is enabled.
