# Skill And Runtime Security Disclosure

## Skill Package

The bundled `scripts/diagnose.py` is a read-only local inventory command. It does not open sockets, make HTTP requests, invoke package managers, run Judikt, launch an MCP upstream, read environment-variable values, read client configuration contents, or modify files.

The documentation contains commands that can install software, start an operator-selected upstream, create a policy, and edit MCP client configuration. Execute those commands only after disclosing the exact action and receiving user consent.

## Separately Installed Runtime

Judikt always communicates with the MCP upstream selected by the operator. Depending on the upstream, that process may itself make network calls.

Judikt can make these additional outbound calls only when their corresponding integration is configured:

- Groq for optional incident summaries;
- Slack for approval requests and signed action callbacks;
- AWS services, including Secrets Manager, S3, DynamoDB, EventBridge, CloudWatch, and X-Ray;
- HTTPS SIEM/webhook or Splunk HEC audit destinations;
- Redis for distributed rate limiting;
- Vault for secret resolution;
- OIDC/JWKS endpoints for JWT verification metadata and signing keys;
- OTLP collectors for traces;
- incident-management endpoints such as Argus integrations.

Do not enable an integration without identifying its endpoint, data sent, credential source, TLS requirements, retention implications, and expected cost. Keep policy decisions deterministic; optional LLM availability must not decide allow or deny outcomes.

## Identity And Approval Boundaries

Unauthenticated stdio has no per-caller authentication. Judikt sources identity only from the policy's `local_stdio_identity` and forwards tool arguments unchanged, so every client sharing that policy is represented as the same principal. `identity_argument_fields` is empty by default; policies may explicitly opt argument fields into claim checking, but those claims never override a trusted local or authenticated identity.

Authenticated remote mode binds policy evaluation to the validated subject. Judikt is an OAuth resource server, not an authorization server; the selected IdP owns PKCE, login, consent, and client registration.

Direct approval issuance remains sensitive even though the runtime also requires the explicit `JUDIKT_ALLOW_DIRECT_APPROVAL` switch and administrator authorization for authenticated remote callers. Never fabricate or expose an approval token and never enable direct issuance only to make a test pass.

In local stdio mode, approvals and roles protect against prompt-injected calls arriving through MCP. They do not protect against an agent with arbitrary shell access running as the same operating-system user, because that agent can read `approval.key` and the policy. Real separation requires running Judikt and its secrets under a different OS user, or using a remote approval workflow such as Slack or an authenticated remote gateway with a configured secret.

## Generated Policy Boundary

`judikt init` and policy-free `judikt wrap` generate an annotation-derived starter policy (read-only by default). MCP annotations are self-reported by the upstream and are not trusted security facts. They can only make generation stricter than the mutation-name check. Treat `tool_classification` and every generated permission as a starting point for operator review. `approve-writes` gates write and destructive tools with approvals; `permissive` allows all discovered tools and emits a warning. An explicit policy passed to `judikt wrap --policy` is used as-is.

## Content Inspection Boundary

`inbound_content_inspection.thresholds` configures the minimum blocking severity for `tool_description`, `tool_argument`, and `tool_result`. Defaults are medium, medium, and high respectively. Medium tool-result findings redact the matched span; more than `max_medium_findings` (default `3`) quarantines the full result. Low findings are recorded. Oversized results scan the first and last halves of the byte budget and record a finding without blocking by default, while oversized metadata fails closed.

Report detection accuracy only with this breakdown, measured on 2026-10-24:

| Measurement | What it is | Samples | Recall | Precision | False-positive rate |
| --- | --- | --- | --- | --- | --- |
| Project-authored regression split (test) | Written alongside the rules; a regression check, not a generalisation measure | 178 (70 attack) | 98.57% | 100% | 0% (tool results 0%) |
| External holdout: BIPIA | Independent attack strings in README, issue, web, email, and log wrappers plus tool descriptions; never used for tuning | 300 (250 attack) | 0.8% | 100% | 0% |
| External holdout: InjecAgent | Independent injections inside agent tool outputs; never used for tuning | 335 (250 attack) | 0% | n/a (no detections) | 0% |
| External holdout, by surface | Same holdout | tool_result 510 / tool_description 125 | 0.53% / 0% | 100% / n/a | 0% / n/a |
| Real package documentation | Installed Python and npm READMEs, 4 KB chunks, benign only | 1,526 chunks from 653 packages | n/a | n/a | 0.59% (0.92% before the 2026-10-24 rule changes) |

Deterministic rules miss novel paraphrases; Judikt relies on policy, approvals and least-privilege tool exposure as the primary controls. Never quote the regression-split numbers alone as the guard's accuracy. Evidence is published under [docs/evidence](https://github.com/gaurav-gs7/Judikt/tree/main/docs/evidence) (`content-guard-recall-2026-10-24-test.json`, `content-guard-external-after-2026-10-24.json`, and `real-docs-fpr-2026-10-24-after.json`). Do not describe this deterministic guard as complete prompt-injection prevention.
