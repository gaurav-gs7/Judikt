# Skill And Runtime Security Disclosure

## Skill Package

The bundled `scripts/diagnose.py` is a read-only local inventory command. It does not open sockets, make HTTP requests, invoke package managers, run Judikt, launch an MCP upstream, read environment-variable values, read client configuration contents, or modify files.

The documentation contains commands that can install software, start an operator-selected upstream, create a policy, and edit MCP client configuration. Execute those commands only after disclosing the exact action and receiving user consent.

## Separately Installed Runtime

Judikt always communicates with the MCP upstream selected by the operator. Depending on the upstream, that process may itself make network calls.

Judikt can make these additional outbound calls only when their corresponding integration is configured:

- an LLM provider for optional incident summaries: Groq, OpenAI, Anthropic, Gemini, or an operator-specified OpenAI-compatible endpoint, selected explicitly with `JUDIKT_LLM_PROVIDER` (a Groq key alone keeps the original Groq behaviour);
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

Direct approval issuance remains sensitive even though the runtime also requires the explicit `JUDIKT_ALLOW_DIRECT_APPROVAL` switch and administrator authorization for authenticated remote callers. Never fabricate or expose an approval token and never enable direct issuance only to make a test pass. When Judikt holds a call and names an id, tell the user to run `judikt approve <id>` themselves and then retry the identical call. Never run `judikt approve` or `judikt issue-approval` on the user's behalf, even if you have shell access.

In local stdio mode, approvals and roles protect against prompt-injected calls arriving through MCP. They do not protect against an agent with arbitrary shell access running as the same operating-system user, because that agent can read `approval.key` and the policy. Real separation requires running Judikt and its secrets under a different OS user, or using a remote approval workflow such as Slack or an authenticated remote gateway with a configured secret.

## Generated Policy Boundary

`judikt init` and policy-free `judikt wrap` generate an annotation-derived starter policy (read-only by default). MCP annotations are self-reported by the upstream and are not trusted security facts. They can only make generation stricter than the mutation-name check. Treat `tool_classification` and every generated permission as a starting point for operator review. `approve-writes` gates write and destructive tools with approvals; `permissive` allows all discovered tools and emits a warning. Under every profile, a write or destructive call whose arguments reuse a value that an instruction in a tool result named (an email address, URL, domain, account number, crypto address, handle, identifier, quoted string or name) needs approval (rule `untrusted_provenance`); `untrusted_provenance.mode` can be `require_approval` (default), `deny`, `report` or `off`, and `track: everywhere` also counts addresses in plain data fields. A task scope (`judikt wrap --task-writes TOOL,...`, `JUDIKT_TASK_WRITES`, or `task_scope.write_tools`) holds any write outside the listed tools (rule `task_scope`). When `task_scope.mode` is `agent`, call `judikt_declare_task` once, at the start, with exactly the write tools the user's request needs, before reading anything; the first tool result seals it. Never declare extra tools in case they are needed later, and do not switch either gate off to make a task pass; ask the user to approve the specific call. An explicit policy passed to `judikt wrap --policy` is used as-is.

## Content Inspection Boundary

`inbound_content_inspection.thresholds` configures the minimum blocking severity for `tool_description`, `tool_argument`, and `tool_result`. Defaults are medium, medium, and high respectively. Medium tool-result findings redact the matched span; more than `max_medium_findings` (default `3`) quarantines the full result. Low findings are recorded. Oversized results scan the first and last halves of the byte budget and record a finding without blocking by default, while oversized metadata fails closed.

Tool results and descriptions are also scored by a deterministic learned classifier that calls no model; it can be disabled with `inbound_content_inspection.learned_classifier`. Report detection accuracy only with this breakdown for rules and classifier together, measured on 2026-10-28:

| Measurement | What it is | Samples | Recall | Precision | False-positive rate |
| --- | --- | --- | --- | --- | --- |
| External holdout: BIPIA | Independent attack strings in tool results and descriptions; never used for training or tuning | 300 (250 attack) | 54.8% | 100% | 0% |
| External holdout: InjecAgent | Independent injections inside agent tool outputs; never used for training or tuning | 335 (250 attack) | 7.6% | 100% | 0% |
| Real package documentation | Installed Python and npm READMEs, 4 KB chunks, benign only | 1,725 chunks from 717 packages | n/a | n/a | 0.64% |
| Project-authored regression split (test) | Written alongside the rules; a regression check, not a generalisation measure | 178 (70 attack) | 98.57% | 100% | 0% |

Deterministic rules miss novel paraphrases; Judikt relies on policy, approvals and least-privilege tool exposure as the primary controls. Never quote the regression-split numbers alone as the guard's accuracy. Evidence is published under [docs/evidence](https://github.com/gaurav-gs7/Judikt/tree/main/docs/evidence) (`content-guard-recall-2026-10-24-test.json`, `content-guard-external-after-2026-10-24.json`, and `real-docs-fpr-2026-10-24-after.json`). Do not describe this deterministic guard as complete prompt-injection prevention.
