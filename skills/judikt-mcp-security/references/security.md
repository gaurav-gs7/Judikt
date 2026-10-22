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

Unauthenticated stdio has no per-caller authentication. Judikt removes caller-provided `actor`, `user`, and `requested_by` values and substitutes the policy's `local_stdio_identity` where applicable. This prevents argument-level spoofing but represents every client sharing that policy as the same principal.

Authenticated remote mode binds policy evaluation to the validated subject. Judikt is an OAuth resource server, not an authorization server; the selected IdP owns PKCE, login, consent, and client registration.

Direct approval issuance remains sensitive even though the runtime also requires the explicit `JUDIKT_ALLOW_DIRECT_APPROVAL` switch and administrator authorization for authenticated remote callers. Never fabricate or expose an approval token and never enable direct issuance only to make a test pass.
