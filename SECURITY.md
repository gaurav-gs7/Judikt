# Security Policy

Judikt is a self-hosted reference implementation, not a managed security service. Its security boundary depends on the selected transport, authentication mode, upstream process, state backends, and deployment controls. The packaged default policy is neutral and fail-closed; only operator-selected upstreams are loaded outside explicit demo mode.

## Local And Demo Boundary

The supported local boundary includes:

- JSON-RPC MCP over stdio between a local MCP client, Judikt, and an operator-selected stdio upstream;
- loopback-only Streamable HTTP MCP for local development;
- the loopback-only dashboard and its local API;
- deterministic demo adapters loaded only by `judikt demo` or the explicit test harness.

Unauthenticated stdio does not authenticate individual callers. Judikt ignores caller-supplied `actor`, `user`, and `requested_by` values and uses `local_stdio_identity` from the policy where an identity field is required. This prevents argument-level actor spoofing, but every client sharing that policy is represented as the same local principal. Use separate policy files and operating-system accounts when local clients require distinct identities.

The generated starter policy contains only exact names returned by the upstream's `tools/list`; it is not a trust assessment of those tools. Review descriptions, schemas, permissions, upstream code, and credentials before enabling the catalog. External stdio servers run as separate processes, but Judikt does not provide an OS-level sandbox. Apply filesystem, container, user, and network isolation appropriate to the upstream.

Local SQLite audit storage, file-backed approvals and pins, and in-process rate limits are single-node controls. They are suitable for development and constrained single-host operation, not multi-replica consistency or durable centralized evidence.

Do not expose the dashboard outside loopback without a strong random `JUDIKT_API_TOKEN`. Do not use `JUDIKT_DEMO_MODE=true` outside an isolated evaluation environment.

## Authenticated Remote Boundary

Judikt exposes an official MCP SDK Streamable HTTP endpoint. A non-loopback bind fails closed unless static bearer or JWT authentication is configured. `JUDIKT_ALLOW_UNAUTHENTICATED_REMOTE=true` is an explicit lab escape hatch and is not a supported production setting.

Static bearer authentication proves possession of one shared secret. It is appropriate only for a constrained single-operator environment and does not provide per-user identity. JWT mode supports HS256 or JWKS-backed RS256 verification and validates expiration, not-before time, issuer, audience, required scopes, and an optional group. The validated subject is bound to policy evaluation and auditing. Administrative control-plane tools require the configured administrator scope or group for JWT callers.

Judikt is an OAuth resource server, not an authorization server. The selected identity provider and MCP client own login, client registration, consent, authorization-code handling, refresh tokens, and PKCE. Judikt advertises OAuth protected-resource metadata and rejects caller-token passthrough to upstream tools; upstream access must use separate operator-owned, least-privilege credentials.

For non-loopback service:

- terminate TLS at a trusted ingress or load balancer and advertise an explicit HTTPS `JUDIKT_RESOURCE_URI`;
- restrict network access and configure exact allowed browser origins when applicable;
- keep bearer tokens, JWT signing material, approval keys, and audit-signing keys in a secret manager;
- do not place tokens in command arguments, client configuration committed to source control, or logs;
- keep `JUDIKT_ALLOW_DIRECT_APPROVAL` disabled unless direct issuance is an intentional administrative workflow;
- use the Slack approval workflow or another authenticated human approval system for destructive actions;
- validate callback signatures and apply replay protections for approval integrations.

Origin validation is defense in depth, not complete DNS-rebinding protection. Deployment-edge Host validation, DNS policy, TLS, firewall rules, and reverse-proxy hardening remain operator responsibilities. The unauthenticated health and protected-resource metadata endpoints intentionally expose status and authorization metadata; Slack callbacks use their own signature validation.

## Production Boundary

A production deployment must add operational controls around the authenticated remote boundary. At minimum:

- use Redis-backed distributed rate limiting for multiple replicas;
- use AWS Secrets Manager, Vault, or an equivalent secret store with scoped workload identity and rotation;
- ship signed audit events to an append-only central destination such as S3 or a controlled SIEM, and monitor delivery failures;
- use durable external state where approvals, runtime state, and audit continuity must survive host replacement;
- export redacted metrics and traces to an access-controlled observability system and define retention limits;
- isolate upstream processes with least-privilege OS users, containers, or workload sandboxes and restrict egress;
- enforce least-privilege IAM, encrypted storage, backup and restoration procedures, SLOs, alerts, and tested runbooks;
- pin versions, review generated policy changes, protect deployment artifacts, and test rollback and failure modes;
- separate tenants at the identity, policy, state, secret, compute, and audit layers. Judikt does not currently provide built-in multi-tenant isolation.

Optional integrations make outbound calls only when configured. These include MCP upstreams, Groq, Slack, AWS services, SIEM or Splunk endpoints, Redis, Vault, OIDC/JWKS providers, OTLP collectors, and incident-management webhooks. Operators must review the endpoint, transmitted metadata, credentials, TLS posture, retention, availability, and cost before enabling each integration. No LLM participates in deterministic allow or deny decisions.

Content inspection, redaction, metadata pinning, approvals, kill switches, and audit signatures are defense-in-depth controls. Content detection is heuristic and cannot guarantee detection of every prompt injection, encoded payload, data leak, or malicious tool behavior. Judikt also does not yet provide cryptographically signed policy bundles, complete MCP resource and prompt proxying, semantic DLP, or complete deployment-edge DNS-rebinding defenses.

Do not describe a deployment as verified because controls are present in configuration. Exercise the deployed authentication, authorization, approval, response-inspection, rate-limit, audit-export, secret-rotation, recovery, and failure paths and retain sanitized evidence.

## Reporting A Vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do not include live credentials, customer data, approval tokens, or exploit traffic against systems you do not own. Include the affected revision, deployment mode, reproduction steps, impact, and suggested mitigation when available.
