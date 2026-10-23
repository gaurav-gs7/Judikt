# Setup And Onboarding

## 1. Detect Without Changing State

From the skill directory, run:

```bash
python3 scripts/diagnose.py
```

The diagnostic only checks local executable, package-version, and candidate MCP-client configuration metadata. It makes no network calls, launches no upstream, reads no configuration contents, and writes nothing.

Also establish these facts without exposing environment-variable values:

- the upstream's executable and argument vector;
- whether running it may contact an external service;
- the MCP client name and configuration location;
- the intended local identity or remote authentication mode;
- the policy and audit destinations;
- whether the operation is a disposable evaluation or persistent setup.

Report the findings and proposed changes. Do not continue to installation or configuration without explicit user consent.

## 2. Install The Runtime With Consent

Judikt requires Python 3.11 or newer. The skill does not include the runtime.

After the user approves the source, version, environment, and network access, install a published release:

```bash
python3 -m pip install judikt
```

For a trusted local checkout, install that checkout instead:

```bash
python3 -m pip install /absolute/path/to/Judikt
```

Prefer an isolated virtual environment when the client can reference its absolute `judikt` executable. Verify without printing environment values:

```bash
command -v judikt
judikt --help
```

Do not claim successful installation until the command exits successfully.

## 3. Generate A Reviewable Policy

`judikt init` starts the selected upstream, requests its real `tools/list`, and writes an annotation-derived starter policy (read-only by default). Upstream annotations are self-reported, not trusted security facts, and can only make generation stricter than Judikt's mutation-name check. The generated policy and its `tool_classification` entries are a starting point to review. Judikt refuses to overwrite an existing destination unless `--force` is supplied.

Show the exact command and obtain consent before running it:

```bash
judikt init \
  --profile read-only \
  --name <stable-server-name> \
  --identity <local-identity> \
  --output /absolute/path/judikt-policy.json \
  -- <upstream-executable> <upstream-arguments...>
```

Profiles are `read-only` (only read-tier tools are allowed), `approve-writes` (write and destructive tools require signed approval), and `permissive` (all discovered tools are allowed and Judikt prints a warning). Review the generated tool names, classifications, conflicts, and policy controls. Do not add wildcard permissions to make setup easier. Do not use `--force` without separate overwrite consent.

For quick disposable evaluation, `judikt wrap -- <upstream command>` generates the same ephemeral annotation-derived starter policy with the `read-only` profile by default. Prefer a persistent reviewed policy for ongoing use. An explicit `judikt wrap --policy ...` policy is used as-is and is never reclassified.

## 4. Connect And Smoke-Test

Use [mcp-configuration.md](mcp-configuration.md) to prepare the smallest client configuration change. Obtain consent, preserve unrelated configuration, and validate the edited file's syntax.

After the user reloads or restarts the client:

1. Initialize the MCP connection.
2. Request `tools/list` through Judikt.
3. Compare the guarded catalog with the reviewed policy.
4. With explicit authorization, call one tool whose description and schema establish that it is read-only.
5. Confirm a sanitized audit event or correlation identifier when available.
6. Do not test restart, rollback, write, delete, approval issuance, or kill-switch mutation as onboarding smoke tests.

## 5. Assess What Was Proven

Mark a control `verified` only when runtime evidence exercised it. A setting present in a policy, environment name, or deployment manifest is `configured-not-verified` until tested. Record skipped checks and why they were skipped.

Never include credentials, raw injected content, approval tokens, or full sensitive tool results in the assessment.
