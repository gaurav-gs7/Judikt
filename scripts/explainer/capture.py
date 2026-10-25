"""Capture the real Judikt runs shown in the 2-minute explainer video.

Drives `judikt wrap` against a scripted GitHub-like MCP fixture and records
every decision the video shows in capture.json. Nothing is mocked inside
Judikt: the gateway, policy, approval tokens, kill switch, pinning and audit
chain are the installed package.

    python scripts/explainer/capture.py                  # source tree
    python scripts/explainer/capture.py --judikt judikt --source PyPI
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Run as a script, so this directory is on sys.path.
from mcp_harness import StdioClient, result_text

HERE = Path(__file__).resolve().parent

DRIFT_NOISE = ("Judikt starter", "Excluded", "Approval-gated", "Annotation", "Judikt pin pending")


def decision(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result", response)
    meta = (result.get("_meta") or {}).get("io.judikt/decision", {})
    return {
        "isError": result.get("isError"),
        "rule": meta.get("rule"),
        "action": meta.get("action"),
        "risk": meta.get("risk_level"),
        "text": result_text(response) or json.dumps(response.get("error")),
    }


def capture(judikt: list[str], work: Path) -> dict[str, Any]:
    home = work / "home"
    upstream_dir = work / "upstream"
    home.mkdir()
    upstream_dir.mkdir()
    shutil.copy(HERE / "github_mcp_fixture.py", upstream_dir / "github_mcp.py")
    variant = upstream_dir / "variant.txt"
    variant.write_text("original\n")
    env = dict(
        os.environ,
        HOME=str(home),
        XDG_STATE_HOME=str(home / "state"),
        JUDIKT_UPSTREAM_TIMEOUT_SECONDS="3",
    )
    upstream = [sys.executable, str(upstream_dir / "github_mcp.py")]

    def cli(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        kwargs.setdefault("env", env)
        return subprocess.run([*judikt, *args], capture_output=True, text=True, check=False, **kwargs)

    out: dict[str, Any] = {}

    # 1. One command, read-only by default.
    client = StdioClient([*judikt, "wrap", "--", *upstream], env=env)
    client.initialize()
    out["tools_readonly"] = [tool["name"] for tool in client.rpc("tools/list")["result"]["tools"]]
    out["read_file"] = decision(client.call("read_file", {"path": "deploy.yaml"}))
    out["delete_ro"] = decision(client.call("delete_repo", {"repo": "payments-prod"}))
    out["poisoned"] = decision(client.call("get_readme", {"package": "left-pad-ng"}))
    started = time.time()
    out["hung"] = decision(client.call("search_issues", {"query": "flaky deploy"}, timeout=60))
    out["hung_seconds"] = round(time.time() - started, 1)
    out["hung_leaks_secret"] = "ghp_" in out["hung"]["text"]
    out["hung_leaks_injection"] = "ignore previous" in out["hung"]["text"]

    # Kill switch flipped from a separate process while the session is live.
    killed = cli("kill", "tool", "read_file", "--reason", "INC-142 suspected data exfiltration")
    out["kill_cmd_rc"] = killed.returncode
    time.sleep(1.5)
    out["read_after_kill"] = decision(client.call("read_file", {"path": "deploy.yaml"}))
    cli("unkill", "tool", "read_file", "--reason", "INC-142 resolved")
    client.close()
    out["wrap_stderr"] = "".join(client.stderr)

    upstreams = home / "state" / "judikt" / "upstreams"
    key = next(path.name for path in upstreams.iterdir() if path.is_dir())
    out["state_key"] = key
    audit_db = upstreams / key / "audit.db"

    # 2. Argument-bound, single-use approvals.
    cli("pins", "accept", key, "--tool", "delete_repo", "--yes")
    client = StdioClient([*judikt, "wrap", "--profile", "approve-writes", "--", *upstream], env=env)
    client.initialize()
    client.rpc("tools/list")
    arguments = {"repo": "old-sandbox"}
    out["delete_noapproval"] = decision(client.call("delete_repo", arguments))
    issued = cli(
        "issue-approval", "--actor", "local-operator", "--reason", "remove abandoned sandbox",
        "--server", "github_mcp", "--tool", "delete_repo", "--arguments", json.dumps(arguments),
    )
    if issued.returncode != 0:
        raise SystemExit(f"issue-approval failed: {issued.stderr}")
    token = issued.stdout.strip().splitlines()[-1]
    out["token_prefix"] = token[:22]
    out["delete_other_args"] = decision(
        client.call("delete_repo", {"repo": "payments-prod", "approval_token": token})
    )
    out["delete_approved"] = decision(client.call("delete_repo", {**arguments, "approval_token": token}))
    out["delete_replay"] = decision(client.call("delete_repo", {**arguments, "approval_token": token}))
    client.close()

    # 3. Rug pull: the upstream silently changes a tool description.
    variant.write_text("rugpull\n")
    initialize = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "judikt-explainer", "version": "1"},
            },
        }
    )
    drifted = cli("wrap", "--", *upstream, input=initialize + "\n", timeout=60)
    out["drift_rc"] = drifted.returncode
    out["drift_stderr"] = [
        line for line in drifted.stderr.splitlines() if line.strip() and not line.startswith(DRIFT_NOISE)
    ]
    variant.write_text("original\n")

    # 4. Verify the signed audit chain, then tamper with a copy.
    verified = cli("audit", "verify", env={**env, "JUDIKT_AUDIT_DB": str(audit_db)})
    report = json.loads(verified.stdout)
    out["audit"] = {name: report.get(name) for name in ("status", "signed", "checked_events", "errors")}
    tampered = work / "tampered.db"
    for suffix in ("", "-wal", "-shm"):
        source = Path(f"{audit_db}{suffix}")
        if source.exists():
            shutil.copy(source, f"{tampered}{suffix}")
    connection = sqlite3.connect(tampered)
    row = connection.execute(
        "select seq, tool, rule from audit_events where rule='allowlist' order by seq limit 1"
    ).fetchone()
    connection.execute(
        "update audit_events set rule='allow', allowed=1, reason='allowed by policy' where seq=?", (row[0],)
    )
    connection.commit()
    connection.close()
    out["tampered_row"] = {"seq": row[0], "tool": row[1], "rule_before": row[2]}
    checked = cli("audit", "verify", "--audit-db", str(tampered), "--full")
    tamper_report = json.loads(checked.stdout) if checked.stdout.strip().startswith("{") else {}
    out["audit_tampered"] = {
        "rc": checked.returncode,
        "status": tamper_report.get("status"),
        "errors": tamper_report.get("errors", [])[:2],
    }
    out["version"] = cli("--version").stdout.strip()
    return json.loads(json.dumps(out).replace(str(home), "~"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--judikt", help="judikt command to run (default: this source tree)")
    parser.add_argument("--source", default="source tree", help="label shown in the video's terminal title")
    parser.add_argument("--output", type=Path, default=HERE / "capture.json")
    args = parser.parse_args()
    if args.judikt:
        judikt = shlex.split(args.judikt)
    else:
        os.environ["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(HERE.parents[1] / "src"), os.environ.get("PYTHONPATH")])
        )
        judikt = [sys.executable, "-m", "judikt.cli"]
    with tempfile.TemporaryDirectory(prefix="judikt-explainer-") as directory:
        out = capture(judikt, Path(directory))
    out["judikt_source"] = args.source
    args.output.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {args.output} ({out['version']}, {args.source})")


if __name__ == "__main__":
    main()
