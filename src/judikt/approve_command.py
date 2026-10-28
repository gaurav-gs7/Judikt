"""``judikt approve``: review and approve calls the local gateway held."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from typing import TextIO

from .approval import ApprovalAuthority, ApprovalConfigurationError
from .pending_approvals import APPROVED_TTL_SECONDS, PendingApproval, PendingApprovalStore, enabled

RULE_LABELS = {
    "approval_required": "the policy requires approval for this tool",
    "untrusted_provenance": "the arguments reuse a value that untrusted tool output asked for",
    "task_scope": "the tool is not one of the writes declared for this task",
}


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    approve = subparsers.add_parser(
        "approve",
        help="review and approve a call Judikt held for approval",
        description=(
            "With no id, list the calls waiting for approval. With an id, show the exact "
            "call and approve it once; the agent's next identical call then runs."
        ),
    )
    approve.add_argument("id", nargs="?", help="the id shown in the held call's message")
    approve.add_argument("--yes", action="store_true", help="approve without the confirmation prompt")
    approve.add_argument("--deny", action="store_true", help="discard the held call instead")
    approve.add_argument("--reason", default="approved with judikt approve")


def _age(entry: PendingApproval) -> str:
    seconds = int(time.time() - entry.created_at)
    return f"{seconds // 60}m{seconds % 60:02d}s ago"


def _describe(entry: PendingApproval, out: TextIO) -> None:
    print(f"Held call {entry.id} ({_age(entry)}, by {entry.actor})", file=out)
    print(f"  tool:   {entry.server} / {entry.tool}", file=out)
    print(f"  why:    {RULE_LABELS.get(entry.rule, entry.rule)} (rule {entry.rule})", file=out)
    print(f"  detail: {entry.reason}", file=out)
    print("  arguments:", file=out)
    for line in json.dumps(entry.arguments, indent=2, sort_keys=True).splitlines():
        print(f"    {line}", file=out)


def run(
    args: argparse.Namespace,
    *,
    store: PendingApprovalStore | None = None,
    stdin: TextIO = sys.stdin,
    out: TextIO = sys.stdout,
) -> int:
    if store is None and not enabled():
        print(
            "approve: local held-call approvals are off (JUDIKT_PRODUCTION or JUDIKT_PENDING_APPROVALS); "
            "use the configured approval workflow",
            file=sys.stderr,
        )
        return 2
    store = store or PendingApprovalStore()
    if not args.id:
        entries = store.entries()
        if not entries:
            print("No calls are waiting for approval.", file=out)
            return 0
        for entry in entries:
            state = "approved, waiting for retry" if entry.approved else entry.rule
            print(f"{entry.id}  {_age(entry):>10}  {entry.server}/{entry.tool}  [{state}]", file=out)
        print("\nReview one with: judikt approve <id>", file=out)
        return 0
    try:
        entry = store.get(args.id)
    except ValueError as exc:
        print(f"approve: {exc}", file=sys.stderr)
        return 2
    if entry is None:
        print(f"approve: no held call {args.id} (it may have expired or already run)", file=sys.stderr)
        return 1
    _describe(entry, out)
    if args.deny:
        store.discard(entry.id)
        print(f"Discarded {entry.id}. The agent's retry will be held again.", file=out)
        return 0
    if entry.approved:
        print("Already approved; waiting for the agent to retry.", file=out)
        return 0
    if not args.yes:
        if not stdin.isatty():
            print("approve: not a terminal; pass --yes to approve non-interactively", file=sys.stderr)
            return 2
        print("Approve this exact call once? [y/N] ", end="", file=out, flush=True)
        if stdin.readline().strip().lower() not in {"y", "yes"}:
            print("Not approved.", file=out)
            return 1
    approver = f"local:{getpass.getuser()}"
    try:
        token = ApprovalAuthority().issue(
            actor=approver,
            reason=args.reason,
            server=entry.server,
            tool=entry.tool,
            arguments=entry.arguments,
            ttl_seconds=APPROVED_TTL_SECONDS,
        )
    except ApprovalConfigurationError as exc:
        print(f"approve: {exc}", file=sys.stderr)
        return 2
    store.approve(entry.id, token, approver)
    minutes = APPROVED_TTL_SECONDS // 60
    print(
        f"Approved {entry.id}. Ask the agent to retry the same call; it runs once, "
        f"within {minutes} minutes, with exactly these arguments.",
        file=out,
    )
    return 0
