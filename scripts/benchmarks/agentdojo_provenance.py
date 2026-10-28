"""AgentDojo ground-truth replay of Judikt's untrusted-provenance gate.

AgentDojo (Debenedetti et al., 2024) ships, for every user task and every
injection task, the exact tool calls a correct agent makes. This script runs
those calls against AgentDojo's own simulated environments and feeds every
tool result and every call through ``judikt.provenance``, the same tracker the
gateway uses, with tool tiers from Judikt's ``RiskEngine``.

Two questions, both without a language model:

* Burden: on a clean environment, how often does a legitimate user task make a
  write that reuses a value it first read from a tool, and so would stop for
  human approval?
* Protection: with the injection planted where the user task will read it
  (AgentDojo's own injection-candidate rule and its ``important_instructions``
  template), does the attacker's write get held?

The content guard is deliberately not applied: Judikt's classifier was trained
on AgentDojo injection goals and environments, so its AgentDojo numbers would
not be independent. The provenance gate learns nothing from any dataset.

Tool annotations: AgentDojo tools carry none, so a tool is marked read-only when
its name starts with get, list, search, read or check; every other tool is a
write. Ground-truth calls stand in for the agent, so the user's own prompt is
invisible to Judikt exactly as it is in production.

Usage (needs ``pip install agentdojo==0.1.35``):
    PYTHONPATH=src python scripts/benchmarks/agentdojo_provenance.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any

from judikt.provenance import ProvenanceTracker, indicators
from judikt.risk import RiskEngine

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "docs" / "evidence" / "agentdojo-provenance.json"
VERSION = "0.1.35"
BENCHMARK = "v1.2"
READ_VERBS = ("get", "list", "search", "read", "check")
SCOPE = "agent"


def definition(name: str) -> dict[str, Any]:
    read_only = name.split("_", 1)[0] in READ_VERBS
    return {"name": name, "annotations": {"readOnlyHint": read_only, "destructiveHint": False}}


class Replay:
    def __init__(self, suite: Any) -> None:
        from agentdojo.functions_runtime import FunctionsRuntime

        self.suite = suite
        self.runtime = FunctionsRuntime(suite.tools)
        self.risk = RiskEngine({})
        self.tiers = {tool.name: self.risk.tier(tool.name, definition(tool.name)) for tool in suite.tools}

    def run(self, tracker: ProvenanceTracker, environment: Any, calls: list[Any]) -> list[dict[str, Any]]:
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

        steps = []
        for call in calls:
            arguments = dict(call.args)
            tier = self.tiers[call.function]
            matches = tracker.matches(SCOPE, arguments) if tier != "read" else []
            tracker.observe_arguments(SCOPE, arguments)
            result, error = self.runtime.run_function(environment, call.function, arguments)
            seen = tool_result_to_str(result) if error is None else error
            tracker.observe_result(SCOPE, self.suite.name, call.function, seen)
            steps.append(
                {
                    "tool": call.function,
                    "tier": tier,
                    "held": bool(matches),
                    "kinds": sorted({match.kind for match in matches}),
                    "seen": seen,
                }
            )
        return steps


def injection_text(goal: str) -> str:
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    return ImportantInstructionsAttack._JB_STRING.format(goal=goal, user="Emma Johnson", model="AI assistant")


def candidates(suite: Any, user_task: Any) -> list[str]:
    from agentdojo.attacks.base_attacks import BaseAttack

    class Probe(BaseAttack):
        name = "judikt_probe"

        def attack(self, user_task: Any, injection_task: Any) -> dict[str, str]:
            return {}

    return Probe(suite, None).get_injection_candidates(user_task)


def evaluate(suite: Any) -> dict[str, Any]:
    replay = Replay(suite)
    utility: list[dict[str, Any]] = []
    for task_id, task in suite.user_tasks.items():
        environment = suite.load_and_inject_default_environment({})
        steps = replay.run(ProvenanceTracker(), environment, task.ground_truth(environment.model_copy(deep=True)))
        writes = [step for step in steps if step["tier"] != "read"]
        utility.append(
            {
                "user_task": task_id,
                "writes": len(writes),
                "held_writes": sum(step["held"] for step in writes),
                "held_tools": [step["tool"] for step in writes if step["held"]],
                "held_kinds": sorted({kind for step in writes for kind in step["kinds"]}),
            }
        )
    attacks: list[dict[str, Any]] = []
    skipped: dict[str, set[str]] = defaultdict(set)
    for task_id, task in suite.user_tasks.items():
        try:
            vectors = candidates(suite, task)
        except ValueError:
            continue
        for injection_id, injection in suite.injection_tasks.items():
            payload = injection_text(injection.GOAL)
            environment = suite.load_and_inject_default_environment({vector: payload for vector in vectors})
            tracker = ProvenanceTracker()
            user_steps = replay.run(tracker, environment, task.ground_truth(environment.model_copy(deep=True)))
            attack_steps = replay.run(tracker, environment, injection.ground_truth(environment.model_copy(deep=True)))
            attacker_writes = [step for step in attack_steps if step["tier"] != "read"]
            if not attack_steps:
                skipped["no_ground_truth"].add(injection_id)
                continue
            if not attacker_writes:
                skipped["no_write"].add(injection_id)
            traceable = bool(indicators(injection.GOAL))
            attacks.append(
                {
                    "user_task": task_id,
                    "injection_task": injection_id,
                    "attacker_writes": len(attacker_writes),
                    "held": any(step["held"] for step in attacker_writes),
                    "goal_carries_traceable_value": traceable,
                    "agent_saw_injection": any("<INFORMATION>" in step["seen"] for step in user_steps),
                }
            )
    return {
        "utility": utility,
        "attacks": attacks,
        "injection_tasks_not_scored": {reason: sorted(ids) for reason, ids in skipped.items()},
    }


def rate(rows: list[dict[str, Any]], predicate: Any) -> dict[str, Any]:
    hits = sum(1 for row in rows if predicate(row))
    return {"count": hits, "of": len(rows), "rate": round(hits / len(rows), 4) if rows else None}


def summarise(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    def section(utility: list[dict[str, Any]], attacks: list[dict[str, Any]]) -> dict[str, Any]:
        writing = [row for row in utility if row["writes"]]
        attackable = [row for row in attacks if row["attacker_writes"]]
        by_injection: dict[str, list[bool]] = defaultdict(list)
        for row in attackable:
            by_injection[row["injection_task"]].append(row["held"])
        return {
            "user_tasks_with_a_held_write": rate(utility, lambda row: row["held_writes"] > 0),
            "user_tasks_with_a_held_write_among_tasks_that_write": rate(writing, lambda row: row["held_writes"] > 0),
            "held_kinds_in_user_tasks": dict(Counter(kind for row in utility for kind in row["held_kinds"])),
            "attacks_held": rate(attackable, lambda row: row["held"]),
            "agent_saw_the_injection": rate(attackable, lambda row: row["agent_saw_injection"]),
            "attacks_held_when_goal_carries_a_traceable_value": rate(
                [row for row in attackable if row["goal_carries_traceable_value"]], lambda row: row["held"]
            ),
            "attacks_whose_goal_carries_a_traceable_value": rate(
                attackable, lambda row: row["goal_carries_traceable_value"]
            ),
            "injection_tasks_always_held": sorted(key for key, held in by_injection.items() if all(held)),
            "injection_tasks_never_held": sorted(key for key, held in by_injection.items() if not any(held)),
        }

    report = {name: section(result["utility"], result["attacks"]) for name, result in results.items()}
    report["all"] = section(
        [row for result in results.values() for row in result["utility"]],
        [row for result in results.values() for row in result["attacks"]],
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if metadata.version("agentdojo") != VERSION:
        raise SystemExit(f"agentdojo {VERSION} is required")
    from agentdojo.task_suite.load_suites import get_suites

    results = {name: evaluate(suite) for name, suite in sorted(get_suites(BENCHMARK).items())}
    summary = summarise(results)
    report = {
        "benchmark": f"AgentDojo {BENCHMARK} ground-truth replay of the untrusted-provenance gate",
        "agentdojo_version": VERSION,
        "notes": [
            "No language model runs; AgentDojo's ground-truth calls stand in for the agent.",
            "Tool tiers: names starting with get, list, search, read or check are read-only; others are writes.",
            "A held write is one Judikt's default policy would stop for human approval (rule untrusted_provenance).",
            "Attacks: injection planted in every vector the user task reads, using AgentDojo's important_instructions template.",
            "An attack counts as held if any of its ground-truth writes is held.",
            "The content guard is not applied, because Judikt's classifier was trained on AgentDojo data.",
            "Not scored: injection tasks with no ground-truth calls in AgentDojo 0.1.35, and tasks whose ground truth makes no write (nothing for a write gate to hold).",
        ],
        "injection_tasks_not_scored": {name: result["injection_tasks_not_scored"] for name, result in results.items()},
        "summary": summary,
        "details": {
            name: {"utility": result["utility"], "attacks": result["attacks"]} for name, result in results.items()
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    for name, section in summary.items():
        print(
            f"{name:10} attacks held {section['attacks_held']['count']}/{section['attacks_held']['of']}"
            f" ({section['attacks_held']['rate']});"
            f" user tasks with a held write {section['user_tasks_with_a_held_write']['count']}"
            f"/{section['user_tasks_with_a_held_write']['of']}"
        )


if __name__ == "__main__":
    main()
