"""Ground-truth replay of Judikt's write gates on AgentDojo-style benchmarks.

AgentDojo (Debenedetti et al., 2024) and AgentDyn (2026, built on the same
framework) ship, for every user task, the exact tool calls a correct agent
makes. This script runs those calls in the benchmark's own simulated
environments and passes every tool result and every call through the same
classes the gateway uses: ``judikt.provenance.ProvenanceTracker``,
``judikt.task_scope.TaskScopeStore`` and ``judikt.risk.RiskEngine`` for tiers.

Two questions, without a language model:

* Burden: on a clean environment, how many legitimate user tasks make a write
  that a gate would stop for human approval?
* Protection: with the injection planted where the user task will read it
  (the framework's injection-candidate rule and its ``important_instructions``
  template), is the attacker's write held?

Gate configurations, each measured on its own:

* ``provenance_everywhere``: addresses and links tracked wherever they appear.
* ``provenance``: Judikt's default, values tracked only inside instructions.
* ``provenance_and_task_scope``: the default plus a task scope declared as the
  write tools of the user task's own correct solution. That is an exact
  declaration, so it is an upper bound on what a declaration achieves.

Attacker calls: AgentDojo's injection-task ground truth; for AgentDyn, whose
injection ground truths are placeholders, the calls pre-registered in
``tests/fixtures/benchmarks/agentdyn_attacker_calls.json`` before any
measurement. The content guard is not applied (Judikt's classifier was trained
on AgentDojo data; leaving it out keeps the two benchmarks comparable).

Tool annotations: neither benchmark ships any, so a tool is read-only when its
name starts with a read verb (AgentDojo: get, list, search, read, check;
AgentDyn adds view and browse, as pre-registered). Every other tool is a write.

Usage:
    pip install agentdojo==0.1.35   # AgentDojo
    PYTHONPATH=src python scripts/benchmarks/ground_truth_replay.py --benchmark agentdojo
    pip install -e <AgentDyn checkout at the pinned commit>   # in a separate venv
    PYTHONPATH=src python scripts/benchmarks/ground_truth_replay.py --benchmark agentdyn
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Callable

from judikt.provenance import ProvenanceConfig, ProvenanceTracker, argument_values, strings
from judikt.risk import RiskEngine
from judikt.task_scope import TaskScopeConfig, TaskScopeStore

ROOT = Path(__file__).resolve().parents[2]
SCOPE = "agent"
AGENTDYN_CALLS = ROOT / "tests" / "fixtures" / "benchmarks" / "agentdyn_attacker_calls.json"
BENCHMARKS = {
    "agentdojo": {
        "version": "v1.2",
        "suites": None,
        "read_prefixes": ("get", "list", "search", "read", "check"),
        "read_names": (),
        "output": ROOT / "docs" / "evidence" / "agentdojo-replay.json",
    },
    "agentdyn": {
        "version": "v1",
        "suites": ("shopping", "github", "dailylife"),
        "output": ROOT / "docs" / "evidence" / "agentdyn-replay.json",
    },
}
CONFIGURATIONS = ("provenance_everywhere", "provenance", "provenance_and_task_scope")


@dataclass(frozen=True)
class Call:
    function: str
    args: dict[str, Any]


class Replay:
    def __init__(self, suite: Any, read_prefixes: tuple[str, ...], read_names: tuple[str, ...]) -> None:
        from agentdojo.functions_runtime import FunctionsRuntime

        self.suite = suite
        self.runtime = FunctionsRuntime(suite.tools)
        risk = RiskEngine({})
        self.tiers = {}
        for tool in suite.tools:
            read_only = tool.name in read_names or tool.name.split("_", 1)[0] in read_prefixes
            definition = {"name": tool.name, "annotations": {"readOnlyHint": read_only, "destructiveHint": False}}
            self.tiers[tool.name] = risk.tier(tool.name, definition)

    def run(
        self,
        environment: Any,
        calls: list[Any],
        trackers: dict[str, ProvenanceTracker],
        scopes: dict[str, TaskScopeStore],
    ) -> list[dict[str, Any]]:
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

        steps = []
        for call in calls:
            arguments = dict(call.args)
            tier = self.tiers.get(call.function, "write")
            holds: dict[str, list[str]] = {}
            for name, tracker in trackers.items():
                reasons = []
                if tier != "read":
                    if tracker.matches(SCOPE, arguments):
                        reasons.extend(sorted(_matched(tracker, arguments)))
                    scope = scopes.get(name)
                    if scope is not None and not scope.permits(SCOPE, self.suite.name, call.function):
                        reasons.append(f"task_scope:{call.function}")
                holds[name] = reasons
                tracker.observe_arguments(SCOPE, arguments)
            if call.function in self.tiers:
                result, error = self.runtime.run_function(environment, call.function, arguments)
            else:
                result, error = None, f"unknown tool {call.function}"
            seen = tool_result_to_str(result) if error is None else str(error)
            for name, tracker in trackers.items():
                tracker.observe_result(SCOPE, self.suite.name, call.function, seen)
                if name in scopes:
                    scopes[name].seal(SCOPE)
            steps.append({"tool": call.function, "tier": tier, "holds": holds, "seen": seen})
        return steps


def _matched(tracker: ProvenanceTracker, arguments: dict[str, Any]) -> set[str]:
    keys = {key for text in strings(arguments) for key in argument_values(text)}
    return {f"{kind}:{value}" for kind, value in keys if tracker._origins.get((SCOPE, kind, value))}


def _gates(declared: frozenset[str]) -> tuple[dict[str, ProvenanceTracker], dict[str, TaskScopeStore]]:
    trackers = {
        "provenance_everywhere": ProvenanceTracker(ProvenanceConfig(track="everywhere")),
        "provenance": ProvenanceTracker(ProvenanceConfig()),
        "provenance_and_task_scope": ProvenanceTracker(ProvenanceConfig()),
    }
    scopes = {"provenance_and_task_scope": TaskScopeStore(TaskScopeConfig(mode="operator", write_tools=declared))}
    return trackers, scopes


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


def evaluate(suite: Any, replay: Replay, attacker_calls: Callable[[Any, Any], list[Any]]) -> dict[str, Any]:
    utility: list[dict[str, Any]] = []
    declared_for: dict[str, frozenset[str]] = {}
    for task_id, task in suite.user_tasks.items():
        environment = suite.load_and_inject_default_environment({})
        calls = task.ground_truth(environment.model_copy(deep=True))
        declared = frozenset(call.function for call in calls if replay.tiers.get(call.function, "write") != "read")
        declared_for[task_id] = declared
        trackers, scopes = _gates(declared)
        steps = replay.run(environment, calls, trackers, scopes)
        writes = [step for step in steps if step["tier"] != "read"]
        utility.append(
            {
                "user_task": task_id,
                "writes": len(writes),
                "held": {
                    name: [{"tool": step["tool"], "why": step["holds"][name]} for step in writes if step["holds"][name]]
                    for name in CONFIGURATIONS
                },
            }
        )
    attacks: list[dict[str, Any]] = []
    skipped: dict[str, set[str]] = defaultdict(set)
    for task_id, task in suite.user_tasks.items():
        try:
            vectors = candidates(suite, task)
        except ValueError:
            skipped["user_task_not_injectable"].add(task_id)
            continue
        for injection_id, injection in suite.injection_tasks.items():
            payload = injection_text(injection.GOAL)
            environment = suite.load_and_inject_default_environment({vector: payload for vector in vectors})
            trackers, scopes = _gates(declared_for[task_id])
            user_steps = replay.run(environment, task.ground_truth(environment.model_copy(deep=True)), trackers, scopes)
            calls = attacker_calls(injection, environment)
            if not calls:
                skipped["no_attacker_calls"].add(injection_id)
                continue
            attack_steps = replay.run(environment, calls, trackers, scopes)
            writes = [step for step in attack_steps if step["tier"] != "read"]
            if not writes:
                skipped["attack_makes_no_write"].add(injection_id)
                continue
            attacks.append(
                {
                    "user_task": task_id,
                    "injection_task": injection_id,
                    "attacker_writes": len(writes),
                    "held": {name: any(step["holds"][name] for step in writes) for name in CONFIGURATIONS},
                    "why": {
                        name: sorted({reason for step in writes for reason in step["holds"][name]})
                        for name in CONFIGURATIONS
                    },
                    "agent_saw_injection": any("<INFORMATION>" in step["seen"] for step in user_steps),
                }
            )
    return {
        "utility": utility,
        "attacks": attacks,
        "not_scored": {reason: sorted(ids) for reason, ids in skipped.items()},
    }


def rate(rows: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    hits = sum(1 for row in rows if predicate(row))
    return {"count": hits, "of": len(rows), "rate": round(hits / len(rows), 4) if rows else None}


def summarise(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    def section(utility: list[dict[str, Any]], attacks: list[dict[str, Any]]) -> dict[str, Any]:
        writing = [row for row in utility if row["writes"]]
        out: dict[str, Any] = {"agent_saw_the_injection": rate(attacks, lambda row: row["agent_saw_injection"])}
        for name in CONFIGURATIONS:
            by_injection: dict[str, list[bool]] = defaultdict(list)
            for row in attacks:
                by_injection[row["injection_task"]].append(row["held"][name])
            out[name] = {
                "attacks_held": rate(attacks, lambda row, n=name: row["held"][n]),
                "user_tasks_with_a_held_write": rate(utility, lambda row, n=name: bool(row["held"][n])),
                "user_tasks_with_a_held_write_among_tasks_that_write": rate(
                    writing, lambda row, n=name: bool(row["held"][n])
                ),
                "injection_tasks_never_held": sorted(key for key, held in by_injection.items() if not any(held)),
            }
        return out

    report = {name: section(result["utility"], result["attacks"]) for name, result in results.items()}
    report["all"] = section(
        [row for result in results.values() for row in result["utility"]],
        [row for result in results.values() for row in result["attacks"]],
    )
    return report


def agentdyn_calls(suite_name: str, pinned: dict[str, Any]) -> Callable[[Any, Any], list[Any]]:
    table = pinned["calls"][suite_name]

    def calls(injection: Any, environment: Any) -> list[Any]:
        return [Call(item["function"], item["args"]) for item in table.get(injection.ID, [])]

    return calls


def agentdyn_commit() -> str:
    import agentdojo

    source = Path(agentdojo.__file__).resolve().parents[2]
    try:
        return subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--benchmark", choices=sorted(BENCHMARKS), default="agentdojo")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    spec = dict(BENCHMARKS[args.benchmark])
    if metadata.version("agentdojo") != "0.1.35":
        raise SystemExit("agentdojo 0.1.35 (or AgentDyn at the pinned commit) is required")
    from agentdojo.task_suite.load_suites import get_suite, get_suites

    source: dict[str, Any] = {"framework_version": metadata.version("agentdojo")}
    if args.benchmark == "agentdyn":
        pinned = json.loads(AGENTDYN_CALLS.read_text())
        commit = agentdyn_commit()
        if commit != pinned["agentdyn_commit"]:
            raise SystemExit(f"AgentDyn must be installed from commit {pinned['agentdyn_commit']} (found {commit})")
        spec["read_prefixes"] = tuple(pinned["read_only_prefixes"])
        spec["read_names"] = tuple(pinned["read_only_names"])
        suites = {name: get_suite(spec["version"], name) for name in spec["suites"]}
        source.update({"repository": "https://github.com/leolee99/AgentDyn", "commit": commit})
        callers = {name: agentdyn_calls(name, pinned) for name in suites}
    else:
        suites = dict(sorted(get_suites(spec["version"]).items()))
        callers = {name: (lambda injection, environment: injection.ground_truth(environment.model_copy(deep=True))) for name in suites}
    results = {
        name: evaluate(suite, Replay(suite, spec["read_prefixes"], spec["read_names"]), callers[name])
        for name, suite in suites.items()
    }
    summary = summarise(results)
    report = {
        "benchmark": f"{args.benchmark} {spec['version']} ground-truth replay of Judikt's write gates",
        "source": source,
        "configurations": {
            "provenance_everywhere": "untrusted_provenance with track: everywhere",
            "provenance": "untrusted_provenance with the default track: instructed",
            "provenance_and_task_scope": "the default plus task_scope.write_tools = the user task's own correct writes",
        },
        "notes": [
            "No language model runs; ground-truth calls stand in for the agent.",
            f"Read-only tools: names starting with {', '.join(spec['read_prefixes'])}"
            + (f", plus {', '.join(spec['read_names'])}" if spec["read_names"] else "")
            + "; every other tool is a write.",
            "A held write is one the gate stops for human approval.",
            "Attacks: the injection is planted in every vector the user task reads, with the important_instructions template.",
            "An attack counts as held if any of its writes is held. Attacks that make no write are not scored.",
            "The content guard is not applied.",
        ],
        "not_scored": {name: result["not_scored"] for name, result in results.items()},
        "summary": summary,
        "details": {name: {"utility": result["utility"], "attacks": result["attacks"]} for name, result in results.items()},
    }
    output = args.output or spec["output"]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    for suite_name, section in summary.items():
        line = [f"{suite_name:10}"]
        for name in CONFIGURATIONS:
            held = section[name]["attacks_held"]
            burden = section[name]["user_tasks_with_a_held_write"]
            line.append(f"{name}: {held['count']}/{held['of']} held, {burden['count']}/{burden['of']} tasks prompted")

        print(" | ".join(line))


if __name__ == "__main__":
    main()
