from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from judikt.approval import ApprovalAuthority
from judikt.backends import KubernetesBackend
from judikt.catalog import gateway_result
from judikt.ops_runtime import JudiktOpsRuntime
from judikt.paths import DEMO_POLICY_PATH
from judikt.protocol import GuardedToolError, MCPProtocolError


APPROVAL_SECRET = "kubernetes-restart-approval-secret-at-least-32-bytes"
ROLLBACK_PLAN = "wait for a ready replacement and restore workload capacity on failure"


class KubernetesSimulatorRestartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.backend = KubernetesBackend(
            {
                "state_db": str(Path(self.temp_dir.name) / "kubernetes.db"),
                "verification_timeout_seconds": 0.04,
                "poll_interval_seconds": 0.005,
            }
        )

    def arguments(self, key: str, **extra: object) -> dict[str, object]:
        return {
            "namespace": "prod",
            "pod": "payment-service-xyz",
            "idempotency_key": key,
            **extra,
        }

    def test_unowned_pod_is_refused(self) -> None:
        self.backend.pods[("prod", "payment-service-xyz")]["owner"] = None

        with self.assertRaises(GuardedToolError) as raised:
            self.backend.call(
                "kubernetes.restart_pod",
                self.arguments("unowned"),
            )

        self.assertEqual(raised.exception.rule, "unowned_pod")
        self.assertEqual(raised.exception.result["status"], "refused")

    def test_pdb_with_no_disruptions_blocks_restart(self) -> None:
        self.backend.pods[("prod", "payment-service-xyz")][
            "pdb_disruptions_allowed"
        ] = 0

        with self.assertRaises(GuardedToolError) as raised:
            self.backend.call(
                "kubernetes.restart_pod",
                self.arguments("pdb-blocked"),
            )

        self.assertEqual(raised.exception.rule, "pdb_blocks")

    def test_single_replica_requires_explicit_allow_downtime(self) -> None:
        pod = self.backend.pods[("prod", "payment-service-xyz")]
        pod.update(
            {
                "desired_replicas": 1,
                "available_replicas": 1,
                "max_unavailable": 1,
            }
        )

        with self.assertRaises(GuardedToolError) as raised:
            self.backend.call(
                "kubernetes.restart_pod",
                self.arguments("single-refused"),
            )
        allowed = self.backend.call(
            "kubernetes.restart_pod",
            self.arguments("single-allowed", allow_downtime=True),
        )

        self.assertEqual(raised.exception.rule, "would_cause_downtime")
        self.assertEqual(allowed["status"], "verified")

    def test_happy_path_is_verified_and_idempotent(self) -> None:
        arguments = self.arguments("same-operation")

        first = self.backend.call("kubernetes.restart_pod", arguments)
        second = self.backend.call("kubernetes.restart_pod", arguments)

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "verified")
        self.assertEqual(first["owner"], {"kind": "Deployment", "name": "payment-service"})
        self.assertEqual(
            self.backend.pods[("prod", "payment-service-xyz")]["eviction_count"],
            1,
        )

    def test_never_ready_replacement_times_out(self) -> None:
        self.backend.pods[("prod", "payment-service-xyz")][
            "replacement_ready"
        ] = False

        with self.assertRaises(GuardedToolError) as raised:
            self.backend.call(
                "kubernetes.restart_pod",
                self.arguments("never-ready"),
            )
        with self.assertRaises(GuardedToolError) as repeated:
            self.backend.call(
                "kubernetes.restart_pod",
                self.arguments("never-ready"),
            )

        self.assertEqual(raised.exception.rule, "restart_verification_timeout")
        self.assertEqual(repeated.exception.rule, "restart_verification_timeout")
        self.assertTrue(raised.exception.operational_failure)
        self.assertEqual(raised.exception.result["status"], "timed_out")
        self.assertEqual(
            self.backend.pods[("prod", "payment-service-xyz")]["eviction_count"],
            1,
        )

    def test_already_restarted_pod_is_detected(self) -> None:
        old = self.backend.pods[("prod", "payment-service-xyz")]
        old["terminating"] = True
        old["ready"] = False
        replacement = {
            **old,
            "pod": "payment-service-replacement-existing",
            "terminating": False,
            "ready": True,
            "status": "Running",
        }
        self.backend.pods[("prod", replacement["pod"])] = replacement

        result = self.backend.call(
            "kubernetes.restart_pod",
            self.arguments("already-restarted"),
        )

        self.assertEqual(result["status"], "already_restarted")
        self.assertEqual(result["new_pod"], replacement["pod"])
        self.assertNotIn("eviction_count", old)

    def test_production_target_requires_idempotency_key(self) -> None:
        with self.assertRaises(GuardedToolError) as raised:
            self.backend.call(
                "kubernetes.restart_pod",
                {"namespace": "prod", "pod": "payment-service-xyz"},
            )
        self.assertEqual(raised.exception.rule, "idempotency_required")


class KubernetesPipelineFailureTest(unittest.TestCase):
    def test_timeout_is_mcp_error_audited_and_emits_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "JUDIKT_KUBERNETES_MODE": "simulated",
                "JUDIKT_KUBERNETES_STATE_DB": str(Path(directory) / "kubernetes.db"),
                "XDG_STATE_HOME": str(Path(directory) / "state"),
                "JUDIKT_AUDIT_HMAC_SECRET": "kubernetes-audit-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
            },
            clear=False,
        ):
            runtime = JudiktOpsRuntime(
                DEMO_POLICY_PATH,
                Path(directory) / "audit.db",
                include_demo_servers=True,
                approval_authority=ApprovalAuthority(APPROVAL_SECRET),
            )
            assert runtime.kubernetes is not None
            runtime.kubernetes.verification_timeout = 0.03
            runtime.kubernetes.poll_interval = 0.005
            runtime.kubernetes.pods[("prod", "payment-service-xyz")][
                "replacement_ready"
            ] = False
            arguments = {
                "namespace": "prod",
                "pod": "payment-service-xyz",
                "idempotency_key": "pipeline-never-ready",
                "actor": "sre-oncall",
                "environment": "production",
                "rollback_plan": ROLLBACK_PLAN,
            }
            token = runtime.policy.issue_approval(
                actor="sre-oncall",
                reason="test readiness timeout",
                server="kubernetes",
                tool="kubernetes.restart_pod",
                arguments=arguments,
            )
            try:
                with mock.patch.object(
                    runtime.findings,
                    "dispatch",
                    return_value="disabled",
                ) as dispatch:
                    outcome = runtime.call_tool(
                        "kubernetes",
                        "kubernetes.restart_pod",
                        {**arguments, "approval_token": token},
                    )
                audit = runtime.audit.recent()
            finally:
                runtime.close()

        rendered = gateway_result(outcome)
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.rule, "restart_verification_timeout")
        self.assertEqual(outcome.result["status"], "timed_out")
        self.assertTrue(rendered["isError"])
        self.assertEqual(rendered["structuredContent"]["status"], "timed_out")
        self.assertEqual(audit[0]["rule"], "restart_verification_timeout")
        dispatch.assert_called_once()
        self.assertEqual(dispatch.call_args.args[0]["rule"], "restart_verification_timeout")


class KubernetesKubectlRestartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.log_path = self.root / "kubectl.jsonl"
        self.cluster_state = self.root / "cluster.json"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.kubectl_path = self.bin_dir / "kubectl"
        self.kubectl_path.write_text(_FAKE_KUBECTL)
        self.kubectl_path.chmod(0o755)
        self.environment = {
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_KUBECTL_LOG": str(self.log_path),
            "FAKE_KUBECTL_STATE": str(self.cluster_state),
            "JUDIKT_KUBERNETES_MODE": "kubectl",
        }

    def backend(self, **overrides: object) -> KubernetesBackend:
        return KubernetesBackend(
            {
                "context": "kind-judikt",
                "state_db": str(self.root / "idempotency.db"),
                "subprocess_timeout_seconds": 2,
                "verification_timeout_seconds": 1,
                "poll_interval_seconds": 0.01,
                **overrides,
            }
        )

    def test_exact_preflight_eviction_and_verification_commands(self) -> None:
        original_run = subprocess.run
        observed_kwargs: list[dict[str, object]] = []

        def checked_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            observed_kwargs.append(dict(kwargs))
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["timeout"], 2.0)
            return original_run(*args, **kwargs)

        with mock.patch.dict(os.environ, self.environment, clear=False), mock.patch(
            "judikt.backends.subprocess.run",
            side_effect=checked_run,
        ):
            result = self.backend().call(
                "kubernetes.restart_pod",
                {
                    "namespace": "prod",
                    "pod": "payments-abc",
                    "idempotency_key": "fake-kubectl-happy",
                },
            )

        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        argument_vectors = [call["args"] for call in calls]
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["new_pod"], "payments-new")
        self.assertTrue(observed_kwargs)
        self.assertTrue(
            all(args[:2] == ["--context", "kind-judikt"] for args in argument_vectors)
        )
        self.assertEqual(
            argument_vectors,
            [
                ["--context", "kind-judikt", "get", "pod", "payments-abc", "-n", "prod", "-o", "json"],
                ["--context", "kind-judikt", "get", "replicaset", "payments-rs", "-n", "prod", "-o", "json"],
                ["--context", "kind-judikt", "get", "deployment", "payments", "-n", "prod", "-o", "json"],
                ["--context", "kind-judikt", "get", "pods", "-n", "prod", "-o", "json"],
                ["--context", "kind-judikt", "get", "pdb", "-n", "prod", "-o", "json"],
                [
                    "--context",
                    "kind-judikt",
                    "create",
                    "--raw",
                    "/api/v1/namespaces/prod/pods/payments-abc/eviction",
                    "-f",
                    "-",
                ],
                ["--context", "kind-judikt", "get", "pods", "-n", "prod", "-o", "json"],
                ["--context", "kind-judikt", "get", "deployment", "payments", "-n", "prod", "-o", "json"],
            ],
        )
        eviction = calls[5]
        body = json.loads(eviction["stdin"])
        self.assertEqual(body["kind"], "Eviction")
        self.assertEqual(body["metadata"], {"name": "payments-abc", "namespace": "prod"})

    def test_server_side_dry_run_performs_preflight_without_mutation(self) -> None:
        with mock.patch.dict(os.environ, self.environment, clear=False):
            result = self.backend().call(
                "kubernetes.restart_pod",
                {
                    "namespace": "prod",
                    "pod": "payments-abc",
                    "idempotency_key": "fake-kubectl-dry-run",
                    "dry_run": True,
                },
            )

        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        eviction = next(call for call in calls if "--raw" in call["args"])
        self.assertIn("--dry-run=server", eviction["args"])
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["dry_run"])
        self.assertFalse(json.loads(self.cluster_state.read_text())["evicted"])

    def test_eviction_failure_is_not_deleted_without_explicit_fallback(self) -> None:
        environment = {**self.environment, "FAKE_KUBECTL_EVICTION_FAIL": "true"}
        with mock.patch.dict(os.environ, environment, clear=False), self.assertRaises(
            GuardedToolError
        ) as raised:
            self.backend().call(
                "kubernetes.restart_pod",
                {
                    "namespace": "prod",
                    "pod": "payments-abc",
                    "idempotency_key": "fake-kubectl-eviction-failed",
                },
            )

        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(raised.exception.rule, "restart_failed")
        self.assertEqual(raised.exception.result["status"], "failed")
        self.assertFalse(any("delete" in call["args"] for call in calls))

    def test_explicit_delete_fallback_is_verified(self) -> None:
        environment = {**self.environment, "FAKE_KUBECTL_EVICTION_FAIL": "true"}
        with mock.patch.dict(os.environ, environment, clear=False):
            result = self.backend(allow_delete_fallback=True).call(
                "kubernetes.restart_pod",
                {
                    "namespace": "prod",
                    "pod": "payments-abc",
                    "idempotency_key": "fake-kubectl-delete-fallback",
                },
            )

        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["checks"]["eviction"], "delete_fallback")
        self.assertIn(
            [
                "--context",
                "kind-judikt",
                "delete",
                "pod",
                "payments-abc",
                "-n",
                "prod",
                "--wait=false",
            ],
            [call["args"] for call in calls],
        )

    def test_invalid_names_are_rejected_before_kubectl(self) -> None:
        with mock.patch.dict(os.environ, self.environment, clear=False), mock.patch(
            "judikt.backends.subprocess.run"
        ) as run, self.assertRaises(GuardedToolError) as raised:
            self.backend().call(
                "kubernetes.restart_pod",
                {
                    "namespace": "Prod_Invalid",
                    "pod": "payments-abc",
                    "idempotency_key": "invalid-name",
                },
            )
        self.assertEqual(raised.exception.rule, "invalid_kubernetes_name")
        run.assert_not_called()

    def test_subprocess_timeout_is_enforced(self) -> None:
        environment = {**self.environment, "FAKE_KUBECTL_SLEEP": "0.2"}
        with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
            MCPProtocolError,
            "timed out",
        ):
            self.backend(subprocess_timeout_seconds=0.03).call(
                "kubernetes.get_pod",
                {"namespace": "prod", "pod": "payments-abc"},
            )

    def test_kubectl_mode_requires_explicit_context(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"JUDIKT_KUBERNETES_MODE": "kubectl", "JUDIKT_KUBERNETES_CONTEXT": ""},
            clear=False,
        ), self.assertRaisesRegex(ValueError, "kubernetes.context"):
            KubernetesBackend()


@unittest.skipUnless(
    os.getenv("JUDIKT_TEST_KUBECONFIG"),
    "set JUDIKT_TEST_KUBECONFIG for the optional kind-backed test",
)
class KubernetesKindOptionalTest(unittest.TestCase):
    def test_server_side_dry_run_against_kind(self) -> None:
        namespace = os.getenv("JUDIKT_TEST_KUBERNETES_NAMESPACE", "default")
        pod = os.getenv("JUDIKT_TEST_KUBERNETES_POD", "")
        if not pod:
            self.skipTest("set JUDIKT_TEST_KUBERNETES_POD to a controlled pod")
        kubeconfig = str(os.environ["JUDIKT_TEST_KUBECONFIG"])
        current = subprocess.run(
            ["kubectl", "config", "current-context", "--kubeconfig", kubeconfig],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "KUBECONFIG": kubeconfig,
                "JUDIKT_KUBERNETES_MODE": "kubectl",
            },
            clear=False,
        ):
            backend = KubernetesBackend(
                {
                    "context": current,
                    "state_db": str(Path(directory) / "idempotency.db"),
                }
            )
            result = backend.call(
                "kubernetes.restart_pod",
                {
                    "namespace": namespace,
                    "pod": pod,
                    "idempotency_key": "optional-kind-dry-run",
                    "dry_run": True,
                },
            )
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["dry_run"])


_FAKE_KUBECTL = textwrap.dedent(
    r"""
    #!/usr/bin/env python3
    import json
    import os
    import sys
    import time
    from pathlib import Path

    log_path = Path(os.environ["FAKE_KUBECTL_LOG"])
    state_path = Path(os.environ["FAKE_KUBECTL_STATE"])
    if state_path.exists():
        state = json.loads(state_path.read_text())
    else:
        state = {"evicted": False}
        state_path.write_text(json.dumps(state))
    delay = float(os.getenv("FAKE_KUBECTL_SLEEP", "0"))
    if delay:
        time.sleep(delay)
    arguments = sys.argv[1:]
    stdin = sys.stdin.read()
    with log_path.open("a") as stream:
        stream.write(json.dumps({"args": arguments, "stdin": stdin}) + "\n")
    command = arguments[2:]

    def emit(value):
        print(json.dumps(value))

    owner = [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "payments-rs", "controller": True}]
    ready = [{"type": "Ready", "status": "True"}]
    old_pod = {
        "metadata": {"name": "payments-abc", "labels": {"app": "payments"}, "ownerReferences": owner},
        "status": {"conditions": ready},
    }
    new_pod = {
        "metadata": {"name": "payments-new", "labels": {"app": "payments"}, "ownerReferences": owner},
        "status": {"conditions": ready},
    }
    if command[:3] == ["get", "pod", "payments-abc"]:
        if state["evicted"]:
            print("Error from server (NotFound): pods payments-abc not found", file=sys.stderr)
            raise SystemExit(1)
        emit(old_pod)
    elif command[:3] == ["get", "replicaset", "payments-rs"]:
        emit({"metadata": {"ownerReferences": [{"kind": "Deployment", "name": "payments", "controller": True}]}})
    elif command[:3] == ["get", "deployment", "payments"]:
        emit({
            "spec": {"replicas": 2, "strategy": {"rollingUpdate": {"maxUnavailable": 1}}},
            "status": {"availableReplicas": 2},
        })
    elif command[:2] == ["get", "pods"]:
        emit({"items": [new_pod] if state["evicted"] else [old_pod]})
    elif command[:2] == ["get", "pdb"]:
        emit({"items": [{"spec": {"selector": {"matchLabels": {"app": "payments"}}}, "status": {"disruptionsAllowed": 1}}]})
    elif command[:2] == ["create", "--raw"]:
        if os.getenv("FAKE_KUBECTL_EVICTION_FAIL") == "true":
            print("eviction rejected", file=sys.stderr)
            raise SystemExit(2)
        if "--dry-run=server" not in command:
            state["evicted"] = True
            state_path.write_text(json.dumps(state))
        emit({"status": "Success"})
    elif command[:3] == ["delete", "pod", "payments-abc"]:
        state["evicted"] = True
        state_path.write_text(json.dumps(state))
        print("pod deleted")
    elif command[:3] == ["rollout", "status", "deployment/payments"]:
        print("deployment successfully rolled out")
    else:
        print("unsupported fake kubectl command", file=sys.stderr)
        raise SystemExit(2)
    """
).lstrip()


if __name__ == "__main__":
    unittest.main()
