from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

from .models import Tool
from .paths import ensure_private_directory, state_root
from .protocol import GuardedToolError, MCPProtocolError, serve_stdio


def _schema(**properties: dict[str, str]) -> dict[str, Any]:
    optional = {
        "allow_downtime",
        "actor",
        "auto_create_incident",
        "dry_run",
        "environment",
        "incident_id",
        "idempotency_key",
        "requested_by",
        "rollback_plan",
        "shadow_mode",
        "user",
    }
    return {
        "type": "object",
        "properties": properties,
        "required": [name for name in properties if name not in optional],
        "additionalProperties": False,
    }


PLATFORM_TOOLS = [
    Tool(
        "platform.health",
        "Inspect the deployment health, replica counts, release, and error rate of a production service.",
        _schema(service={"type": "string"}),
    ),
    Tool(
        "platform.read_config",
        "Read runtime configuration for a production service. Secrets are redacted by Judikt.",
        _schema(service={"type": "string"}),
    ),
    Tool(
        "platform.read_logs",
        "Read recent application logs for a production service.",
        _schema(
            service={"type": "string"},
            query={"type": "string"},
            limit={"type": "integer", "minimum": 1, "maximum": 100},
        ),
    ),
    Tool(
        "platform.run_diagnostic",
        "Run an allowlisted diagnostic command against a production service.",
        _schema(service={"type": "string"}, command={"type": "string"}),
    ),
    Tool(
        "platform.restart_deployment",
        "Perform a rolling restart of a production deployment after explicit approval.",
        _schema(
            service={"type": "string"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
    Tool(
        "platform.rollback_deployment",
        "Roll a production deployment back to a known release after explicit approval.",
        _schema(
            service={"type": "string"},
            version={"type": "string"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
]

KUBERNETES_TOOLS = [
    Tool(
        "kubernetes.get_pod",
        "Read pod status from a Kubernetes namespace. Uses a safe simulator by default.",
        _schema(namespace={"type": "string"}, pod={"type": "string"}),
    ),
    Tool(
        "kubernetes.restart_pod",
        "Restart an owned Kubernetes pod through PDB-aware eviction and verify a ready replacement. Requires actor, approval, rollback plan, and idempotency key in production.",
        _schema(
            namespace={"type": "string"},
            pod={"type": "string"},
            idempotency_key={"type": "string", "minLength": 1, "maxLength": 128},
            allow_downtime={"type": "boolean"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
    Tool(
        "kubernetes.rollout_status",
        "Read rollout status for a Kubernetes deployment.",
        _schema(namespace={"type": "string"}, deployment={"type": "string"}),
    ),
]

INCIDENT_TOOLS = [
    Tool(
        "incident.create",
        "Create an operational incident.",
        _schema(title={"type": "string"}, severity={"type": "string"}),
    ),
    Tool(
        "incident.attach_evidence",
        "Attach a correlated audit event to an incident.",
        _schema(incident_id={"type": "string"}, evidence={"type": "object"}),
    ),
    Tool(
        "incident.timeline",
        "Read the incident timeline.",
        _schema(incident_id={"type": "string"}),
    ),
]


class PlatformOpsBackend:
    def __init__(self) -> None:
        self.services = {
            "payments-api": {
                "status": "degraded",
                "release": "payments-api@2026.05.3",
                "replicas": {"desired": 4, "available": 4},
                "error_rate_5m": 0.042,
                "p99_latency_ms": 836,
                "restarts": 0,
            },
            "checkout-worker": {
                "status": "healthy",
                "release": "checkout-worker@2026.05.1",
                "replicas": {"desired": 3, "available": 3},
                "error_rate_5m": 0.001,
                "p99_latency_ms": 142,
                "restarts": 0,
            },
        }

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        service = arguments.get("service", "")
        if service not in self.services:
            raise MCPProtocolError(f"unknown service: {service}")
        state = self.services[service]
        if tool == "platform.health":
            return {"service": service, **state}
        if tool == "platform.read_config":
            return {
                "service": service,
                "environment": "production",
                "region": "us-east-1",
                "log_level": "INFO",
                "database_pool_size": 20,
                "api_key": "sk-demo-sensitive-value",
            }
        if tool == "platform.read_logs":
            limit = arguments["limit"]
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
                raise MCPProtocolError("log limit must be an integer between 1 and 100")
            return {
                "service": service,
                "query": arguments["query"],
                "logs": [
                    "2026-05-31T09:15:02Z WARN payment provider timeout dependency=stripe",
                    "2026-05-31T09:15:03Z ERROR request failed route=/v1/charge status=503",
                ][:limit],
            }
        if tool == "platform.run_diagnostic":
            command = arguments["command"]
            diagnostics = {
                "dependency-health": "stripe-api=degraded postgres=healthy redis=healthy",
                "error-rate": "http_5xx_rate_5m=0.042 timeout_rate_5m=0.038",
                "latency-summary": "p50_ms=91 p95_ms=440 p99_ms=836",
            }
            if command not in diagnostics:
                raise MCPProtocolError("diagnostic command is not allowlisted")
            return {"service": service, "command": command, "output": diagnostics[command]}
        if tool == "platform.restart_deployment":
            state["restarts"] += 1
            return {
                "service": service,
                **state,
                "service_status": state["status"],
                "action": "rolling_restart",
                "status": "completed",
            }
        if tool == "platform.rollback_deployment":
            previous = state["release"]
            state["release"] = arguments["version"]
            state["status"] = "healthy"
            state["error_rate_5m"] = 0.003
            state["p99_latency_ms"] = 176
            return {
                "service": service,
                "action": "deployment_rollback",
                "from_release": previous,
                "to_release": state["release"],
                "status": "completed",
            }
        raise MCPProtocolError(f"unsupported platform tool: {tool}")


class KubernetesBackend:
    """Kubernetes operations adapter.

    The default mode is a deterministic simulator so the project remains safe,
    portable, and free-tier friendly. Set JUDIKT_KUBERNETES_MODE=kubectl to
    point the adapter at a real kubeconfig for a controlled lab environment.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = dict(config or {})
        self.mode = os.getenv("JUDIKT_KUBERNETES_MODE", "simulated").lower()
        if self.mode not in {"simulated", "kubectl"}:
            raise ValueError("JUDIKT_KUBERNETES_MODE must be simulated or kubectl")
        self.context = str(
            self.config.get("context")
            or os.getenv("JUDIKT_KUBERNETES_CONTEXT", "")
        ).strip()
        if self.mode == "kubectl" and not self.context:
            raise ValueError("kubernetes.context is required in kubectl mode")
        self.allow_delete_fallback = _boolean_setting(
            self.config,
            "allow_delete_fallback",
            False,
        )
        self.subprocess_timeout = _positive_setting(
            self.config,
            "subprocess_timeout_seconds",
            20.0,
        )
        self.verification_timeout = _positive_setting(
            self.config,
            "verification_timeout_seconds",
            180.0,
        )
        self.poll_interval = _positive_setting(
            self.config,
            "poll_interval_seconds",
            3.0,
        )
        configured_state = str(
            self.config.get("state_db")
            or os.getenv("JUDIKT_KUBERNETES_STATE_DB", "")
        ).strip()
        self.state_path = (
            Path(configured_state).expanduser()
            if configured_state
            else state_root() / "kubernetes-restarts.db"
        )
        self._known_targets: dict[tuple[str, str], dict[str, Any]] = {}
        self.pods = {
            ("prod", "payment-service-xyz"): {
                "namespace": "prod",
                "pod": "payment-service-xyz",
                "deployment": "payment-service",
                "owner": {
                    "kind": "Deployment",
                    "name": "payment-service",
                    "direct_kind": "ReplicaSet",
                    "direct_name": "payment-service-7d9f5d",
                },
                "desired_replicas": 2,
                "available_replicas": 2,
                "max_unavailable": 1,
                "pdb_disruptions_allowed": 1,
                "status": "Running",
                "restarts": 0,
                "ready": True,
                "replacement_ready": True,
                "readiness_delay": 0.0,
                "node": "ip-10-0-12-44.ec2.internal",
            },
            ("prod", "payments-api-7d9f5d"): {
                "namespace": "prod",
                "pod": "payments-api-7d9f5d",
                "deployment": "payments-api",
                "owner": {
                    "kind": "Deployment",
                    "name": "payments-api",
                    "direct_kind": "ReplicaSet",
                    "direct_name": "payments-api-7d9f5d",
                },
                "desired_replicas": 2,
                "available_replicas": 2,
                "max_unavailable": 1,
                "pdb_disruptions_allowed": 1,
                "status": "Running",
                "restarts": 1,
                "ready": True,
                "replacement_ready": True,
                "readiness_delay": 0.0,
                "node": "ip-10-0-9-13.ec2.internal",
            },
        }

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if tool == "kubernetes.get_pod":
            return self._get_pod(arguments)
        if tool == "kubernetes.restart_pod":
            return self._restart_pod(arguments)
        if tool == "kubernetes.rollout_status":
            return self._rollout_status(arguments)
        raise MCPProtocolError(f"unsupported kubernetes tool: {tool}")

    def _get_pod(self, arguments: dict[str, Any]) -> dict[str, Any]:
        namespace, pod = self._validated_target(arguments)
        if self.mode == "kubectl":
            return self._kubectl_json(["get", "pod", pod, "-n", namespace, "-o", "json"])
        return dict(self._pod(namespace, pod))

    def _restart_pod(self, arguments: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        namespace, pod = self._validated_target(arguments)
        production = _production_target(namespace, arguments)
        idempotency_key = str(arguments.get("idempotency_key", "")).strip()
        if production and not idempotency_key:
            self._refuse(
                "idempotency_required",
                "production pod restarts require idempotency_key",
                namespace,
                pod,
            )
        if idempotency_key and IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._refuse(
                "invalid_idempotency_key",
                "idempotency_key must contain 1-128 safe characters",
                namespace,
                pod,
            )
        prior = self._idempotency_record(idempotency_key, namespace, pod)
        if prior and isinstance(prior.get("result"), dict):
            return self._stored_result(prior["result"])
        prior_context = prior.get("context") if prior else None
        context = (
            self._preflight_kubectl(namespace, pod, arguments, prior_context)
            if self.mode == "kubectl"
            else self._preflight_simulator(namespace, pod, arguments, prior_context)
        )
        if context.get("already_restarted"):
            result = self._restart_result(
                status="already_restarted",
                namespace=namespace,
                old_pod=pod,
                new_pod=context.get("new_pod"),
                owner=context["owner"],
                started=started,
                checks=context["checks"],
            )
            self._finish_idempotency(idempotency_key, namespace, pod, context, result)
            return result
        if prior and prior.get("status") == "in_progress":
            self._refuse(
                "idempotency_in_progress",
                "an operation with this idempotency key is still in progress",
                namespace,
                pod,
            )
        if idempotency_key:
            existing = self._reserve_idempotency(
                idempotency_key,
                namespace,
                pod,
                context,
            )
            if existing is not None:
                return self._stored_result(existing)
        try:
            result = (
                self._restart_kubectl(namespace, pod, arguments, context, started)
                if self.mode == "kubectl"
                else self._restart_simulator(namespace, pod, arguments, context, started)
            )
        except GuardedToolError as exc:
            if idempotency_key and exc.operational_failure:
                self._finish_idempotency(
                    idempotency_key,
                    namespace,
                    pod,
                    context,
                    exc.result,
                )
            raise
        self._finish_idempotency(idempotency_key, namespace, pod, context, result)
        return result

    def _rollout_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        namespace = _dns1123_name(arguments["namespace"], "namespace", 63)
        deployment = _dns1123_name(arguments["deployment"], "deployment", 253)
        if self.mode == "kubectl":
            output = self._kubectl(["rollout", "status", f"deployment/{deployment}", "-n", namespace])
            return {"namespace": namespace, "deployment": deployment, "status": output}
        matching = [pod for pod in self.pods.values() if pod["namespace"] == namespace and pod["deployment"] == deployment]
        return {
            "namespace": namespace,
            "deployment": deployment,
            "available_pods": len([pod for pod in matching if pod["ready"]]),
            "desired_pods": max(len(matching), 1),
            "status": "healthy" if matching else "unknown",
        }

    def _pod(self, namespace: str, pod: str) -> dict[str, Any]:
        key = (namespace, pod)
        if key not in self.pods:
            raise MCPProtocolError(f"unknown pod: {namespace}/{pod}")
        return self.pods[key]

    def _preflight_simulator(
        self,
        namespace: str,
        pod: str,
        arguments: dict[str, Any],
        prior_context: Any,
    ) -> dict[str, Any]:
        state = self.pods.get((namespace, pod))
        if state is None:
            context = prior_context if isinstance(prior_context, dict) else self._known_targets.get((namespace, pod))
            replacement = self._simulated_ready_replacement(namespace, pod, context)
            if replacement is not None and context is not None:
                return {
                    **context,
                    "already_restarted": True,
                    "new_pod": replacement["pod"],
                }
            self._refuse("unowned_pod", "pod does not exist or has no trusted owner", namespace, pod)
        owner = state.get("owner")
        if not isinstance(owner, dict) or owner.get("kind") not in {
            "Deployment",
            "StatefulSet",
            "DaemonSet",
        }:
            self._refuse("unowned_pod", "pod is not owned by a supported workload", namespace, pod)
        context = {
            "owner": {"kind": owner["kind"], "name": owner["name"]},
            "direct_owner": {
                "kind": owner.get("direct_kind", owner["kind"]),
                "name": owner.get("direct_name", owner["name"]),
            },
            "desired": int(state.get("desired_replicas", 1)),
            "available": int(state.get("available_replicas", int(bool(state.get("ready"))))),
            "max_unavailable": int(state.get("max_unavailable", 1)),
            "checks": {"ownership": "passed"},
        }
        self._known_targets[(namespace, pod)] = context
        replacement = self._simulated_ready_replacement(namespace, pod, context)
        if state.get("terminating") and replacement is not None:
            return {
                **context,
                "already_restarted": True,
                "new_pod": replacement["pod"],
            }
        self._check_availability(
            context,
            ready=state.get("ready") is True,
            allow_downtime=arguments.get("allow_downtime") is True,
            namespace=namespace,
            pod=pod,
        )
        context["checks"]["availability"] = "passed"
        if int(state.get("pdb_disruptions_allowed", 1)) == 0:
            self._refuse("pdb_blocks", "a matching PodDisruptionBudget blocks eviction", namespace, pod)
        context["checks"]["pdb"] = "passed"
        return context

    def _restart_simulator(
        self,
        namespace: str,
        pod: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
        started: float,
    ) -> dict[str, Any]:
        state = self._pod(namespace, pod)
        checks = dict(context["checks"])
        if arguments.get("dry_run") is True:
            checks.update({"eviction": "server_dry_run", "replacement": "not_required"})
            return self._restart_result(
                status="verified",
                namespace=namespace,
                old_pod=pod,
                new_pod=None,
                owner=context["owner"],
                started=started,
                checks=checks,
                dry_run=True,
            )
        action_started = time.monotonic()
        state["terminating"] = True
        state["ready"] = False
        state["status"] = "Terminating"
        state["restarts"] = int(state.get("restarts", 0)) + 1
        state["last_restart_at"] = dt.datetime.now(dt.UTC).isoformat()
        state["available_replicas"] = max(0, context["available"] - 1)
        state["eviction_count"] = int(state.get("eviction_count", 0)) + 1
        replacement_name = f"{context['owner']['name']}-replacement-{state['restarts']}"
        replacement = {
            **state,
            "pod": replacement_name,
            "status": "Pending",
            "ready": False,
            "terminating": False,
            "restarts": 0,
        }
        self.pods[(namespace, replacement_name)] = replacement
        checks["eviction"] = "accepted"
        action_ms = (time.monotonic() - action_started) * 1000
        verification_started = time.monotonic()
        ready_at = verification_started + float(state.get("readiness_delay", 0.0))
        deadline = verification_started + self.verification_timeout
        while time.monotonic() < deadline:
            if state.get("replacement_ready", True) and time.monotonic() >= ready_at:
                replacement["ready"] = True
                replacement["status"] = "Running"
                replacement["available_replicas"] = context["available"]
            if replacement["ready"] and replacement["available_replicas"] >= context["available"]:
                checks["replacement"] = "ready"
                return self._restart_result(
                    status="verified",
                    namespace=namespace,
                    old_pod=pod,
                    new_pod=replacement_name,
                    owner=context["owner"],
                    started=started,
                    checks=checks,
                    action_ms=action_ms,
                    verification_ms=(time.monotonic() - verification_started) * 1000,
                )
            time.sleep(self.poll_interval)
        checks["replacement"] = "timed_out"
        result = self._restart_result(
            status="timed_out",
            namespace=namespace,
            old_pod=pod,
            new_pod=replacement_name,
            owner=context["owner"],
            started=started,
            checks=checks,
            action_ms=action_ms,
            verification_ms=(time.monotonic() - verification_started) * 1000,
        )
        raise GuardedToolError(
            "restart_verification_timeout",
            "replacement pod did not become ready before the verification deadline",
            result,
            operational_failure=True,
        )

    def _preflight_kubectl(
        self,
        namespace: str,
        pod: str,
        arguments: dict[str, Any],
        prior_context: Any,
    ) -> dict[str, Any]:
        pod_document = self._kubectl_json_optional(
            ["get", "pod", pod, "-n", namespace, "-o", "json"]
        )
        if pod_document is None:
            context = prior_context if isinstance(prior_context, dict) else self._known_targets.get((namespace, pod))
            replacement = self._ready_replacement(namespace, pod, context)
            if context is not None and replacement is not None:
                return {
                    **context,
                    "already_restarted": True,
                    "new_pod": replacement,
                }
            self._refuse("unowned_pod", "pod does not exist or has no trusted owner", namespace, pod)
        context = self._kubectl_owner_context(namespace, pod_document)
        context["checks"] = {"ownership": "passed"}
        self._known_targets[(namespace, pod)] = context
        replacement = self._ready_replacement(namespace, pod, context)
        if pod_document.get("metadata", {}).get("deletionTimestamp") and replacement:
            return {
                **context,
                "already_restarted": True,
                "new_pod": replacement,
            }
        self._check_availability(
            context,
            ready=_pod_ready(pod_document),
            allow_downtime=arguments.get("allow_downtime") is True,
            namespace=namespace,
            pod=pod,
        )
        context["checks"]["availability"] = "passed"
        pdbs = self._kubectl_json(["get", "pdb", "-n", namespace, "-o", "json"])
        labels = pod_document.get("metadata", {}).get("labels", {})
        for pdb in pdbs.get("items", []):
            selector = pdb.get("spec", {}).get("selector", {})
            if _selector_matches(selector, labels) and int(
                pdb.get("status", {}).get("disruptionsAllowed", 0)
            ) == 0:
                self._refuse(
                    "pdb_blocks",
                    "a matching PodDisruptionBudget blocks eviction",
                    namespace,
                    pod,
                )
        context["checks"]["pdb"] = "passed"
        return context

    def _kubectl_owner_context(
        self,
        namespace: str,
        pod_document: dict[str, Any],
    ) -> dict[str, Any]:
        reference = _controller_reference(pod_document)
        if reference is None:
            self._refuse(
                "unowned_pod",
                "pod has no controller ownerReference",
                namespace,
                str(pod_document.get("metadata", {}).get("name", "unknown")),
            )
        direct_kind, direct_name = reference
        if direct_kind == "ReplicaSet":
            replica_set = self._kubectl_json(
                ["get", "replicaset", direct_name, "-n", namespace, "-o", "json"]
            )
            workload_reference = _controller_reference(replica_set)
            if workload_reference is None or workload_reference[0] != "Deployment":
                self._refuse(
                    "unowned_pod",
                    "ReplicaSet is not controlled by a Deployment",
                    namespace,
                    str(pod_document.get("metadata", {}).get("name", "unknown")),
                )
            workload_kind, workload_name = workload_reference
        elif direct_kind in {"StatefulSet", "DaemonSet"}:
            workload_kind, workload_name = direct_kind, direct_name
        else:
            self._refuse(
                "unowned_pod",
                "pod is not owned by a ReplicaSet, StatefulSet, or DaemonSet",
                namespace,
                str(pod_document.get("metadata", {}).get("name", "unknown")),
            )
        resource = {
            "Deployment": "deployment",
            "StatefulSet": "statefulset",
            "DaemonSet": "daemonset",
        }[workload_kind]
        workload = self._kubectl_json(
            ["get", resource, workload_name, "-n", namespace, "-o", "json"]
        )
        desired, available, max_unavailable = _workload_availability(
            workload_kind,
            workload,
        )
        return {
            "owner": {"kind": workload_kind, "name": workload_name},
            "direct_owner": {"kind": direct_kind, "name": direct_name},
            "desired": desired,
            "available": available,
            "max_unavailable": max_unavailable,
        }

    def _restart_kubectl(
        self,
        namespace: str,
        pod: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
        started: float,
    ) -> dict[str, Any]:
        checks = dict(context["checks"])
        body = json.dumps(
            {
                "apiVersion": "policy/v1",
                "kind": "Eviction",
                "metadata": {"name": pod, "namespace": namespace},
            },
            separators=(",", ":"),
        )
        action_started = time.monotonic()
        command = [
            "create",
            "--raw",
            f"/api/v1/namespaces/{namespace}/pods/{pod}/eviction",
            "-f",
            "-",
        ]
        if arguments.get("dry_run") is True:
            command.append("--dry-run=server")
        try:
            self._kubectl(command, input_text=body)
            checks["eviction"] = (
                "server_dry_run" if arguments.get("dry_run") is True else "accepted"
            )
        except MCPProtocolError as exc:
            if self.allow_delete_fallback and arguments.get("dry_run") is not True:
                self._kubectl(
                    ["delete", "pod", pod, "-n", namespace, "--wait=false"]
                )
                checks["eviction"] = "delete_fallback"
            else:
                result = self._restart_result(
                    status="failed",
                    namespace=namespace,
                    old_pod=pod,
                    new_pod=None,
                    owner=context["owner"],
                    started=started,
                    checks={**checks, "eviction": "failed"},
                )
                raise GuardedToolError(
                    "restart_failed",
                    "Kubernetes eviction request failed",
                    result,
                    operational_failure=True,
                ) from exc
        action_ms = (time.monotonic() - action_started) * 1000
        if arguments.get("dry_run") is True:
            checks["replacement"] = "not_required"
            return self._restart_result(
                status="verified",
                namespace=namespace,
                old_pod=pod,
                new_pod=None,
                owner=context["owner"],
                started=started,
                checks=checks,
                action_ms=action_ms,
                dry_run=True,
            )
        verification_started = time.monotonic()
        deadline = verification_started + self.verification_timeout
        while time.monotonic() < deadline:
            try:
                replacement = self._ready_replacement(namespace, pod, context)
                workload = self._kubectl_json(
                    [
                        "get",
                        {
                            "Deployment": "deployment",
                            "StatefulSet": "statefulset",
                            "DaemonSet": "daemonset",
                        }[context["owner"]["kind"]],
                        context["owner"]["name"],
                        "-n",
                        namespace,
                        "-o",
                        "json",
                    ]
                )
                _, available, _ = _workload_availability(
                    context["owner"]["kind"], workload
                )
            except MCPProtocolError as exc:
                result = self._restart_result(
                    status="failed",
                    namespace=namespace,
                    old_pod=pod,
                    new_pod=None,
                    owner=context["owner"],
                    started=started,
                    checks={**checks, "replacement": "check_failed"},
                    action_ms=action_ms,
                    verification_ms=(time.monotonic() - verification_started) * 1000,
                )
                raise GuardedToolError(
                    "restart_failed",
                    "Kubernetes replacement verification failed",
                    result,
                    operational_failure=True,
                ) from exc
            if replacement is not None and available >= context["available"]:
                checks["replacement"] = "ready"
                return self._restart_result(
                    status="verified",
                    namespace=namespace,
                    old_pod=pod,
                    new_pod=replacement,
                    owner=context["owner"],
                    started=started,
                    checks=checks,
                    action_ms=action_ms,
                    verification_ms=(time.monotonic() - verification_started) * 1000,
                )
            time.sleep(self.poll_interval)
        result = self._restart_result(
            status="timed_out",
            namespace=namespace,
            old_pod=pod,
            new_pod=None,
            owner=context["owner"],
            started=started,
            checks={**checks, "replacement": "timed_out"},
            action_ms=action_ms,
            verification_ms=(time.monotonic() - verification_started) * 1000,
        )
        raise GuardedToolError(
            "restart_verification_timeout",
            "replacement pod did not become ready before the verification deadline",
            result,
            operational_failure=True,
        )

    def _ready_replacement(
        self,
        namespace: str,
        old_pod: str,
        context: Any,
    ) -> str | None:
        if not isinstance(context, dict):
            return None
        pods = self._kubectl_json(["get", "pods", "-n", namespace, "-o", "json"])
        direct = context.get("direct_owner", {})
        for candidate in pods.get("items", []):
            metadata = candidate.get("metadata", {})
            name = str(metadata.get("name", ""))
            if name == old_pod or metadata.get("deletionTimestamp"):
                continue
            if _controller_reference(candidate) == (
                direct.get("kind"),
                direct.get("name"),
            ) and _pod_ready(candidate):
                return name
        return None

    def _simulated_ready_replacement(
        self,
        namespace: str,
        old_pod: str,
        context: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(context, dict):
            return None
        direct = context.get("direct_owner", {})
        for (candidate_namespace, candidate_name), candidate in self.pods.items():
            owner = candidate.get("owner", {})
            if (
                candidate_namespace == namespace
                and candidate_name != old_pod
                and owner.get("direct_kind", owner.get("kind")) == direct.get("kind")
                and owner.get("direct_name", owner.get("name")) == direct.get("name")
                and candidate.get("ready") is True
                and not candidate.get("terminating")
            ):
                return candidate
        return None

    def _check_availability(
        self,
        context: dict[str, Any],
        *,
        ready: bool,
        allow_downtime: bool,
        namespace: str,
        pod: str,
    ) -> None:
        floor = max(1, context["desired"] - context["max_unavailable"])
        projected = context["available"] - int(ready)
        if projected < floor and not allow_downtime:
            self._refuse(
                "would_cause_downtime",
                "evicting this pod would violate the workload availability floor",
                namespace,
                pod,
            )

    def _validated_target(self, arguments: dict[str, Any]) -> tuple[str, str]:
        return (
            _dns1123_name(arguments["namespace"], "namespace", 63),
            _dns1123_name(arguments["pod"], "pod", 253),
        )

    @staticmethod
    def _restart_result(
        *,
        status: str,
        namespace: str,
        old_pod: str,
        new_pod: Any,
        owner: dict[str, Any],
        started: float,
        checks: dict[str, Any],
        action_ms: float = 0.0,
        verification_ms: float = 0.0,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "namespace": namespace,
            "old_pod": old_pod,
            "new_pod": new_pod,
            "owner": owner,
            "dry_run": dry_run,
            "durations": {
                "action_ms": round(action_ms, 3),
                "verification_ms": round(verification_ms, 3),
                "total_ms": round((time.monotonic() - started) * 1000, 3),
            },
            "checks": checks,
        }

    @staticmethod
    def _stored_result(result: dict[str, Any]) -> dict[str, Any]:
        stored = dict(result)
        status = stored.get("status")
        if status == "timed_out":
            raise GuardedToolError(
                "restart_verification_timeout",
                "replacement pod did not become ready before the verification deadline",
                stored,
                operational_failure=True,
            )
        if status == "failed":
            raise GuardedToolError(
                "restart_failed",
                "Kubernetes pod restart previously failed",
                stored,
                operational_failure=True,
            )
        return stored

    @staticmethod
    def _refuse(
        rule: str,
        message: str,
        namespace: str,
        pod: str,
    ) -> None:
        raise GuardedToolError(
            rule,
            message,
            {
                "status": "refused",
                "namespace": namespace,
                "old_pod": pod,
                "new_pod": None,
                "owner": None,
                "durations": {},
                "checks": {rule: "failed"},
            },
        )

    def _idempotency_record(
        self,
        key: str,
        namespace: str,
        pod: str,
    ) -> dict[str, Any] | None:
        if not key:
            return None
        connection = self._state_connection()
        try:
            row = connection.execute(
                "SELECT namespace, pod, status, context_json, result_json "
                "FROM kubernetes_restart_idempotency WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        if row[0] != namespace or row[1] != pod:
            self._refuse(
                "idempotency_conflict",
                "idempotency_key was already used for a different pod",
                namespace,
                pod,
            )
        return {
            "status": row[2],
            "context": json.loads(row[3]) if row[3] else None,
            "result": json.loads(row[4]) if row[4] else None,
        }

    def _reserve_idempotency(
        self,
        key: str,
        namespace: str,
        pod: str,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        connection = self._state_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT namespace, pod, status, result_json "
                "FROM kubernetes_restart_idempotency WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO kubernetes_restart_idempotency "
                    "(idempotency_key, namespace, pod, status, context_json, result_json, updated_at) "
                    "VALUES (?, ?, ?, 'in_progress', ?, NULL, ?)",
                    (
                        key,
                        namespace,
                        pod,
                        json.dumps(context, sort_keys=True),
                        dt.datetime.now(dt.UTC).isoformat(),
                    ),
                )
                connection.commit()
                return None
            connection.commit()
        finally:
            connection.close()
        if row[0] != namespace or row[1] != pod:
            self._refuse(
                "idempotency_conflict",
                "idempotency_key was already used for a different pod",
                namespace,
                pod,
            )
        if row[2] == "complete" and row[3]:
            return json.loads(row[3])
        self._refuse(
            "idempotency_in_progress",
            "an operation with this idempotency key is still in progress",
            namespace,
            pod,
        )

    def _finish_idempotency(
        self,
        key: str,
        namespace: str,
        pod: str,
        context: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        if not key:
            return
        connection = self._state_connection()
        try:
            connection.execute(
                "INSERT INTO kubernetes_restart_idempotency "
                "(idempotency_key, namespace, pod, status, context_json, result_json, updated_at) "
                "VALUES (?, ?, ?, 'complete', ?, ?, ?) "
                "ON CONFLICT(idempotency_key) DO UPDATE SET "
                "status = 'complete', context_json = excluded.context_json, "
                "result_json = excluded.result_json, updated_at = excluded.updated_at",
                (
                    key,
                    namespace,
                    pod,
                    json.dumps(context, sort_keys=True),
                    json.dumps(result, sort_keys=True),
                    dt.datetime.now(dt.UTC).isoformat(),
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def _state_connection(self) -> sqlite3.Connection:
        ensure_private_directory(self.state_path.parent)
        connection = sqlite3.connect(self.state_path, timeout=5)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS kubernetes_restart_idempotency ("
            "idempotency_key TEXT PRIMARY KEY, namespace TEXT NOT NULL, pod TEXT NOT NULL, "
            "status TEXT NOT NULL, context_json TEXT, result_json TEXT, updated_at TEXT NOT NULL)"
        )
        connection.commit()
        return connection

    def _kubectl(self, args: list[str], *, input_text: str | None = None) -> str:
        command = ["kubectl", "--context", self.context, *args]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=self.subprocess_timeout,
            )
        except FileNotFoundError as exc:
            raise MCPProtocolError("kubectl executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise MCPProtocolError("kubectl command timed out") from exc
        if completed.returncode != 0:
            if completed.returncode == 1 and "notfound" in completed.stderr.lower():
                raise _KubectlNotFoundError("Kubernetes resource was not found")
            raise MCPProtocolError(
                f"kubectl command failed with exit code {completed.returncode}"
            )
        return completed.stdout.strip()

    def _kubectl_json_optional(self, args: list[str]) -> dict[str, Any] | None:
        try:
            return self._kubectl_json(args)
        except _KubectlNotFoundError:
            return None

    def _kubectl_json(self, args: list[str]) -> dict[str, Any]:
        try:
            value = json.loads(self._kubectl(args))
        except json.JSONDecodeError as exc:
            raise MCPProtocolError("kubectl returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise MCPProtocolError("kubectl returned a non-object JSON response")
        return value


DNS1123_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class _KubectlNotFoundError(MCPProtocolError):
    pass


def _dns1123_name(value: Any, label: str, maximum: int) -> str:
    name = str(value) if isinstance(value, str) else ""
    if (
        not name
        or len(name) > maximum
        or any(
            len(segment) > 63 or DNS1123_LABEL_PATTERN.fullmatch(segment) is None
            for segment in name.split(".")
        )
    ):
        raise GuardedToolError(
            "invalid_kubernetes_name",
            f"{label} must be a valid DNS-1123 name",
            {
                "status": "refused",
                "old_pod": None,
                "new_pod": None,
                "owner": None,
                "durations": {},
                "checks": {"input_validation": "failed"},
            },
        )
    return name


def _production_target(namespace: str, arguments: dict[str, Any]) -> bool:
    return (
        namespace in {"prod", "production"}
        or str(arguments.get("environment", "")).lower() in {"prod", "production"}
        or os.getenv("JUDIKT_PRODUCTION", "").lower() in {"1", "true", "yes"}
    )


def _boolean_setting(config: dict[str, Any], name: str, default: bool) -> bool:
    value = config.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"kubernetes.{name} must be a boolean")
    return value


def _positive_setting(config: dict[str, Any], name: str, default: float) -> float:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"kubernetes.{name} must be a positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"kubernetes.{name} must be a positive number")
    return result


def _controller_reference(document: dict[str, Any]) -> tuple[Any, Any] | None:
    references = document.get("metadata", {}).get("ownerReferences", [])
    if not isinstance(references, list):
        return None
    selected = next(
        (
            reference
            for reference in references
            if isinstance(reference, dict) and reference.get("controller") is True
        ),
        None,
    )
    if selected is None:
        return None
    kind = selected.get("kind")
    name = selected.get("name")
    return (kind, name) if isinstance(kind, str) and isinstance(name, str) else None


def _workload_availability(
    kind: str,
    workload: dict[str, Any],
) -> tuple[int, int, int]:
    spec = workload.get("spec", {})
    status = workload.get("status", {})
    if kind == "DaemonSet":
        desired = int(status.get("desiredNumberScheduled", 0))
        available = int(status.get("numberAvailable", 0))
        configured = spec.get("updateStrategy", {}).get("rollingUpdate", {}).get(
            "maxUnavailable", 1
        )
    elif kind == "StatefulSet":
        desired = int(spec.get("replicas", 1))
        available = int(status.get("readyReplicas", 0))
        configured = spec.get("updateStrategy", {}).get("rollingUpdate", {}).get(
            "maxUnavailable", 1
        )
    else:
        desired = int(spec.get("replicas", 1))
        available = int(status.get("availableReplicas", 0))
        configured = spec.get("strategy", {}).get("rollingUpdate", {}).get(
            "maxUnavailable", 1
        )
    if desired < 1 or available < 0:
        raise MCPProtocolError("Kubernetes workload returned invalid replica counts")
    if isinstance(configured, str) and configured.endswith("%"):
        try:
            percentage = float(configured[:-1])
        except ValueError as exc:
            raise MCPProtocolError("Kubernetes workload has invalid maxUnavailable") from exc
        max_unavailable = math.ceil(desired * percentage / 100)
    elif isinstance(configured, int) and not isinstance(configured, bool):
        max_unavailable = configured
    else:
        raise MCPProtocolError("Kubernetes workload has invalid maxUnavailable")
    if max_unavailable < 0:
        raise MCPProtocolError("Kubernetes workload has invalid maxUnavailable")
    return desired, available, max_unavailable


def _pod_ready(pod: dict[str, Any]) -> bool:
    conditions = pod.get("status", {}).get("conditions", [])
    return any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") == "True"
        for condition in conditions
    )


def _selector_matches(selector: Any, labels: Any) -> bool:
    if not isinstance(selector, dict) or not isinstance(labels, dict):
        return False
    match_labels = selector.get("matchLabels", {})
    if not isinstance(match_labels, dict) or any(
        labels.get(key) != value for key, value in match_labels.items()
    ):
        return False
    expressions = selector.get("matchExpressions", [])
    if not isinstance(expressions, list):
        return False
    for expression in expressions:
        if not isinstance(expression, dict):
            return False
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values", [])
        if not isinstance(key, str) or not isinstance(values, list):
            return False
        present = key in labels
        if operator == "In" and (not present or labels[key] not in values):
            return False
        if operator == "NotIn" and present and labels[key] in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
        if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return False
    return True


class IncidentBackend:
    def __init__(self) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if tool == "incident.create":
            incident_id = f"INC-{secrets.token_hex(3).upper()}"
            incident = {
                "id": incident_id,
                "title": arguments["title"],
                "severity": arguments["severity"],
                "timeline": [_timeline("incident created")],
            }
            self.incidents[incident_id] = incident
            return incident
        incident_id = arguments["incident_id"]
        if incident_id not in self.incidents:
            raise MCPProtocolError(f"unknown incident: {incident_id}")
        incident = self.incidents[incident_id]
        if tool == "incident.attach_evidence":
            incident["timeline"].append(_timeline("evidence attached", arguments["evidence"]))
            return incident
        if tool == "incident.timeline":
            return incident
        raise MCPProtocolError(f"unsupported incident tool: {tool}")


def _timeline(event: str, details: Any = None) -> dict[str, Any]:
    item = {"at": dt.datetime.now(dt.UTC).isoformat(), "event": event}
    if details is not None:
        item["details"] = details
    return item


def run_backend(name: str) -> None:
    if name == "platform-ops":
        backend = PlatformOpsBackend()
        serve_stdio("platform-ops-mcp", PLATFORM_TOOLS, backend.call)
        return
    if name == "incident":
        backend = IncidentBackend()
        serve_stdio("incident-mcp", INCIDENT_TOOLS, backend.call)
        return
    if name == "kubernetes":
        backend = KubernetesBackend()
        serve_stdio("kubernetes-mcp", KUBERNETES_TOOLS, backend.call)
        return
    raise SystemExit(f"unknown backend: {name}")
