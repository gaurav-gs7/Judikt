from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from .secrets import resolve_configured_secret


class AuditSink(Protocol):
    name: str

    def write(self, event: dict[str, Any]) -> None:
        ...


class NullAuditSink:
    name = "none"

    def write(self, event: dict[str, Any]) -> None:
        return


class JsonlAuditSink:
    name = "jsonl"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()


class S3AuditSink:
    name = "s3"

    def __init__(self, bucket: str, prefix: str = "judikt/audit") -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional AWS path
            raise RuntimeError("S3 audit shipping requires boto3") from exc
        self._client = boto3.client("s3")
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def write(self, event: dict[str, Any]) -> None:
        created_at = str(event["created_at"])
        day = created_at[:10]
        chain_id = str(event.get("chain_id", "legacy"))
        sequence = str(event.get("seq", event.get("correlation_id", "unknown")))
        record_type = str(event.get("record_type", "event"))
        key = f"{self.prefix}/date={day}/chain={chain_id}/{record_type}-{sequence}.json"
        self._client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(event, sort_keys=True, separators=(",", ":")).encode(),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )


class SiemAuditSink:
    name = "siem"

    def __init__(
        self,
        endpoint: str,
        token: str,
        *,
        protocol: str = "json",
        hmac_secret: str = "",
        timeout_seconds: float = 2.0,
    ) -> None:
        self.endpoint = _siem_endpoint(endpoint)
        if not token:
            raise RuntimeError("SIEM audit export requires an operator-owned token")
        normalized_protocol = protocol.strip().lower()
        if normalized_protocol not in {"json", "splunk_hec"}:
            raise RuntimeError("JUDIKT_SIEM_PROTOCOL must be json or splunk_hec")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise RuntimeError("JUDIKT_SIEM_TIMEOUT_SECONDS must be a positive finite number")
        self._token = token
        self.protocol = normalized_protocol
        self._hmac_secret = hmac_secret
        self._timeout_seconds = timeout_seconds

    def write(self, event: dict[str, Any]) -> None:
        body = json.dumps(
            self._payload(event),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        authorization = (
            f"Splunk {self._token}"
            if self.protocol == "splunk_hec"
            else f"Bearer {self._token}"
        )
        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
            "User-Agent": "Judikt/audit-exporter",
            "X-Judikt-Event-SHA256": hashlib.sha256(body).hexdigest(),
            "X-Judikt-Event-ID": (
                f"{event.get('chain_id', 'legacy')}:{event.get('seq', 'unknown')}:"
                f"{event.get('record_type', 'event')}"
            ),
        }
        if self._hmac_secret:
            signature = hmac.new(
                self._hmac_secret.encode(), body, hashlib.sha256
            ).hexdigest()
            headers["X-Judikt-Signature-256"] = f"sha256={signature}"
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                status = int(getattr(response, "status", 200))
                if status < 200 or status >= 300:
                    raise RuntimeError(f"SIEM audit export returned HTTP {status}")
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError(f"SIEM audit export returned HTTP {code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError("SIEM audit export is unavailable") from exc

    def _payload(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.protocol == "splunk_hec":
            return {
                "source": "judikt",
                "sourcetype": "judikt:audit:json",
                "event": event,
                "fields": {
                    "server": str(event.get("server", "unknown")),
                    "tool": str(event.get("tool", "unknown")),
                    "allowed": str(bool(event.get("allowed", False))).lower(),
                    "rule": str(event.get("rule", "unknown")),
                },
            }
        return {
            "schema_version": "judikt.audit.v1",
            "source": "judikt",
            "event": event,
        }


def build_audit_sink(default_jsonl_path: Path) -> AuditSink:
    mode = os.getenv("JUDIKT_AUDIT_SINK", "none").strip().lower()
    if mode in {"", "none", "disabled"}:
        return NullAuditSink()
    if mode == "jsonl":
        path = Path(os.getenv("JUDIKT_AUDIT_JSONL_PATH", str(default_jsonl_path)))
        return JsonlAuditSink(path)
    if mode == "s3":
        bucket = os.getenv("JUDIKT_AUDIT_S3_BUCKET", "")
        if not bucket:
            raise RuntimeError("JUDIKT_AUDIT_S3_BUCKET is required for the S3 audit sink")
        return S3AuditSink(bucket, os.getenv("JUDIKT_AUDIT_S3_PREFIX", "judikt/audit"))
    if mode == "siem":
        endpoint = os.getenv("JUDIKT_SIEM_URL", "").strip()
        if not endpoint:
            raise RuntimeError("JUDIKT_SIEM_URL is required for the SIEM audit sink")
        token = resolve_configured_secret(
            direct_env="JUDIKT_SIEM_TOKEN",
            aws_secret_env="JUDIKT_SIEM_TOKEN_SECRET_ARN",
            vault_path_env="JUDIKT_SIEM_TOKEN_VAULT_PATH",
            json_key_env="JUDIKT_SIEM_TOKEN_SECRET_JSON_KEY",
            required=True,
            description="SIEM audit token",
        )
        hmac_secret = resolve_configured_secret(
            direct_env="JUDIKT_SIEM_HMAC_SECRET",
            aws_secret_env="JUDIKT_SIEM_HMAC_SECRET_ARN",
            vault_path_env="JUDIKT_SIEM_HMAC_SECRET_VAULT_PATH",
            json_key_env="JUDIKT_SIEM_HMAC_SECRET_JSON_KEY",
            description="SIEM audit HMAC secret",
        )
        return SiemAuditSink(
            endpoint,
            token,
            protocol=os.getenv("JUDIKT_SIEM_PROTOCOL", "json"),
            hmac_secret=hmac_secret,
            timeout_seconds=_positive_float_env("JUDIKT_SIEM_TIMEOUT_SECONDS", 2.0),
        )
    raise RuntimeError(f"unsupported audit sink mode: {mode}")


def _siem_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("JUDIKT_SIEM_URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("JUDIKT_SIEM_URL must not contain credentials, query, or fragment")
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    allow_http = os.getenv("JUDIKT_SIEM_ALLOW_INSECURE_HTTP", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if parsed.scheme == "http" and not loopback and not allow_http:
        raise RuntimeError("non-loopback SIEM audit export requires HTTPS")
    return endpoint.rstrip("/")


def _positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive finite number") from exc
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{name} must be a positive finite number")
    return value
