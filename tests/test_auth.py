from __future__ import annotations

import asyncio
import io
import json
import threading
import time
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from judikt.auth import AuthConfig, AuthError, Authenticator, create_hs256_jwt
from judikt.real_mcp import _AuthMiddleware
from judikt.real_mcp import _warn_for_static_admin
from judikt.request_context import (
    bind_authenticated_subject,
    can_execute_control_plane_tool,
    has_control_plane_role,
    is_control_plane_admin,
    reset_authenticated_subject,
)

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_RS256_DEPS = True
except ImportError:
    HAS_RS256_DEPS = False


class JWKSHandler(BaseHTTPRequestHandler):
    document: dict[str, object] = {}
    request_count = 0

    def do_GET(self) -> None:
        type(self).request_count += 1
        body = json.dumps(type(self).document).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class AuthenticatorTest(unittest.TestCase):
    @unittest.skipUnless(HAS_RS256_DEPS, "optional auth dependencies are not installed")
    def test_rs256_jwks_validates_token_caches_keys_and_rejects_bad_signature(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
        jwk.update({"kid": "unit-test-key", "use": "sig", "alg": "RS256"})
        JWKSHandler.document = {"keys": [jwk]}
        JWKSHandler.request_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), JWKSHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        now = int(time.time())
        claims = {
            "sub": "sre-oncall",
            "iss": "https://issuer.example.test",
            "aud": "judikt",
            "exp": now + 300,
            "scope": "mcp:tools",
        }
        token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "unit-test-key"})
        authenticator = Authenticator(
            AuthConfig(
                jwt_jwks_url=f"http://127.0.0.1:{server.server_port}/jwks.json",
                jwt_issuer="https://issuer.example.test",
                jwt_audience="judikt",
            )
        )

        first = authenticator.authenticate(f"Bearer {token}")
        second = authenticator.authenticate(f"Bearer {token}")

        self.assertEqual(first.subject, "sre-oncall")
        self.assertEqual(second.subject, "sre-oncall")
        self.assertEqual(JWKSHandler.request_count, 1)

        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(claims, attacker_key, algorithm="RS256", headers={"kid": "unit-test-key"})
        with self.assertRaisesRegex(AuthError, "invalid JWT"):
            authenticator.authenticate(f"Bearer {forged}")

    def test_hs256_jwt_validates_issuer_audience_and_group(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {
                "sub": "sre-oncall",
                "iss": "https://issuer.example.test",
                "aud": "judikt",
                "exp": int(time.time()) + 300,
                "groups": ["sre"],
                "scope": "mcp:tools",
            },
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(
                jwt_hs256_secret=secret,
                jwt_issuer="https://issuer.example.test",
                jwt_audience="judikt",
                jwt_required_group="sre",
            )
        )

        result = authenticator.authenticate(f"Bearer {token}")

        self.assertEqual(result.subject, "sre-oncall")
        self.assertEqual(result.claims["aud"], "judikt")

    def test_hs256_jwt_rejects_wrong_group(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {
                "sub": "readonly",
                "exp": int(time.time()) + 300,
                "groups": ["readonly"],
            },
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(jwt_hs256_secret=secret, jwt_required_group="sre", required_scopes=())
        )

        with self.assertRaises(AuthError):
            authenticator.authenticate(f"Bearer {token}")

    def test_static_bearer_still_works(self) -> None:
        authenticator = Authenticator(AuthConfig(bearer_token="local-token"))

        result = authenticator.authenticate("Bearer local-token")

        self.assertEqual(result.subject, "bearer-token")
        self.assertEqual(result.claims["role"], "execute")

    def test_jwt_rejects_missing_required_scope(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {"sub": "sre-oncall", "aud": "judikt", "exp": int(time.time()) + 300},
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(
                jwt_hs256_secret=secret,
                jwt_audience="judikt",
                required_scopes=("mcp:execute",),
            )
        )

        with self.assertRaisesRegex(AuthError, "missing required scopes"):
            authenticator.authenticate(f"Bearer {token}")

    def test_remote_jwt_configuration_requires_audience(self) -> None:
        config = AuthConfig(jwt_hs256_secret="secret", jwt_issuer="https://issuer.example.test")

        with self.assertRaisesRegex(AuthError, "JWT_AUDIENCE"):
            config.validate_for_remote_server()

    def test_remote_jwt_configuration_requires_issuer(self) -> None:
        config = AuthConfig(jwt_hs256_secret="secret", jwt_audience="mcp-resource")

        with self.assertRaisesRegex(AuthError, "JWT_ISSUER"):
            config.validate_for_remote_server()

    def test_remote_jwt_configuration_requires_authorization_server(self) -> None:
        config = AuthConfig(
            jwt_hs256_secret="secret",
            jwt_issuer="https://issuer.example.test",
            jwt_audience="mcp-resource",
        )

        with self.assertRaisesRegex(AuthError, "AUTHORIZATION_SERVER"):
            config.validate_for_remote_server()

    def test_bearer_challenge_advertises_resource_metadata_and_scopes(self) -> None:
        config = AuthConfig(required_scopes=("mcp:tools", "logs:read"))

        challenge = config.bearer_challenge(
            "https://judikt.example.test/.well-known/oauth-protected-resource"
        )

        self.assertEqual(
            challenge,
            'Bearer resource_metadata="https://judikt.example.test/.well-known/oauth-protected-resource", '
            'scope="mcp:tools logs:read"',
        )

    def test_metadata_url_is_derived_from_resource_origin(self) -> None:
        config = AuthConfig(resource_uri="https://judikt.example.test/custom/mcp?tenant=platform")

        self.assertEqual(
            config.protected_resource_metadata_url(),
            "https://judikt.example.test/.well-known/oauth-protected-resource",
        )

    def test_resource_uri_must_be_absolute(self) -> None:
        with self.assertRaisesRegex(AuthError, "absolute HTTP"):
            AuthConfig(resource_uri="https:///mcp").validate_for_remote_server()

    def test_origin_validation_uses_resource_origin_or_explicit_allowlist(self) -> None:
        default_config = AuthConfig(resource_uri="https://judikt.example.test/mcp")
        allowlisted_config = AuthConfig(
            resource_uri="https://judikt.example.test/mcp",
            allowed_origins=("https://console.example.test",),
        )

        self.assertTrue(default_config.origin_allowed("https://judikt.example.test"))
        self.assertFalse(default_config.origin_allowed("https://attacker.example.test"))
        self.assertTrue(allowlisted_config.origin_allowed("https://console.example.test/"))
        self.assertFalse(allowlisted_config.origin_allowed("null"))

    def test_remote_auth_urls_require_https_outside_loopback(self) -> None:
        config = AuthConfig(
            jwt_jwks_url="http://issuer.example.test/jwks.json",
            jwt_issuer="https://issuer.example.test",
            jwt_audience="https://judikt.example.test/mcp",
            resource_uri="https://judikt.example.test/mcp",
            authorization_server="https://issuer.example.test",
        )

        with self.assertRaisesRegex(AuthError, "JWT_JWKS_URL must use HTTPS"):
            config.validate_for_remote_server()

    def test_jwt_requires_expiry(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {"sub": "sre-oncall", "aud": "judikt", "scope": "mcp:tools"},
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(jwt_hs256_secret=secret, jwt_audience="judikt")
        )

        with self.assertRaisesRegex(AuthError, "exp claim"):
            authenticator.authenticate(f"Bearer {token}")

    def test_protected_resource_metadata_advertises_resource_and_authorization_server(self) -> None:
        config = AuthConfig(
            resource_uri="https://judikt.example.test/mcp",
            authorization_server="https://auth.example.test",
        )

        metadata = config.protected_resource_metadata()

        self.assertEqual(metadata["resource"], "https://judikt.example.test/mcp")
        self.assertEqual(metadata["authorization_servers"], ["https://auth.example.test"])
        self.assertEqual(
            metadata["scopes_supported"],
            ["mcp:read", "mcp:execute", "mcp:approve", "mcp:admin"],
        )

    def test_remote_binding_requires_authentication(self) -> None:
        with self.assertRaisesRegex(AuthError, "requires bearer or JWT"):
            AuthConfig().validate_for_remote_server(require_auth=True)

    def test_static_bearer_and_jwt_cannot_be_combined(self) -> None:
        config = AuthConfig(
            bearer_token="lab-token",
            jwt_hs256_secret="jwt-secret",
            jwt_issuer="https://issuer.example.test",
            jwt_audience="mcp-resource",
        )

        with self.assertRaisesRegex(AuthError, "cannot be enabled together"):
            config.validate_for_remote_server()

    def test_control_plane_admin_requires_admin_scope_or_group_for_jwt(self) -> None:
        normal = bind_authenticated_subject(
            "sre-oncall", {"sub": "sre-oncall", "scope": "mcp:tools", "groups": ["sre"]}
        )
        try:
            self.assertFalse(is_control_plane_admin())
        finally:
            reset_authenticated_subject(normal)

        admin = bind_authenticated_subject(
            "platform-admin",
            {"sub": "platform-admin", "scope": "mcp:tools mcp:admin"},
        )
        try:
            self.assertTrue(is_control_plane_admin())
        finally:
            reset_authenticated_subject(admin)

    def test_explicit_roles_deny_unauthenticated_admin_and_map_scopes_and_groups(self) -> None:
        self.assertFalse(is_control_plane_admin())
        self.assertFalse(has_control_plane_role("approve"))
        self.assertTrue(can_execute_control_plane_tool())

        cases = [
            ({"scope": "mcp:execute"}, "execute", True),
            ({"scope": "mcp:execute"}, "admin", False),
            ({"scope": "mcp:admin"}, "admin", True),
            ({"groups": ["mcp-admin"]}, "admin", True),
            ({"cognito:groups": ["mcp-approve"]}, "approve", True),
        ]
        for claims, role, expected in cases:
            with self.subTest(claims=claims, role=role):
                context = bind_authenticated_subject("operator", claims)
                try:
                    self.assertEqual(has_control_plane_role(role), expected)
                finally:
                    reset_authenticated_subject(context)

    def test_static_bearer_admin_is_explicit_and_warned(self) -> None:
        execute = Authenticator(AuthConfig(bearer_token="token")).authenticate("Bearer token")
        admin = Authenticator(
            AuthConfig(bearer_token="token", bearer_role="admin")
        ).authenticate("Bearer token")
        execute_context = bind_authenticated_subject(execute.subject, execute.claims)
        try:
            self.assertFalse(is_control_plane_admin())
        finally:
            reset_authenticated_subject(execute_context)
        admin_context = bind_authenticated_subject(admin.subject, admin.claims)
        try:
            self.assertTrue(is_control_plane_admin())
        finally:
            reset_authenticated_subject(admin_context)

        with redirect_stderr(io.StringIO()) as stderr:
            _warn_for_static_admin(AuthConfig(bearer_token="token", bearer_role="admin"))
        self.assertIn("grants full control-plane access", stderr.getvalue())

    def test_http_middleware_rejects_untrusted_origin(self) -> None:
        middleware = _AuthMiddleware(
            self._unused_asgi_app,
            Authenticator(
                AuthConfig(
                    bearer_token="test-token",
                    resource_uri="https://judikt.example.test/mcp",
                )
            ),
            set(),
        )

        messages = self._run_middleware(
            middleware,
            [(b"origin", b"https://attacker.example.test")],
        )

        self.assertEqual(messages[0]["status"], 403)

    def test_http_middleware_rejects_untrusted_origin_without_authentication(self) -> None:
        middleware = _AuthMiddleware(
            self._unused_asgi_app,
            Authenticator(AuthConfig(resource_uri="http://127.0.0.1:8080/mcp")),
            set(),
        )

        messages = self._run_middleware(
            middleware,
            [(b"origin", b"http://attacker.example.test")],
        )

        self.assertEqual(messages[0]["status"], 403)

    def test_http_middleware_returns_scoped_oauth_challenge(self) -> None:
        middleware = _AuthMiddleware(
            self._unused_asgi_app,
            Authenticator(
                AuthConfig(
                    bearer_token="test-token",
                    resource_uri="https://judikt.example.test/mcp",
                    required_scopes=("mcp:tools",),
                )
            ),
            set(),
        )

        messages = self._run_middleware(middleware, [])
        headers = dict(messages[0]["headers"])

        self.assertEqual(messages[0]["status"], 401)
        self.assertIn(b'resource_metadata="https://judikt.example.test/', headers[b"www-authenticate"])
        self.assertIn(b'scope="mcp:tools"', headers[b"www-authenticate"])

    @staticmethod
    async def _unused_asgi_app(scope: object, receive: object, send: object) -> None:
        raise AssertionError("request should have been rejected by authentication middleware")

    @staticmethod
    def _run_middleware(middleware: _AuthMiddleware, headers: list[tuple[bytes, bytes]]) -> list[dict]:
        messages: list[dict] = []

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict) -> None:
            messages.append(message)

        asyncio.run(
            middleware(
                {"type": "http", "path": "/mcp", "headers": headers},
                receive,
                send,
            )
        )
        return messages


if __name__ == "__main__":
    unittest.main()
