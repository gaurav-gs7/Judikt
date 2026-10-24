from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.upstreams import (
    UpstreamConfigError,
    _optional_number,
    _parse_timeouts,
    load_upstream_servers,
    resolve_operator_environment,
    resolve_operator_headers,
    validate_remote_url,
)


class OptionalNumberTest(unittest.TestCase):
    def test_absent_key_returns_none(self) -> None:
        self.assertIsNone(_optional_number("s", {}, "timeout", allow_zero=False))

    def test_boolean_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "positive number"):
            _optional_number("s", {"timeout": True}, "timeout", allow_zero=False)

    def test_non_numeric_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "positive number"):
            _optional_number("s", {"timeout": "5"}, "timeout", allow_zero=False)

    def test_negative_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "positive number"):
            _optional_number("s", {"timeout": -1}, "timeout", allow_zero=False)

    def test_zero_is_rejected_unless_allowed(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "positive number"):
            _optional_number("s", {"ttl": 0}, "ttl", allow_zero=False)
        self.assertEqual(_optional_number("s", {"ttl": 0}, "ttl", allow_zero=True), 0.0)

    def test_valid_number_is_returned_as_float(self) -> None:
        self.assertEqual(_optional_number("s", {"t": 5}, "t", allow_zero=False), 5.0)


class ParseTimeoutsTest(unittest.TestCase):
    def test_non_dict_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "must be an object"):
            _parse_timeouts("s", ["not", "a", "dict"])

    def test_unknown_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "unknown timeout keys"):
            _parse_timeouts("s", {"bogus": 5})

    def test_non_positive_value_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "must be a positive number"):
            _parse_timeouts("s", {"call": 0})

    def test_valid_timeouts_are_returned_as_floats(self) -> None:
        result = _parse_timeouts("s", {"initialize": 5, "list": 10, "call": 15})
        self.assertEqual(result, {"initialize": 5.0, "list": 10.0, "call": 15.0})


class ResolveOperatorEnvironmentTest(unittest.TestCase):
    def test_non_dict_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "env must be an object"):
            resolve_operator_environment("s", ["not", "a", "dict"])

    def test_invalid_target_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "invalid environment variable name"):
            resolve_operator_environment("s", {"": "value"})

    def test_plain_string_value_is_passed_through_when_not_sensitive(self) -> None:
        resolved = resolve_operator_environment("s", {"SERVICE_NAME": "payments-api"})
        self.assertEqual(resolved, {"SERVICE_NAME": "payments-api"})

    def test_non_string_non_dict_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "string or source object"):
            resolve_operator_environment("s", {"PORT": 8080})

    def test_source_with_no_recognised_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "exactly one supported source"):
            resolve_operator_environment("s", {"TOKEN": {}})

    def test_source_with_multiple_keys_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "exactly one supported source"):
            resolve_operator_environment(
                "s", {"TOKEN": {"from_env": "A", "from_vault": "secret/a"}}
            )

    def test_source_with_unknown_extra_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "exactly one supported source"):
            resolve_operator_environment("s", {"TOKEN": {"from_env": "A", "bogus": 1}})

    def test_non_string_source_value_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "must be a non-empty string"):
            resolve_operator_environment("s", {"TOKEN": {"from_env": 5}})

    def test_non_string_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "json_key.*must be a string"):
            resolve_operator_environment(
                "s", {"TOKEN": {"from_env": "A", "json_key": 5}}
            )

    def test_from_env_with_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "cannot use json_key"):
            resolve_operator_environment(
                "s", {"TOKEN": {"from_env": "A", "json_key": "k"}}
            )

    def test_from_env_missing_variable_is_rejected(self) -> None:
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("JUDIKT_TEST_MISSING_VAR_XYZ", None)
            with self.assertRaisesRegex(UpstreamConfigError, "missing operator environment"):
                resolve_operator_environment(
                    "s", {"TOKEN": {"from_env": "JUDIKT_TEST_MISSING_VAR_XYZ"}}
                )

    def test_from_env_resolves_from_the_operator_environment(self) -> None:
        with patch.dict("os.environ", {"JUDIKT_TEST_VAR_XYZ": "shh"}, clear=False):
            resolved = resolve_operator_environment(
                "s", {"TOKEN": {"from_env": "JUDIKT_TEST_VAR_XYZ"}}
            )
        self.assertEqual(resolved, {"TOKEN": "shh"})


class ResolveOperatorHeadersTest(unittest.TestCase):
    def test_non_dict_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "headers must be an object"):
            resolve_operator_headers("s", ["not", "a", "dict"])

    def test_invalid_header_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "invalid HTTP header name"):
            resolve_operator_headers("s", {"bad header": {"from_env": "A"}})

    def test_forbidden_transport_header_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "transport header"):
            resolve_operator_headers("s", {"Host": {"from_env": "A"}})

    def test_non_dict_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "from_env or from_aws_secret"):
            resolve_operator_headers("s", {"X-Api-Key": "plain-value"})

    def test_newline_in_resolved_header_value_is_rejected(self) -> None:
        with patch.dict("os.environ", {"JUDIKT_TEST_HEADER_XYZ": "a\nb"}, clear=False):
            with self.assertRaisesRegex(UpstreamConfigError, "contains a newline"):
                resolve_operator_headers(
                    "s", {"X-Api-Key": {"from_env": "JUDIKT_TEST_HEADER_XYZ"}}
                )

    def test_header_resolves_from_the_operator_environment(self) -> None:
        with patch.dict("os.environ", {"JUDIKT_TEST_HEADER_OK": "token-value"}, clear=False):
            resolved = resolve_operator_headers(
                "s", {"X-Api-Key": {"from_env": "JUDIKT_TEST_HEADER_OK"}}
            )
        self.assertEqual(resolved, {"X-Api-Key": "token-value"})


class ValidateRemoteUrlTest(unittest.TestCase):
    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "invalid port"):
            validate_remote_url("https://example.com:999999", False, resolve_dns=False)

    def test_non_http_scheme_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "absolute HTTP"):
            validate_remote_url("ftp://example.com", False, resolve_dns=False)

    def test_missing_hostname_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "absolute HTTP"):
            validate_remote_url("https://", False, resolve_dns=False)

    def test_credentials_in_url_are_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "credentials or a fragment"):
            validate_remote_url("https://user:pass@example.com", False, resolve_dns=False)

    def test_fragment_in_url_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "credentials or a fragment"):
            validate_remote_url("https://example.com#frag", False, resolve_dns=False)

    def test_non_https_non_localhost_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "requires HTTPS"):
            validate_remote_url("http://example.com", False, resolve_dns=False)

    def test_plain_http_localhost_is_allowed(self) -> None:
        # The HTTPS requirement is waived for localhost, but the loopback
        # address is still disallowed unless private networks are allowed.
        validate_remote_url("http://127.0.0.1:8080", True, resolve_dns=False)

    def test_allow_private_network_bypasses_address_checks(self) -> None:
        validate_remote_url("https://10.0.0.5", True, resolve_dns=False)

    def test_private_literal_address_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "disallowed address"):
            validate_remote_url("https://10.0.0.5", False, resolve_dns=False)

    def test_cloud_metadata_address_is_rejected(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "disallowed address"):
            validate_remote_url("https://169.254.169.254", False, resolve_dns=False)

    def test_dns_resolution_failure_is_rejected(self) -> None:
        with patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror("name or service not known"),
        ):
            with self.assertRaisesRegex(UpstreamConfigError, "could not be resolved"):
                validate_remote_url("https://example.invalid", False, resolve_dns=True)

    def test_dns_resolution_to_a_public_address_is_allowed(self) -> None:
        with patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
        ):
            validate_remote_url("https://example.com", False, resolve_dns=True)

    def test_dns_resolution_to_a_private_address_is_rejected(self) -> None:
        with patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 443))],
        ):
            with self.assertRaisesRegex(UpstreamConfigError, "disallowed address"):
                validate_remote_url("https://internal.example.com", False, resolve_dns=True)


class LoadUpstreamServersTest(unittest.TestCase):
    def _write(self, directory: str, document: dict[str, object]) -> Path:
        path = Path(directory) / "upstreams.json"
        path.write_text(json.dumps(document))
        return path

    def test_no_path_or_env_returns_empty_list(self) -> None:
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("JUDIKT_UPSTREAM_CONFIG", None)
            self.assertEqual(load_upstream_servers(None), [])

    def test_unreadable_file_is_a_config_error(self) -> None:
        with self.assertRaisesRegex(UpstreamConfigError, "cannot load upstream"):
            load_upstream_servers("/nonexistent/path/upstreams.json")

    def test_missing_servers_object_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"not_servers": {}})
            with self.assertRaisesRegex(UpstreamConfigError, "must contain a 'servers'"):
                load_upstream_servers(path)

    def test_non_object_server_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"servers": {"a": "not-an-object"}})
            with self.assertRaisesRegex(UpstreamConfigError, "non-empty name and object"):
                load_upstream_servers(path)

    def test_requiring_both_command_and_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {"servers": {"a": {"command": ["x"], "url": "https://example.com"}}},
            )
            with self.assertRaisesRegex(UpstreamConfigError, "exactly one of command or url"):
                load_upstream_servers(path)

    def test_neither_command_nor_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"servers": {"a": {}}})
            with self.assertRaisesRegex(UpstreamConfigError, "exactly one of command or url"):
                load_upstream_servers(path)

    def test_empty_command_array_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"servers": {"a": {"command": []}}})
            with self.assertRaisesRegex(UpstreamConfigError, "non-empty string array"):
                load_upstream_servers(path)

    def test_blank_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"servers": {"a": {"url": "   "}}})
            with self.assertRaisesRegex(UpstreamConfigError, "non-empty string"):
                load_upstream_servers(path)

    def test_headers_with_command_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory, {"servers": {"a": {"command": ["x"], "headers": {}}}}
            )
            with self.assertRaisesRegex(UpstreamConfigError, "require url"):
                load_upstream_servers(path)

    def test_env_with_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {"servers": {"a": {"url": "https://example.com", "env": {}}}},
            )
            with self.assertRaisesRegex(UpstreamConfigError, "only valid with command"):
                load_upstream_servers(path)

    def test_cwd_with_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {
                    "servers": {
                        "a": {
                            "url": "https://example.com",
                            "allow_private_network": True,
                            "cwd": "/tmp",
                        }
                    }
                },
            )
            with self.assertRaisesRegex(UpstreamConfigError, "only valid with command"):
                load_upstream_servers(path)

    def test_non_string_cwd_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory, {"servers": {"a": {"command": ["x"], "cwd": 5}}}
            )
            with self.assertRaisesRegex(UpstreamConfigError, "cwd must be a string"):
                load_upstream_servers(path)

    def test_invalid_tool_name_prefix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {"servers": {"a": {"command": ["x"], "tool_name_prefix": "bad prefix!"}}},
            )
            with self.assertRaisesRegex(UpstreamConfigError, "tool_name_prefix"):
                load_upstream_servers(path)

    def test_non_boolean_allow_private_network_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {
                    "servers": {
                        "a": {"url": "https://example.com", "allow_private_network": "yes"}
                    }
                },
            )
            with self.assertRaisesRegex(UpstreamConfigError, "must be a boolean"):
                load_upstream_servers(path)

    def test_non_boolean_expose_error_messages_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {"servers": {"a": {"command": ["x"], "expose_error_messages": "yes"}}},
            )
            with self.assertRaisesRegex(UpstreamConfigError, "must be a boolean"):
                load_upstream_servers(path)

    def test_valid_stdio_server_is_loaded_with_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory, {"servers": {"a": {"command": ["server", "--flag"]}}}
            )
            servers = load_upstream_servers(path)

        self.assertEqual(len(servers), 1)
        server = servers[0]
        self.assertEqual(server.name, "a")
        self.assertEqual(server.command, ("server", "--flag"))
        self.assertEqual(server.url, "")
        self.assertEqual(server.environment, {})
        self.assertFalse(server.allow_private_network)

    def test_valid_remote_server_is_loaded_with_headers_and_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {
                    "servers": {
                        "a": {
                            "url": "https://example.com/mcp",
                            "allow_private_network": True,
                            "catalog_ttl_seconds": 30,
                        }
                    }
                },
            )
            servers = load_upstream_servers(path)

        self.assertEqual(len(servers), 1)
        server = servers[0]
        self.assertEqual(server.url, "https://example.com/mcp")
        self.assertEqual(server.command, ())
        self.assertTrue(server.allow_private_network)
        self.assertEqual(server.catalog_ttl_seconds, 30.0)


if __name__ == "__main__":
    unittest.main()
