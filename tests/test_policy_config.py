from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from judikt.paths import DEFAULT_POLICY_PATH, DEMO_POLICY_PATH
from judikt.policy import PolicyConfigurationError, PolicyEngine, load_policy_config


class PolicyConfigurationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.valid = json.loads(DEFAULT_POLICY_PATH.read_text())

    def _write(self, document: object, name: str = "policy.json") -> Path:
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document))
        return path

    def test_bundled_policies_are_valid(self) -> None:
        for path in (DEFAULT_POLICY_PATH, DEMO_POLICY_PATH):
            with self.subTest(policy=path.name):
                self.assertIsInstance(load_policy_config(path), dict)

    def test_unreadable_or_malformed_files_name_the_file(self) -> None:
        with self.assertRaisesRegex(PolicyConfigurationError, "policy file not found"):
            load_policy_config(self.root / "absent.json")
        with self.assertRaisesRegex(PolicyConfigurationError, r"not valid JSON: .* line 1"):
            load_policy_config(self._write('{"broken": '))
        with self.assertRaisesRegex(PolicyConfigurationError, "must be a JSON object"):
            load_policy_config(self._write([1, 2]))

    def test_shape_errors_name_the_offending_key(self) -> None:
        def variant(**changes: object) -> dict[str, object]:
            document = dict(self.valid)
            for key, value in changes.items():
                if value is None:
                    document.pop(key, None)
                else:
                    document[key] = value
            return document

        cases = [
            (variant(blocked_argument_patterns=None), "'blocked_argument_patterns' is required"),
            (variant(redacted_key_patterns="token"), "'redacted_key_patterns' must be a list of strings"),
            (variant(blocked_argument_patterns=["(unclosed"]), r"'blocked_argument_patterns\[0\]' is not a valid regular expression"),
            (variant(allowed_tools=None), "'allowed_tools' is required"),
            (variant(allowed_tools={"server": "read_file"}), "'allowed_tools.server' must be a list"),
            (variant(actor_permissions={"operator": "*"}), "'actor_permissions.operator' must be a list"),
            (variant(rate_limits_per_minute={"read_file": 5}), "must contain a 'default' limit"),
            (variant(rate_limits_per_minute={"default": -1}), "'rate_limits_per_minute.default' must be a non-negative integer"),
            (variant(rate_limits_per_minute={"default": True}), "must be a non-negative integer"),
            (variant(global_rate_limit_per_minute="many"), "'global_rate_limit_per_minute' must be"),
            (variant(approval_required="delete_repo"), "'approval_required' must be a list of strings"),
            (variant(local_stdio_identity=7), "'local_stdio_identity' must be a string"),
            (variant(allow_demo_boolean_approval="yes"), "must be true or false"),
        ]
        for document, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(PolicyConfigurationError, message):
                    load_policy_config(self._write(document))

    def test_policy_engine_rejects_invalid_policy_before_starting(self) -> None:
        with self.assertRaisesRegex(PolicyConfigurationError, "'blocked_argument_patterns' is required"):
            PolicyEngine(self._write({"allowed_tools": {}}))


if __name__ == "__main__":
    unittest.main()
