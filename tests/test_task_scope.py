from __future__ import annotations

import unittest

from judikt.task_scope import TaskScopeConfig, TaskScopeStore, parse_tool_list


class TaskScopeConfigTest(unittest.TestCase):
    def test_defaults_and_validation(self) -> None:
        config = TaskScopeConfig.from_policy({}, environment={})
        self.assertEqual((config.mode, config.write_tools, config.can_limit), ("operator", None, False))
        self.assertTrue(TaskScopeConfig.from_policy({"task_scope": {"mode": "agent"}}, environment={}).can_limit)
        for section in ({"mode": "strict"}, {"write_tools": "send_email"}, {"other": 1}, []):
            with self.subTest(section=section), self.assertRaises(ValueError):
                TaskScopeConfig.from_policy({"task_scope": section}, environment={})

    def test_environment_replaces_the_policy_list(self) -> None:
        policy = {"task_scope": {"write_tools": ["send_email"]}}
        self.assertEqual(TaskScopeConfig.from_policy(policy, environment={}).write_tools, {"send_email"})
        override = TaskScopeConfig.from_policy(policy, environment={"JUDIKT_TASK_WRITES": "a, b"})
        self.assertEqual(override.write_tools, {"a", "b"})
        self.assertEqual(parse_tool_list("none"), frozenset())
        self.assertEqual(parse_tool_list(" "), frozenset())


class TaskScopeStoreTest(unittest.TestCase):
    def test_operator_scope_limits_every_actor(self) -> None:
        store = TaskScopeStore(TaskScopeConfig(write_tools=frozenset({"send_email", "cal/create_event"})))
        self.assertTrue(store.permits("a", "mail", "send_email"))
        self.assertTrue(store.permits("a", "cal", "create_event"))
        self.assertFalse(store.permits("a", "other", "create_event"))
        self.assertFalse(store.permits("a", "bank", "send_money"))
        self.assertFalse(store.declare("a", {"write_tools": []})[0])

    def test_no_scope_means_no_limit(self) -> None:
        self.assertTrue(TaskScopeStore(TaskScopeConfig()).permits("a", "bank", "send_money"))
        self.assertTrue(TaskScopeStore(TaskScopeConfig(mode="off", write_tools=frozenset())).permits("a", "b", "c"))

    def test_agent_declares_once_before_the_first_result(self) -> None:
        store = TaskScopeStore(TaskScopeConfig(mode="agent"))
        self.assertTrue(store.permits("a", "bank", "send_money"))
        self.assertTrue(store.declare("a", {"write_tools": ["send_email"]})[0])
        self.assertFalse(store.declare("a", {"write_tools": ["send_money"]})[0])
        store.seal("a")
        self.assertTrue(store.permits("a", "mail", "send_email"))
        self.assertFalse(store.permits("a", "bank", "send_money"))
        ok, message = store.declare("b", {"write_tools": ["x"]})
        self.assertTrue(ok, message)

    def test_an_agent_that_reads_before_declaring_gets_an_empty_scope(self) -> None:
        store = TaskScopeStore(TaskScopeConfig(mode="agent"))
        store.seal("a")
        ok, message = store.declare("a", {"write_tools": ["send_money"]})
        self.assertFalse(ok)
        self.assertIn("sealed", message)
        self.assertFalse(store.permits("a", "bank", "send_money"))

    def test_operator_list_bounds_an_agent_declaration(self) -> None:
        store = TaskScopeStore(TaskScopeConfig(mode="agent", write_tools=frozenset({"send_email"})))
        store.declare("a", {"write_tools": ["send_email", "delete_repo"]})
        self.assertTrue(store.permits("a", "mail", "send_email"))
        self.assertFalse(store.permits("a", "git", "delete_repo"))

    def test_malformed_declarations_are_refused(self) -> None:
        store = TaskScopeStore(TaskScopeConfig(mode="agent"))
        for arguments in ({}, {"write_tools": "send_email"}, {"write_tools": [""]}, {"write_tools": ["x"] * 65}):
            with self.subTest(arguments=arguments):
                self.assertFalse(store.declare("a", arguments)[0])


if __name__ == "__main__":
    unittest.main()
