
import unittest
from unittest.mock import Mock

from sentinelguard.core import SentinelGuard
from sentinelguard.enforcement import (
    SecureToolExecutor,
    AccessDeniedError
)
from sentinelguard.guards.access_control import AccessControlGuard


class TestSecureToolExecutor(unittest.TestCase):

    def setUp(self):
        """Create an isolated environment before each test."""

        policies = {
            "admin": {
                "reports": ["read", "delete"]
            },
            "analyst": {
                "reports": ["read"]
            }
        }

        agent_roles = {
            "research_agent": "analyst",
            "admin_agent": "admin"
        }

        tool_actions = {
            "read_reports": ("reports", "read"),
            "delete_reports": ("reports", "delete")
        }

        sentinel = SentinelGuard()

        sentinel.register_guard(
            AccessControlGuard(
                policies=policies,
                agent_roles=agent_roles,
                tool_actions=tool_actions
            )
        )

        self.executor = SecureToolExecutor(sentinel)

        # Mock functions track whether they were executed
        self.read_tool = Mock(return_value="Report contents")
        self.delete_tool = Mock(return_value="Reports deleted")

        self.executor.register_tool(
            "read_reports",
            self.read_tool
        )

        self.executor.register_tool(
            "delete_reports",
            self.delete_tool
        )

    def test_authorized_read_executes(self):
        result = self.executor.execute(
            agent_id="research_agent",
            tool_name="read_reports"
        )

        self.assertEqual(result, "Report contents")
        self.read_tool.assert_called_once_with()

    def test_unauthorized_delete_never_executes(self):
        with self.assertRaises(AccessDeniedError):
            self.executor.execute(
                agent_id="research_agent",
                tool_name="delete_reports"
            )

        # Critical security assertion
        self.delete_tool.assert_not_called()

    def test_admin_delete_executes(self):
        result = self.executor.execute(
            agent_id="admin_agent",
            tool_name="delete_reports"
        )

        self.assertEqual(result, "Reports deleted")
        self.delete_tool.assert_called_once_with()

    def test_unknown_tool_blocked(self):
        with self.assertRaises(AccessDeniedError):
            self.executor.execute(
                agent_id="admin_agent",
                tool_name="unknown_tool"
            )

        self.read_tool.assert_not_called()
        self.delete_tool.assert_not_called()

    def test_duplicate_registration_rejected(self):
        with self.assertRaises(ValueError):
            self.executor.register_tool(
                "read_reports",
                Mock()
            )

        self.read_tool.assert_not_called()

    def test_security_failure_blocks_execution(self):
        # Simulate a SentinelGuard evaluation failure
        self.executor.sentinel.evaluate = Mock(
            side_effect=RuntimeError("Policy engine unavailable")
        )

        with self.assertRaises(AccessDeniedError):
            self.executor.execute(
                agent_id="research_agent",
                tool_name="read_reports"
            )

        self.read_tool.assert_not_called()


if __name__ == "__main__":
    unittest.main()
