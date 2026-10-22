
import unittest

from sentinelguard.guards.access_control import AccessControlGuard
from sentinelguard.models import Action, GuardRequest


class TestAccessControlGuard(unittest.TestCase):

    def setUp(self):
        self.guard = AccessControlGuard(
            policies={
                "admin": {
                    "reports": ["read", "write", "delete"]
                },
                "analyst": {
                    "reports": ["read"]
                }
            },
            agent_roles={
                "research_agent": "analyst",
                "admin_agent": "admin"
            },
            tool_actions={
                "read_reports": ("reports", "read"),
                "delete_reports": ("reports", "delete")
            }
        )

    def test_analyst_can_read(self):
        request = GuardRequest(
            agent_id="research_agent",
            tool_name="read_reports"
        )
        decision = self.guard.evaluate(request)
        self.assertEqual(decision.action, Action.Allow)

    def test_analyst_cannot_delete(self):
        request = GuardRequest(
            agent_id="research_agent",
            tool_name="delete_reports"
        )
        decision = self.guard.evaluate(request)
        self.assertEqual(decision.action, Action.Deny)

    def test_admin_can_delete(self):
        request = GuardRequest(
            agent_id="admin_agent",
            tool_name="delete_reports"
        )
        decision = self.guard.evaluate(request)
        self.assertEqual(decision.action, Action.Allow)

    def test_unknown_agent_denied(self):
        request = GuardRequest(
            agent_id="unknown_agent",
            tool_name="read_reports"
        )
        decision = self.guard.evaluate(request)
        self.assertEqual(decision.action, Action.Deny)

    def test_unmapped_tool_denied(self):
        request = GuardRequest(
            agent_id="research_agent",
            tool_name="unknown_tool"
        )
        decision = self.guard.evaluate(request)
        self.assertEqual(decision.action, Action.Deny)


if __name__ == "__main__":
    unittest.main()
