
from sentinelguard.core import SentinelGuard
from sentinelguard.enforcement import (
    SecureToolExecutor,
    AccessDeniedError
)
from sentinelguard.guards.access_control import AccessControlGuard


# Simulated company database
reports = {
    "Q3": "Confidential financial report"
}


# Define actual executable functions
def read_reports():
    return reports.copy()


def delete_reports():
    reports.clear()
    return "All reports deleted"


# Configure role-based permissions
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


# Initialize SentinelGuard
sentinel = SentinelGuard()

sentinel.register_guard(
    AccessControlGuard(
        policies=policies,
        agent_roles=agent_roles,
        tool_actions=tool_actions
    )
)


# Initialize secure executor
executor = SecureToolExecutor(sentinel)

# Register actual tools
executor.register_tool("read_reports", read_reports)
executor.register_tool("delete_reports", delete_reports)


# Test 1: Authorized read
print("TEST 1: Analyst reads reports")

result = executor.execute(
    agent_id="research_agent",
    tool_name="read_reports"
)

print(result)


# Test 2: Unauthorized deletion
print("\nTEST 2: Analyst attempts deletion")

try:
    executor.execute(
        agent_id="research_agent",
        tool_name="delete_reports"
    )
except AccessDeniedError as error:
    print("BLOCKED:", error)


# Verify reports still exist
print("\nReports remaining:", reports)
