
from sentinelguard.core import SentinelGuard
from sentinelguard.guards.access_control import AccessControlGuard
from sentinelguard.models import GuardRequest


# Define permissions for each role
policies = {
    "admin": {
        "reports": ["read", "write", "delete"]
    },
    "analyst": {
        "reports": ["read"]
    }
}

# Assigned by trusted application configuration
agent_roles = {
    "research_agent": "analyst",
    "admin_agent": "admin"
}

# Map tools to the resource and operation
tool_actions = {
    "read_reports": ("reports", "read"),
    "delete_reports": ("reports", "delete")
}


# Initialize SentinelGuard
sentinel = SentinelGuard()

# Register our new guard
sentinel.register_guard(
    AccessControlGuard(
        policies=policies,
        agent_roles=agent_roles,
        tool_actions=tool_actions
    )
)


# Test an authorized action
request1 = GuardRequest(
    agent_id="research_agent",
    tool_name="read_reports"
)

# Test an unauthorized action
request2 = GuardRequest(
    agent_id="research_agent",
    tool_name="delete_reports"
)

# Evaluate requests
print(sentinel.evaluate(request1))
print(sentinel.evaluate(request2))
