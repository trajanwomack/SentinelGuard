#import senelguard base guard from sentinelguard.guards.base. The BaseGuard class is an abstract base class that defines the interface for all guards. All guards must implement the evaluate method, which takes a GuardRequest and returns a GuardDecision.
from sentinelguard.guards.base import BaseGuard

#import the Action, GuardRequest, and GuardDecision classes from sentinelguard.models. The Action class is an enumeration that defines the possible actions that can be taken by the guard (allow or deny). The GuardRequest class is a dataclass that represents a request to be evaluated by the guard. The GuardDecision class is a dataclass that represents the decision made by the guard after evaluating the request.
from sentinelguard.models import Action, GuardRequest, GuardDecision


#define access control guard class that inherits from BaseGuard. This guard enforces role-based access control (RBAC) for AI agents. It takes policies, agent roles, and tool actions as input and evaluates requests based on these parameters.
class AccessControlGuard(BaseGuard):
    """
    Enforces role-based access control (RBAC)
    for AI agents.
    """

    #define the constructor for the AccessControlGuard class. It takes three parameters: policies, agent_roles, and tool_actions. These parameters are stored as instance variables for later use in the evaluate method.
    def __init__(
        self,
        policies: dict,
        agent_roles: dict,
        tool_actions: dict
    ):
        self.policies = policies
        self.agent_roles = agent_roles
        self.tool_actions = tool_actions

    #define the evaluate method for the AccessControlGuard class. This method takes a GuardRequest as input and returns a GuardDecision. It implements the logic for evaluating whether the request is authorized based on the policies, agent roles, and tool actions provided during initialization.
    def evaluate(self, request: GuardRequest) -> GuardDecision:

        # Step 1: Identify the agent's trusted role
        role = self.agent_roles.get(request.agent_id)

        if role is None:
            return self._deny("Agent has no assigned role")

        # Step 2: Identify the resource and operation
        tool_action = self.tool_actions.get(request.tool_name)

        if tool_action is None:
            return self._deny("Tool has no access control mapping")

        resource, operation = tool_action

        # Step 3: Retrieve permissions for this role
        role_policies = self.policies.get(role, {})
        allowed_actions = role_policies.get(resource, [])

        # Step 4: Check authorization
        if operation not in allowed_actions:
            return self._deny(
                f"Role '{role}' cannot perform "
                f"'{operation}' on '{resource}'"
            )

        return GuardDecision(
            action=Action.Allow,
            reason="Access authorized by policy",
            guard_name="AccessControlGuard"
        )

    def _deny(self, reason: str) -> GuardDecision:
        return GuardDecision(
            action=Action.Deny,
            reason=reason,
            guard_name="AccessControlGuard"
        )
