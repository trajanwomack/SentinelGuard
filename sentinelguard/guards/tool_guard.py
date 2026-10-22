#import sentinelguard.guards.base as base for the BaseGuard class, which is an abstract base class for all guards. The BaseGuard class defines the interface for other classes that implement guards. All guards must implement the evaluate method, which takes a GuardRequest and returns a GuardDecision.
from sentinelguard.guards.base import BaseGuard

#import the Action, GuardRequest, and GuardDecision classes from sentinelguard.models. The Action class is an enumeration that defines the possible actions that can be taken by the guard (allow or deny). The GuardRequest class is a dataclass that represents a request to be evaluated by the guard. The GuardDecision class is a dataclass that represents the decision made by the guard after evaluating the request.
from sentinelguard.models import(
    Action,
    GuardRequest,
    GuardDecision
)

#tool execution guard is a guard that checks if the tool being executed is in the list of allowed tools. If the tool is not in the list, the guard will deny the request and return a GuardDecision with an action of Deny and a reason for the denial. If the tool is in the list, the guard will allow the request and return a GuardDecision with an action of Allow and a reason for the approval.
class ToolExecutionGuard(BaseGuard):

    #__init_ method takes a list of allowed tools and stores it as a frozenset, which is an immutable set. This allows for efficient membership testing when evaluating requests.
    def __init__(self, allowed_tools: list[str]):
        self.allowed_tools = frozenset(allowed_tools)

    #evaluate method takes a GuardRequest and returns a GuardDecision. It checks if the tool being executed is in the list of allowed tools. If the tool is not in the list, it returns a GuardDecision with an action of Deny and a reason for the denial. If the tool is in the list, it returns a GuardDecision with an action of Allow and a reason for the approval.
    def evaluate(
            self,
            request: GuardRequest
    ) -> GuardDecision:
        if request.tool_name not in self.allowed_tools:
            return GuardDecision(
                action=Action.Deny,
                reason=f"Tool '{ request.tool_name}' is not authorized for execution.",
                guard_name="ToolExecutionGuard"
            )

        return GuardDecision(
            action=Action.Allow,
            reason="Tool is authorized for execution.",
            guard_name="ToolExecutionGuard"
        )