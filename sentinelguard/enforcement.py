
#import from abc collections.abc and typing for type hinting
#callable is used to indicate that the function parameter should be a callable object (like a function)
from collections.abc import Callable
from typing import Any

#import sentinelguard.core and sentinelguard.models for core functionality and data models
from sentinelguard.core import SentinelGuard
from sentinelguard.models import Action, GuardRequest

#import AuditLogger and AuditEvent from sentinelguard.audit.logger and sentinelguard.audit.models for logging audit events
from sentinelguard.audit.logger import AuditLogger
from sentinelguard.audit.models import AuditEvent

class AccessDeniedError(Exception):
    """Raised when SentinelGuard denies a tool operation."""


class SecureToolExecutor:
    """
    Executes registered tools only after SentinelGuard
    approves the request.
    """

    #define constructor for SecureToolExecutor class. It takes a SentinelGuard instance as a parameter and initializes an empty dictionary to store registered tools.
    #include an optional audit_logger parameter to log audit events. If provided, it will be used to log the execution of tools.
    def __init__(
        self,
        sentinel,
        audit_logger: AuditLogger | None = None
    ):
        self.sentinel = sentinel
        self._tools: dict[str, Callable[..., Any]] = {}
        self.audit_logger = audit_logger

    #function for tool registration. It takes a tool name and a callable function as parameters. It performs validation checks to ensure the tool name is a non-empty string, the function is callable, and the tool name is not already registered. If all checks pass, it adds the tool to the _tools dictionary.
    def register_tool(
        self,
        name: str,
        function: Callable[..., Any]
    ) -> None:
        """Register a tool using a trusted application setup."""

        if not name or not isinstance(name, str):
            raise ValueError("Tool name must be a non-empty string")

        if not callable(function):
            raise TypeError("Registered tool must be callable")

        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered")

        self._tools[name] = function

    #record an audit event for the tool execution. It takes agent ID, tool name, decision, and reason as parameters. If an audit logger is provided, it creates an AuditEvent instance and logs it using the audit logger.
    def _record_audit(
        self,
        agent_id: str,
        tool_name: str,
        decision: str,
        reason: str
    ) -> None:

        if self.audit_logger is None:
            return

        event = AuditEvent(
            agent_id=agent_id,
            role="unknown",
            tool=tool_name,
            decision=decision,
            reason=reason
        )

        self.audit_logger.log(event)

    
    def execute(
        self,
        agent_id: str,
        tool_name: str,
        **kwargs
        ):
        
        # Step 1: Check that the tool is registered.
        if tool_name not in self._tools:
            self._record_audit(
                agent_id,
                tool_name,
                "deny",
                "Tool is not registered"
            )
            raise AccessDeniedError(
                "Tool is not registered"
            )

        # Step 2: Build the security request.
        request = GuardRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=kwargs
        )

        # Step 3: Evaluate the security policy.
        try:
            decision = self.sentinel.evaluate(request)
        except Exception:
            self._record_audit(
                agent_id,
                tool_name,
                "deny",
                "Security evaluation failed"
            )
            raise AccessDeniedError(
                "Security evaluation failed; execution blocked"
            ) from None

        # Step 4: Enforce the security decision.
        if decision.action != Action.Allow:
            self._record_audit(
                agent_id,
                tool_name,
                "deny",
                decision.reason
            )
            raise AccessDeniedError(
                decision.reason
            )

        # Step 5: Record the authorization BEFORE execution.
        self._record_audit(
            agent_id,
            tool_name,
            "allow",
            decision.reason
        )

        # Step 6: Execute the authorized tool.
        tool = self._tools[tool_name]
        return tool(**kwargs)
