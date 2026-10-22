from dataclasses import dataclass, field
from enum import Enum
from typing import Any

#enum = way to define a set of named values, in this case, the possible actions that can be taken by the guard (allow or deny)
class Action(Enum):
    Allow = "allow"
    Deny = "deny"

#dataclass = way to store data in a class without having to write constructor, repr, eq, etc. automatically
#frozen=True = makes the dataclass immutable, meaning that once an instance is created, its attributes cannot be modified
@dataclass(frozen=True)
class GuardRequest:
    agent_id: str
    tool_name: str
    arguments: dict[str, Any] = field(
        default_factory=dict
    )

@dataclass(frozen=True)
class GuardDecision:
    action: Action
    reason: str
    guard_name: str