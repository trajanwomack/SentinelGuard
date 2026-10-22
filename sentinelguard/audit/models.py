#import dataclass, field, datetime, timezone, and uuid4 for creating an immutable data class to represent an audit event with unique ID and timestamp
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

#create a dataclass called AuditEvent to represent an audit event in the system. This class is immutable (frozen=True) and contains fields for agent ID, role, tool, decision, reason, event ID, and timestamp. The event ID is generated using uuid4 to ensure uniqueness, and the timestamp is set to the current UTC time in ISO format.
@dataclass(frozen=True)
class AuditEvent:
    agent_id: str
    role: str
    tool: str
    decision: str
    reason: str

    event_id: str = field(
        default_factory=lambda: str(uuid4())
    )

    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )