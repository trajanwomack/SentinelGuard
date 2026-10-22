
import json
from dataclasses import asdict
from pathlib import Path

#import AuditEvent from sentinelguard.audit.models to represent an audit event in the system. This class is immutable (frozen=True) and contains fields for agent ID, role, tool, decision, reason, event ID, and timestamp. The event ID is generated using uuid4 to ensure uniqueness, and the timestamp is set to the current UTC time in ISO format.
from sentinelguard.audit.models import AuditEvent


#class AuditLogger is responsible for persisting SentinelGuard audit events as JSON Lines. It provides methods to log a single audit event and read all previously recorded audit events from the log file.
class AuditLogger:
    """Persist SentinelGuard audit events as JSON Lines."""

    def __init__(self, log_path="reports/audit.jsonl"):
        self.log_path = Path(log_path)

        # Create the reports directory if necessary.
        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def log(self, event: AuditEvent) -> None:
        """Append a single audit event to the log file."""

        record = asdict(event)

        with self.log_path.open(
            mode="a",
            encoding="utf-8"
        ) as file:
            file.write(
                json.dumps(record) + "\n"
            )

    def read_events(self) -> list[dict]:
        """Read all previously recorded audit events."""

        if not self.log_path.exists():
            return []

        events = []

        with self.log_path.open(
            mode="r",
            encoding="utf-8"
        ) as file:
            for line in file:
                if line.strip():
                    events.append(json.loads(line))

        return events
