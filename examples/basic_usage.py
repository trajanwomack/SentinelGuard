
from sentinelguard.core import SentinelGuard
from sentinelguard.guards.tool_guard import ToolExecutionGuard
from sentinelguard.models import GuardRequest
from sentinelguard.audit.logger import AuditLogger

# 1. Create our security engine

from sentinelguard.core import SentinelGuard
from sentinelguard.guards.tool_guard import ToolExecutionGuard

from sentinelguard.enforcement import (
    SecureToolExecutor,
    AccessDeniedError
)

from sentinelguard.audit.logger import AuditLogger


# 1. Create the SentinelGuard engine
engine = SentinelGuard()


# 2. Create an authorization guard
tool_guard = ToolExecutionGuard(
    allowed_tools=["read_file", "search_logs"]
)


# 3. Register the guard
engine.register_guard(tool_guard)


# 4. Initialize the audit logger
audit_logger = AuditLogger(
    log_path="reports/audit.jsonl"
)


# 5. Initialize the secure executor
executor = SecureToolExecutor(
    sentinel=engine,
    audit_logger=audit_logger
)


# 6. Define example tools
def read_file(path: str):
    print(f"Reading file: {path}")
    return "Example security log contents"


def delete_file(path: str):
    print(f"Deleting file: {path}")
    return "File deleted"


# 7. Register trusted tools
executor.register_tool("read_file", read_file)
executor.register_tool("delete_file", delete_file)


# 8. Execute an authorized operation
print("\n=== TEST 1: AUTHORIZED OPERATION ===")

try:
    result = executor.execute(
        agent_id="analyst_agent",
        tool_name="read_file",
        path="/data/security.log"
    )

    print("Execution successful:", result)

except AccessDeniedError as error:
    print("Execution denied:", error)


# 9. Attempt an unauthorized operation
print("\n=== TEST 2: UNAUTHORIZED OPERATION ===")

try:
    result = executor.execute(
        agent_id="analyst_agent",
        tool_name="delete_file",
        path="/data/security.log"
    )

    print("Execution successful:", result)

except AccessDeniedError as error:
    print("Execution denied:", error)


# 10. Display audit records
print("\n=== SENTINELGUARD AUDIT SUMMARY ===")

events = audit_logger.read_events()

for event in events:
    print(
        f"\nEvent ID: {event['event_id']}"
        f"\nAgent: {event['agent_id']}"
        f"\nTool: {event['tool']}"
        f"\nDecision: {event['decision'].upper()}"
        f"\nReason: {event['reason']}"
        f"\nTimestamp: {event['timestamp']}"
    )

print(f"\nTotal stored audit events: {len(events)}")
