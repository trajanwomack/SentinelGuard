
from sentinelguard.audit.logger import AuditLogger
from sentinelguard.audit.models import AuditEvent


def main():
    logger = AuditLogger()

    event = AuditEvent(
        agent_id="agent_001",
        role="analyst",
        tool="delete_database",
        decision="deny",
        reason="Insufficient permissions"
    )

    # Persist the event.
    logger.log(event)

    print("Audit event successfully recorded!")
    print(f"Event ID: {event.event_id}")

    # Read the saved events.
    events = logger.read_events()

    print(f"Total recorded events: {len(events)}")

    for saved_event in events:
        print(saved_event)


if __name__ == "__main__":
    main()
