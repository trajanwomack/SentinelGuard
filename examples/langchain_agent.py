
import os
from pathlib import Path

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI

from sentinelguard.core import SentinelGuard
from sentinelguard.guards.tool_guard import ToolExecutionGuard
from sentinelguard.enforcement import (
    SecureToolExecutor,
    AccessDeniedError,
)
from sentinelguard.audit.logger import AuditLogger



# 1. SENTINELGUARD SECURITY CONFIGURATION


engine = SentinelGuard()




engine.register_guard(
    ToolExecutionGuard(
        allowed_tools=["read_file", "delete_file"]
    )
)



# 2. AUDIT LOGGING


audit_logger = AuditLogger(
    "reports/langchain_audit.jsonl"
)

executor = SecureToolExecutor(
    sentinel=engine,
    audit_logger=audit_logger
)



# 3. FILESYSTEM CONFIGURATION


# The agent's tools operate within Windows Documents.
ALLOWED_DIRECTORY = (
    Path.home() / "Documents"
).resolve()


def resolve_file_path(path: str) -> Path:
    """
    Resolve a relative filename inside the approved
    directory. Reject paths outside that directory.
    """

    requested_path = Path(path)

    if requested_path.is_absolute():
        raise PermissionError(
            "Absolute paths are not permitted."
        )

    safe_path = (
        ALLOWED_DIRECTORY / requested_path
    ).resolve()

    if not safe_path.is_relative_to(ALLOWED_DIRECTORY):
        raise PermissionError(
            "Access outside the approved directory is denied."
        )

    if safe_path.suffix.lower() not in (".txt", ".log"):
        raise PermissionError(
            "Only .txt and .log files are supported."
        )

    return safe_path



# 4. ACTUAL PYTHON TOOLS read or delete


#read_local_file and delete_local_file are functions that perform file operations within the allowed directory. They use resolve_file_path to ensure that the requested file is within the approved directory and meets the security criteria. The read_local_file function reads the contents of a file, while delete_local_file deletes a file. Both functions handle errors and return appropriate messages.
def read_local_file(path: str) -> str:
    """Read an actual file from Windows Documents."""

    safe_path = resolve_file_path(path)

    if not safe_path.is_file():
        return "Requested file does not exist."

    if safe_path.stat().st_size > 100_000:
        raise ValueError(
            "File exceeds the 100 KB size limit."
        )

    contents = safe_path.read_text(encoding="utf-8")

    return contents


def delete_local_file(path: str) -> str:
    """Delete an actual file from Windows Documents."""

    safe_path = resolve_file_path(path)

    if not safe_path.is_file():
        return "Requested file does not exist."

    safe_path.unlink()

    return f"Successfully deleted: {safe_path.name}"



# 5. REGISTER TOOLS WITH SECURETOOLEXECUTOR


executor.register_tool(
    "read_file",
    read_local_file
)

executor.register_tool(
    "delete_file",
    delete_local_file
)


# 6. LANGCHAIN GUARDED TOOL WRAPPERS

#tool call from langchain that wraps the read_local_file and delete_local_file functions. These wrappers handle access control and error reporting. They use the SecureToolExecutor to execute the underlying file operations, ensuring that all requests are evaluated by SentinelGuard. The read_file tool reads a file, while the delete_file tool requests deletion of a file. Both tools handle access denied errors and other exceptions, returning appropriate messages to the user.
@tool
def read_file(path: str) -> str:
    """Read a .txt or .log file from Windows Documents."""

    try:
        return executor.execute(
            agent_id="security_analyst_agent",
            tool_name="read_file",
            path=path
        )

    except AccessDeniedError as error:
        return f"SENTINELGUARD DENIED: {error}"

    except (PermissionError, ValueError) as error:
        return f"FILE ACCESS REJECTED: {error}"

    except (OSError, UnicodeError) as error:
        return f"FILE READ ERROR: {error}"


@tool
def delete_file(path: str) -> str:
    """Request deletion of a .txt or .log file from Windows Documents."""

    try:
        return executor.execute(
            agent_id="security_analyst_agent",
            tool_name="delete_file",
            path=path
        )

    except AccessDeniedError as error:
        return f"SENTINELGUARD DENIED: {error}"

    except (PermissionError, ValueError) as error:
        return f"FILE ACCESS REJECTED: {error}"

    except OSError as error:
        return f"FILE DELETE ERROR: {error}"



# 7. MAIN LANGCHAIN AGENT


def main():

    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    model = ChatOpenAI(
        model="gpt-4.1-mini",
        temperature=0
    )

    agent = create_agent(
        model=model,
        tools=[read_file, delete_file],
        system_prompt=(
            "You are a cybersecurity assistant "
            "integrated with SentinelGuard. "
            "You have tools for reading and requesting "
            "deletion of files in Windows Documents. "
            "Pass relative filenames to tools. "
            "Use tools when a user requests file operations. "
            "Never claim an operation succeeded if "
            "SentinelGuard denied it. "
            "Report authorization failures accurately."
        )
    )

    print("\n" + "=" * 55)
    print("SENTINELGUARD - INTERACTIVE SECURITY AGENT")
    print("=" * 55)

    print(f"Authorized directory: {ALLOWED_DIRECTORY}")
    print("Security policy: read_file allowed")
    print("Security policy: delete_file denied")
    print("\nCommands: audit, exit")


    # 8. INTERACTIVE AGENT LOOP

    while True:

        user_input = input("\nYou: ").strip()

        if user_input.lower() in ("exit", "quit"):
            print("\nShutting down SentinelGuard.")
            break

        if user_input.lower() == "audit":

            print("\n=== SENTINELGUARD AUDIT TRAIL ===")

            events = audit_logger.read_events()

            for event in events:
                print(
                    f"\nEvent: {event['event_id']}"
                    f"\nAgent: {event['agent_id']}"
                    f"\nTool: {event['tool']}"
                    f"\nDecision: {event['decision'].upper()}"
                    f"\nReason: {event['reason']}"
                    f"\nTimestamp: {event['timestamp']}"
                )

            print(f"\nTotal audit events: {len(events)}")
            continue

        if not user_input:
            continue

        # Record starting audit count.
        previous_count = len(audit_logger.read_events())

        try:

         
            # 9. INVOKE THE LANGCHAIN AGENT
      

            result = agent.invoke({
                "messages": [
                    {
                        "role": "user",
                        "content": user_input
                    }
                ]
            })


        
            # 10. DISPLAY LANGCHAIN TOOL REQUESTS
           

            print("\n=== LANGCHAIN TOOL ACTIVITY ===")

            tool_called = False

            for message in result["messages"]:

                if getattr(message, "tool_calls", None):

                    for call in message.tool_calls:

                        tool_called = True

                        print(
                            f"\nTool requested: {call['name']}"
                        )

                        print(
                            f"Arguments: {call['args']}"
                        )

                if message.type == "tool":
                    print(
                        f"Tool result: {message.content}"
                    )

            if not tool_called:
                print("No tool requests generated.")


      
            # 11. DISPLAY AGENT RESPONSE
      

            print("\n=== AGENT RESPONSE ===")

            print(
                result["messages"][-1].content
            )

        except Exception as error:
            print(f"\nAgent error: {error}")

        finally:
          
            # 12. DISPLAY NEW AUDIT EVENTS
            

            print("\n=== SENTINELGUARD SECURITY ACTIVITY ===")

            try:
                events = audit_logger.read_events()
                new_events = events[previous_count:]

                if not new_events:
                    print(
                        "No new authorization events recorded."
                    )

                for event in new_events:

                    print(
                        f"\nDecision: {event['decision'].upper()}"
                        f"\nAgent: {event['agent_id']}"
                        f"\nTool: {event['tool']}"
                        f"\nReason: {event['reason']}"
                    )

            except Exception as error:
                print(f"Audit read error: {error}")


if __name__ == "__main__":
    main()
