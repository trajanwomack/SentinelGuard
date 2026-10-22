# SentinelGuard

**A policy-based security framework for AI agents, featuring tool authorization, role-based access control, execution enforcement, and audit logging.**

SentinelGuard is a Python security framework designed to introduce a deterministic authorization layer between AI agents and the tools they use.

Instead of relying solely on an LLM's instructions to prevent unauthorized actions, SentinelGuard evaluates tool requests against registered security policies before permitting execution.

## The Problem

AI agents can interact with external tools, files, APIs, and sensitive resources. Without independent security controls, an agent may attempt operations beyond its intended permissions.

SentinelGuard explores how traditional cybersecurity principles—including least privilege, role-based access control, and auditability—can be applied to agentic AI workflows.

## Architecture

```text
           User Request
                |
                v
         LangChain Agent
                |
                v
       Guarded Tool Wrapper
                |
                v
       SecureToolExecutor
                |
                v
         SentinelGuard
         Policy Engine
                |
        +-------+--------+
        |                |
        v                v
 ToolExecutionGuard  AccessControlGuard
        |                |
        +-------+--------+
                |
                v
         Allow / Deny
                |
        +-------+--------+
        |                |
      Allow             Deny
        |                |
        v                v
   Execute Tool      Block Action
        |
        v
     Tool Result

   Authorization decisions
       -> Audit Logger
```

Guards are independently registered. The LangChain demonstration currently uses `ToolExecutionGuard`; role-based access control is demonstrated separately.

## Core Components

| Component | Responsibility |
|---|---|
| SentinelGuard Engine | Evaluates requests against registered guards |
| ToolExecutionGuard | Checks whether a requested tool is authorized |
| AccessControlGuard | Evaluates agent roles and resource permissions |
| SecureToolExecutor | Enforces authorization before calling registered tools |
| AuditLogger | Records authorization decisions in JSONL format |
| LangChain Integration | Connects an LLM-powered agent to guarded tools |

## Security Features

- Explicit tool allowlists
- Role-based access control
- Deny-by-default behavior when no guards are registered
- Blocking of unauthorized tool execution
- Persistent authorization audit records
- Filesystem path restrictions in the LangChain demonstration
- Modular guard registration

## Installation

Clone the repository:

```bash
git clone https://github.com/trajanwomack/SentinelGuard.git
cd SentinelGuard
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Install the required dependencies for the LangChain example:

```bash
python -m pip install langchain langchain-openai openai
```

Configure the `OPENAI_API_KEY` environment variable before running the LLM-powered demonstration. Never commit API keys or credentials to the repository.

## Running the Examples

Basic tool authorization and audit logging:

```bash
python -m examples.basic_usage
```

Role-based access control:

```bash
python -m examples.access_control_demo
```

LangChain agent integration:

```bash
python -m examples.langchain_agent
```

**Caution:** The LangChain example includes a real file-deletion tool operating on supported files in the user's Windows Documents directory. Review the tool allowlist and use disposable test files before running it.

## Security Demonstrations

**Test 1 — Authorized Tool Execution**

An agent requests a permitted tool. SentinelGuard evaluates the request, returns an allow decision, and the executor runs the registered function.

**Test 2 — Unauthorized Tool Execution**

An agent requests a tool outside its configured allowlist. SentinelGuard returns a deny decision and the executor prevents execution.

**Test 3 — Audit Logging**

The framework records authorization decisions, including the requesting agent, tool, decision, reason, and timestamp.

Additional unit tests cover access control and enforcement behavior.

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Development Roadmap

- External policy configuration and persistent policy storage
- Additional request and output verification
- Expanded security testing and adversarial scenarios
- Support for additional agent frameworks
- More granular resource and argument authorization
- CI/CD integration using GitHub Actions

## Project Status

**Early-stage educational and research prototype.**

SentinelGuard demonstrates core authorization and enforcement concepts but has not been independently security-audited. It should not be treated as a complete production-ready agent security solution.

## Technologies

Python · LangChain · OpenAI API · Role-Based Access Control · JSONL Audit Logging · Git

## Author

Trajan Womack

GitHub: https://github.com/trajanwomack