
from sentinelguard.registry import AgentRegistry

registry = AgentRegistry("config/agents.json")

print("Registered agents:")
for agent in registry.list_agents():
    print(agent["name"])

print("\nLooking up our LangChain agent:")

agent = registry.get_agent(
    "security_analyst_agent"
)

print(agent)
