
import json
from pathlib import Path

#agent registry class to manage registered agents
class AgentRegistry:

    #constructor to initialize the registry with a file path
    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def list_agents(self):
        """Return all registered agents."""
        with self.file_path.open(
            "r", encoding="utf-8"
        ) as file:
            data = json.load(file)

        return data["agents"]

    def get_agent(self, agent_id):
        """Find an agent by its unique ID."""
        for agent in self.list_agents():
            if agent["agent_id"] == agent_id:
                return agent

        return None
