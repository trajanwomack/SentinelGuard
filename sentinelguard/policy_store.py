
import json
from pathlib import Path


class PolicyStore:
    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def get_policy(self, policy_id):
        """Load the security policy for an agent."""
        with self.file_path.open(
            "r", encoding="utf-8"
        ) as file:
            data = json.load(file)

        policy = data["policies"].get(policy_id)

        if policy is None:
            raise ValueError(
                f"Policy '{policy_id}' not found"
            )

        if not isinstance(
            policy.get("allowed_tools"), list
        ):
            raise ValueError(
                "Invalid policy: allowed_tools missing"
            )

        if not all(
            isinstance(tool, str)
            for tool in policy["allowed_tools"]
        ):
            raise ValueError(
                "Invalid policy tool names"
            )

        return policy
