
import json
from pathlib import Path

#for policy store
import os
import tempfile



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


    def save_policy(self, policy_id, allowed_tools):

        #validate the new permissions
        if (
            not isinstance(allowed_tools, list)
            or not all(
                isinstance(tool, str) and tool.strip() 
                for tool in allowed_tools
            )
        ):
            raise ValueError("Invalid allowed_tools: must be a list of non-empty strings")
        
        #load existing policies
        with self.file_path.open(
            "r", encoding="utf-8"
        ) as file:
            data = json.load(file)

        if policy_id not in data["policies"]:
            raise ValueError(
                f"Policy '{policy_id}' not found"
            )

        #update the policy
        data["policies"][policy_id]["allowed_tools"] = (allowed_tools.copy())

        #write to a temporary file first to avoid corruption
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.file_path.parent,
                delete=False,
                suffix=".tmp"
            ) as temp_file:
                temp_path = Path(temp_file.name)
                json.dump(data, temp_file, indent=4)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            # Replace the original file after writing.
            os.replace(temp_path, self.file_path)

        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
