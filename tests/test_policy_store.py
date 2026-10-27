
import json
import tempfile
import unittest
from pathlib import Path

from sentinelguard.policy_store import PolicyStore

class TestPolicyStore(unittest.TestCase):

    def test_save_policy(self):

        #create temporary file for testing

        with tempfile.TemporaryDirectory() as temp_dir:
            policy_file= Path(temp_dir) / "policies.json"

             # Create an initial test policy.
            initial_data = {
                "policies": {
                    "analyst_policy": {
                        "allowed_tools": ["read_file"]
                    }
                }
            }

            policy_file.write_text(json.dumps(initial_data), encoding="utf-8")

            #initialize the PolicyStore with the temporary file
            store = PolicyStore(policy_file)

            #call save_policy to add a new policy
            store.save_policy(
                "analyst_policy", ["read_file", "write_file"]
            )

            #reload the policies from the file to verify the new policy was saved
            updated_policy = store.get_policy("analyst_policy")

            #verify that the new policy has the correct allowed tools
            self.assertEqual(
                updated_policy["allowed_tools"],
                ["read_file", "write_file"]
            )

if __name__ == "__main__":
    unittest.main() 