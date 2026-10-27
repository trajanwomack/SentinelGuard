import streamlit as st
from pathlib import Path

from sentinelguard.registry import AgentRegistry
from sentinelguard.policy_store import PolicyStore



#configuration

# 1. CONFIGURATION

#find sentinelguard project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent

REGISTRY_PATH = PROJECT_ROOT / "config" / "agents.json"

#initialize the agent registry
registry = AgentRegistry(REGISTRY_PATH)


POLICY_PATH = PROJECT_ROOT / "config" / "policies.json"

#initialize the policy store
policy_store = PolicyStore(POLICY_PATH)


# 2. PAGE CONFIGURATION

st.set_page_config(
    page_title="SentinelGuard",
    page_icon="🛡️",
    layout="wide"
)

# 3. DASHBOARD HEADER

st.title("🛡️ SentinelGuard")
st.subheader("AI Agent Security Dashboard")

st.write(
    "Manage connected AI agents and their security policies."
)

# 4. LOAD REGISTERED AGENTS


#load registered agents from the registry and handle errors
#calls agents.json file and loads the agents into the dashboard
try:
    agents = registry.list_agents()

except (OSError, ValueError, KeyError) as error:
    st.error(f"Unable to load agent registry: {error}")
    st.stop()

# 5. DISPLAY CONNECTED AGENTS

st.header("Registered Agents")

if not agents:
    st.info("No agents have been registered.")

else:

    #render the list of agents in a structured format
    for agent in agents:
        with st.container(border=True):
            st.subheader(agent["name"])

            st.write(f"Agent ID: {agent['agent_id']}")
            st.write(f"Framework: {agent['framework']}")
            st.write(f"Policy: {agent['policy_id']}")

            if agent["enabled"]:
                st.success("Enabled")
            else:
                st.warning("Disabled")

            # 6 DISPLAY SECURITY POLICY

            st.markdown("**Security Permissions**")


            #use agent's policy_id to retrieve the security policy from the policy store
            try:
                policy = policy_store.get_policy(
                    agent["policy_id"]
                )

                allowed_tools = policy["allowed_tools"]

                # Available tools for our current LangChain agent.
                available_tools = ["read_file", "delete_file"]

                st.markdown("**Configure Permissions**")

                selected_tools = []

                for tool in available_tools:

                    #check if the tool is allowed for the agent and create a checkbox for it
                    enabled = st.checkbox(
                        label=tool,
                        value=tool in allowed_tools,
                        key=f"{agent['agent_id']}_{tool}"
                    )

                    #if the checkbox is checked, add the tool to the selected_tools list
                    if enabled:
                        selected_tools.append(tool)

                if st.button(
                    "Save Permissions",
                    key=f"save_{agent['agent_id']}"
                ):

                    #save the updated security policy for the agent
                    try:
                        policy_store.save_policy(
                            agent["policy_id"],
                            selected_tools
                        )

                        st.success("Security policy updated successfully!")

                    except (OSError, ValueError, KeyError) as error:
                        st.error(f"Unable to save policy: {error}")

                

            except (OSError, ValueError, KeyError) as error:
                st.error(
                    f"Unable to load agent policy: {error}"
                )


