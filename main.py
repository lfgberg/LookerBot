
import os
from dotenv import load_dotenv
from smolagents import (
    CodeAgent,
    LiteLLMModel,
    HfApiModel,
    ManagedAgent,
    DuckDuckGoSearchTool
)

# Pull in API key from .env
load_dotenv()
hf_api_token = os.getenv('HF_API_TOKEN')

# Using a local mistral instance on ollama
#model = LiteLLMModel(
#    model_id="ollama_chat/mistral",
#    api_base="http://localhost:11434",
#)

# Using HF API
model_id = "Qwen/Qwen2.5-72B-Instruct"
model = HfApiModel(model_id=model_id, token=hf_api_token)

# Web Search Agent
web_agent = CodeAgent(tools=[DuckDuckGoSearchTool()], model=model)

managed_web_agent = ManagedAgent(
    agent=web_agent,
    name="web_search",
    description="Runs web searches for you. Give it your query as an argument."
)

# Manager Agent
manager_agent = CodeAgent(tools=[], model=model, add_base_tools=True, managed_agents=[managed_web_agent])


manager_agent.run(
    "Find all the subsidiaries of United Healthcare, create a well formed JSON file containing each subsidiary, and it's associated domain names. be as thorough as possible.",
)