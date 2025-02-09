import os
from dotenv import load_dotenv
from smolagents import CodeAgent, LiteLLMModel, HfApiModel, DuckDuckGoSearchTool
from github import GitHubSearchTool


def main():
    # Pull in API key from .env
    load_dotenv()
    hf_api_token = os.getenv("HF_API_TOKEN")
    github_api_token = os.getenv("GITHUB_API_TOKEN")

    # Using a local mistral instance on ollama
    # model = LiteLLMModel(
    #    model_id="ollama_chat/mistral",
    #    api_base="http://localhost:11434",
    # )

    # Using HF API
    model_id = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
    model = HfApiModel(model_id=model_id, token=hf_api_token)

    # Web Search Agent
    managed_web_agent = CodeAgent(
        model=model,
        tools=[DuckDuckGoSearchTool()],
        name="web_search",
        description="Runs web searches for you. Give it your query as an argument.",
    )

    # GitHub Search Agent
    managed_github_agent = CodeAgent(
        model=model,
        tools=[GitHubSearchTool(github_api_token)],
        name="github_search",
        description="Runs GitHub searches for you. Give it your query as an argument.",
    )

    # Manager Agent
    manager_agent = CodeAgent(
        tools=[],
        model=model,
        add_base_tools=True,
        managed_agents=[managed_web_agent, managed_github_agent],
    )

    manager_agent.run(
        """You're a helpful manager.
Your job is to manage your agents to perform open source intelligence.
You must use all your available resources to complete your task and maximize profit.
---
Task:
Search GitHub to find exposed wp_config files
---
You must use your agents to perform this task.""",
    )


if __name__ == "__main__":
    main()
