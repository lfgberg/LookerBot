import os
import markdownify
import requests
import re
from dotenv import load_dotenv
from smolagents import CodeAgent, HfApiModel, DuckDuckGoSearchTool, Tool


class VisitWebsiteTool(Tool):
    # Tool info
    name = "visit_website"
    description = """
    Visits a webpage at the given URL and returns its content as a markdown string."""
    inputs = {
        "url": {"type": "string", "description": "The URL of the webpage to visit"}
    }
    output_type = "string"

    def forward(self, url: str):
        try:
            # Send a GET request to the URL
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for bad status codes

            # Convert the HTML content to Markdown
            markdown_content = markdownify(response.text).strip()

            # Remove multiple line breaks
            markdown_content = re.sub(r"\n{3,}", "\n\n", markdown_content)

            return markdown_content

        except requests.RequestException as e:
            return f"Error fetching the webpage: {str(e)}"
        except Exception as e:
            return f"An unexpected error occurred: {str(e)}"


class GitHubSearchTool(Tool):
    # Tool Info
    name = "github_search"
    description = """
    This is a tool that uses the GitHub API to submit a search. It returns the repositories which have results for the submitted query."""
    inputs = {
        "query": {
            "type": "string",
            "description": "The search query to submit to github (A dork such as 'filename:wp-config.php')",
        }
    }
    output_type = "string"

    # Queries GitHub w/API Key
    def query_github(self, query: str):
        url = "https://api.github.com/search/code"

        headers = {
            "Authorization": f"Bearer {github_api_token}",
        }

        params = {"q": query}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        return response

    # Parses results
    def parse_response(self, response: requests.Response):
        results = response.json()
        output = []

        for item in results["items"]:
            output.append(
                [item["repository"]["full_name"], item["path"], item["html_url"]]
            )

        return output

    # The inference code to be executed
    def forward(self, query: str):

        try:
            response = self.query_github(query)
            results = self.parse_response(response)
        except requests.RequestException as e:
            return f"Error fetching the webpage: {str(e)}"

        return results


def main():
    # Pull in API keys from .env
    load_dotenv()

    global hf_api_token
    global github_api_token

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
        description="Runs web searches for you. Give it your query as a task.",
    )

    # GitHub Search Agent
    managed_github_agent = CodeAgent(
        model=model,
        tools=[GitHubSearchTool(), VisitWebsiteTool()],
        name="github_search",
        description="Runs GitHub searches for you. Give it your query as a task.",
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
Search GitHub to find exposed wp_config files.
---
You must use your agents to perform this task.""",
    )


if __name__ == "__main__":
    main()
