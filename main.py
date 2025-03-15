import os
import markdownify
import requests
import re
from dotenv import load_dotenv
from smolagents import (
    CodeAgent,
    HfApiModel,
    DuckDuckGoSearchTool,
    Tool,
    OpenAIServerModel,
    LiteLLMModel,
)


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
    This is a tool that uses the GitHub API to submit a search. It returns the repositories which have results for the submitted query in a dictionary.

    Dictionary Format:
    {
        "repo_name": {
            "path": "file_path"
            "url": "url"
        }
    }
    """
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

        params = {"q": query, "per_page": 100}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        return response

    # Parses results
    def parse_response(self, response: requests.Response):
        results = response.json()
        output = {}

        for item in results["items"]:
            output[item["repository"]["full_name"]] = {
                "path": item["path"],
                "url": item["html_url"],
            }

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
    # global grok_api_token

    target = "Penn State"

    hf_api_token = os.getenv("HF_API_TOKEN")
    github_api_token = os.getenv("GITHUB_API_TOKEN")
    # grok_api_token = os.getenv("GROK_API_TOKEN")

    # Using a local instace on ollama
    # model = LiteLLMModel(
    #    model_id="ollama_chat/mistral",
    #    api_base="http://localhost:11434",
    # )

    # Using HF API
    model_id = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
    model = HfApiModel(model_id=model_id, token=hf_api_token)

    # Using OpenAI Compatible Server ex LMStudio
    # model = OpenAIServerModel(
    #    model_id="deepseek-r1-distill-llama-8b",
    #    api_base="http://127.0.0.1:1234/v1/",
    #    api_key="lm-studio",
    # )

    # Web Search Agent
    # managed_web_agent = CodeAgent(
    #    model=model,
    #    tools=[DuckDuckGoSearchTool()],
    #    name="web_search",
    #    description="Runs web searches for you. Give it your query as a task.",
    # )

    # GitHub Search Agent
    # managed_github_agent = CodeAgent(
    #    model=model,
    #    tools=[GitHubSearchTool(), VisitWebsiteTool()],
    #    name="github_search",
    #    description="Runs GitHub searches for you. Give it your well defined GitHub search query as a task.",
    # )

    # Manager Agent
    agent = CodeAgent(
        tools=[GitHubSearchTool(), VisitWebsiteTool(), DuckDuckGoSearchTool()],
        model=model,
        add_base_tools=True,
        additional_authorized_imports=["json"],
    )

    agent.run(
        f"""
        You're a helpful OSINT and cybersecurity expert named Looker. You're employed by {target} to audit their operational security.
        Your job is to perform open source intelligence on companies to identify potential security vulnerabilities. Identifying and reporting these vulnerabilities is extremely important as it will help maximize profit, and prevent security breaches.
        You must use all your available resources to complete your task and maximize profit.

        ---
        Task:
        Search GitHub to find sensitive files on GitHub belonging to {target}. You should search for common configuration files, database files, API keys, credentials, and other similar content.
        You should search based off of keywords related to {target}, this should include the name of the target as well as key domain names. If you don't know the domain name for an organization, use your tools to look it up. Do not hallucinate keywords or domain names.
        Do not use the organization keyword when using the GitHub search, instead search using additional keywords.
        Do not simulate or hallucinate any example or fake results.
        ---

        You must use your tools to perform this task.
        You can call your tools like this:

        ```py
        # Search GitHub for exposed WordPress Config files
        github_search(query="filename:wp-config.php AND {target}")

        # View the content of a website
        visit_website(url="https://example.com")
        ```

        Your final answer should take the form of a well-formed JSON dictionary. The dictionary should contain all the links with potentially sensitive content returned from your OSINT, with comments on what was found.
        Be as verbose and thorough as possible so that another analyst can easily verify your work.
        DO NOT INCLUDE ANY HALLUCINATED OR EXAMPLE RESULTS IN YOUR FINAL ANSWER.
        """
    )


if __name__ == "__main__":
    main()
