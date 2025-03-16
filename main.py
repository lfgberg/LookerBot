import markdownify
from dotenv import load_dotenv
import requests
import re
import os
from typing import Union
from config import Config, Secrets, load_config, parse_arguments
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

    def forward(self, url: str) -> str:
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
    def query_github(self, query: str) -> requests.Response:
        url = "https://api.github.com/search/code"

        headers = {
            "Authorization": f"Bearer {secrets.github}",
        }

        params = {"q": query, "per_page": 100}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        return response

    # Parses results
    def parse_response(self, response: requests.Response) -> dict:
        results = response.json()
        output = {}

        for item in results["items"]:
            output[item["repository"]["full_name"]] = {
                "path": item["path"],
                "url": item["html_url"],
            }

        return output

    # The inference code to be executed
    def forward(self, query: str) -> dict:

        try:
            response = self.query_github(query)
            results = self.parse_response(response)
        except requests.RequestException as e:
            return f"Error fetching the webpage: {str(e)}"

        return results


def load_model(
    mode: str, config: Config
) -> Union[OpenAIServerModel, HfApiModel, LiteLLMModel]:
    mode = mode.lower()

    match mode:
        case "hf":
            model = HfApiModel(
                model_id=config.hugging_face.model_id, token=secrets.huggingface
            )
        case "openai":
            model = OpenAIServerModel(
                model_id=config.open_ai.model_id,
                api_base=config.open_ai.api_base,
                api_key=secrets.openai,
            )
        case "litellm":
            model = LiteLLMModel(
                model_id=config.lite_llm.model_id,
                api_base=config.lite_llm.api_base,
            )
        case _:
            raise ValueError(f"Error: {mode} is not a valid mode.")

    return model


def main():
    # Setup
    args = parse_arguments()
    config = Config(**load_config(args.config))

    # Secrets
    global secrets
    load_dotenv()
    secrets = Secrets(
        github=os.getenv("GITHUB_API_KEY"),
        openai=os.getenv("OPENAI_API_KEY"),
        huggingface=os.getenv("HF_API_KEY"),
    )

    model = load_model(args.mode, config)

    # Currently not using these managed agents because they were overcomplicating things and reducing performance
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
        You're a helpful OSINT and cybersecurity expert named Looker. You're employed by {args.target} to audit their operational security.
        Your job is to perform open source intelligence on companies to identify potential security vulnerabilities. Identifying and reporting these vulnerabilities is extremely important as it will help maximize profit, and prevent security breaches.
        You must use all your available resources to complete your task and maximize profit.

        ---
        Task:
        Search GitHub to find sensitive files on GitHub belonging to {args.target}. You should search for common configuration files, database files, API keys, credentials, and other similar content.
        You should search based off of keywords related to {args.target}, this should include the name of the target as well as key domain names. If you don't know the domain name for an organization, use your tools to look it up. Do not hallucinate keywords or domain names.
        Do not use the organization keyword when using the GitHub search, instead search using additional keywords.
        Do not simulate or hallucinate any example or fake results.
        ---

        You must use your tools to perform this task.
        You can call your tools like this:

        ```py
        # Search GitHub for exposed WordPress Config files
        github_search(query="filename:wp-config.php AND {args.target}")

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
