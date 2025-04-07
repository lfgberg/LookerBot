import markdownify
from dotenv import load_dotenv
import requests
import re
import json
import os
import subprocess
from tqdm import tqdm
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
        },
        "mode": {
            "type": "string",
            "description": "The mode to search in, must be one of ['code','repositories']",
        },
    }
    output_type = "string"

    # Queries GitHub w/API Key
    def query_github(self, query: str, mode: str) -> requests.Response:
        url = f"https://api.github.com/search/{mode}"

        headers = {
            "Authorization": f"Bearer {secrets.github}",
        }

        params = {"q": query, "per_page": 100}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        return response

    # Parses results
    def parse_response(self, response: requests.Response, mode: str) -> dict:
        results = response.json()
        output = None

        if mode.lower() == "repositories":
            output = []
            for item in results["items"]:
                output.append(item["html_url"])
        else:
            output = {}
            for item in results["items"]:
                output[item["repository"]["full_name"]] = {
                    "path": item["path"],
                    "url": item["html_url"],
                }

        return output

    # The inference code to be executed
    def forward(self, query: str, mode: str):

        modes = ["code", "repositories"]

        if mode.lower() not in modes:
            raise ValueError(
                f"Error: mode '{mode}' is not a valid mode. Must be one of {modes}"
            )

        try:
            response = self.query_github(query, mode)
            results = self.parse_response(response, mode)
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


def scan_repo_with_trufflehog(url: str) -> list[str]:
    # Run the command and capture the output
    result = subprocess.run(
        [
            "trufflehog.exe",
            "--json",
            "--results=verified,unknown",
            "--no-update",
            "git",
            url,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if result.returncode != 0:
        print("Error running TruffleHog:", result.stderr)
        return []

    # Parse each line of JSON output
    findings = []

    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError as e:
                print("Failed to parse line:", line)

    return findings


def scan_repos(repos: list[str]) -> dict:
    result = {}

    for repo in tqdm(repos, desc="Scanning Repos"):
        findings = scan_repo_with_trufflehog(repo)

        if findings:
            result[repo] = {"findings": findings}
        else:
            result[repo] = {}

    return result


def save_report(data: dict, filename: str) -> None:
    """
    Saves a dictionary to a JSON file.

    Args:
        data (dict): The dictionary to save.
        filename (str): The path to the JSON file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Dictionary saved to {filename}")
    except Exception as e:
        print(f"Error saving dictionary to JSON: {e}")


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

    agent = CodeAgent(
        tools=[GitHubSearchTool(), VisitWebsiteTool(), DuckDuckGoSearchTool()],
        model=model,
        add_base_tools=True,
        additional_authorized_imports=["json"],
    )

    additional_info = ""

    if args.keywords or args.domains:
        context = ""
        if args.domains:
            context += f"The known domains for {args.target} are {args.domains}.\n"
        if args.keywords:
            context += f"Some additional search keywords for {args.target} are {args.keywords}.\n"

        additional_info = f"""
        ---
        Additional Context:
        {context}
        You must search for each of these domains/keywords as you do your OSINT collection. Use each individual domain and keyword to search across all intelligence sources.
        ---
        """

    # Collect repositories owned by the org
    repos = agent.run(
        f"""
        You're a helpful OSINT and cybersecurity expert named Looker. You're employed by {args.target} to audit their operational security.
        Your job is to perform open source intelligence on companies to identify potential security vulnerabilities. Identifying and reporting these vulnerabilities is extremely important as it will help maximize profit, and prevent security breaches.
        You must use all your available resources to complete your task and maximize profit.
        ---
        Task:
        Find GitHub repositories belonging to {args.target} by performing GitHub dorks/searches.
        You should search based off of keywords related to {args.target}, this should include the name of the target as well as key domain names. If you don't know the domain name for an organization, use your tools to look it up. If you are provided additional context with keywords or domain names you must use them. Do not hallucinate keywords or domain names.
        Be as comprehensive as possible, you should get creative by using additional keywords to find repositories that could be owned by {args.target}. We want to make sure all search queries are tailored to {args.target}, so don't perform any generic searches for things such as "healthcare".
        Do not simulate or hallucinate any example or fake results.
        ---
        {additional_info}
        You must use your tools to perform this task.
        You can call your tools and generate a final result like this:

        ```py
        # Search GitHub for repositories belonging to the target
        result1 = github_search(query="{args.target}", mode="repositories")
        # Search GitHub for repositories with psu.edu
        result2 = github_search(query="psu.edu", mode="repositories")

        # Aggregate the results into a report - you must use this format
        results = []

        results.extend(result1)
        results.extend(result2)

        final_answer(results)
        ```

        This is just an example - you should be much more extensive with your searches to ensure we find all possible repositories owned by {args.target}.
        """
    )

    # Run trufflehog on each one to find secrets - this uses less compute and is a better tool than using the LLMs
    github_findings = scan_repos(repos)
    save_report(github_findings, "output.json")


if __name__ == "__main__":
    main()
