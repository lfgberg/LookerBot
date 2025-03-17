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

    intel = agent.run(
        f"""
        You're a helpful OSINT and cybersecurity expert named Looker. You're employed by {args.target} to audit their operational security.
        Your job is to perform open source intelligence on companies to identify potential security vulnerabilities. Identifying and reporting these vulnerabilities is extremely important as it will help maximize profit, and prevent security breaches.
        You must use all your available resources to complete your task and maximize profit.

        ---
        Task:
        Find sensitive files belonging to {args.target} by performing GitHub and DuckDuckGo dorks. You should search for common configuration files, database files, API keys, credentials, and other similar content. Be as exhaustive as possible, search for all possible sensitive information.
        You should search based off of keywords related to {args.target}, this should include the name of the target as well as key domain names. If you don't know the domain name for an organization, use your tools to look it up. If you are provided additional context with keywords or domain names you do not need to look them up. Do not hallucinate keywords or domain names.
        Do not use the organization keyword when using the GitHub search, instead search using additional keywords.
        Do not simulate or hallucinate any example or fake results.
        ---
        {additional_info}
        You must use your tools to perform this task.
        You can call your tools and generate a report like this:

        ```py
        # Search GitHub for exposed WordPress Config files - uses the GitHub search syntax
        result = github_search(query="filename:wp-config.php AND {args.target}")

        # View the content of a website
        result1 = visit_website(url="https://example.com")

        # Search DuckDuckGo for pdf files on psu.edu - uses the DuckDuckGo search syntax
        result2 = web_search(query="filetype:pdf site:psu.edu")

        # Aggregate the results into a report
        report = {{                                                                                                                                                                                                                
            "Penn State": {{                                                                                                                                                                                                       
                "GitHub": [],                                                                                                                                                                                                                
                "DuckDuckGo": []                                                                                                                                                                                                                 
            }}                                                                                                                                                                                                                     
        }} 

        report["Penn State"]["GitHub"].append(result)

        final_answer(report)
        ```

        Your final answer should take the form of a well-formed JSON dictionary. The dictionary should contain all the links with potentially sensitive content returned from your OSINT, with comments on what was found, and the query/intelligence source that provided the intel.
        Be as verbose and thorough as possible so that another analyst can easily verify your work.
        DO NOT INCLUDE ANY HALLUCINATED OR EXAMPLE RESULTS IN YOUR FINAL ANSWER.
        Do not just print out your results - you need to return them in your final answer as part of a JSON dictionary.
        Ensure you are wrapping tool use in try catch blocks to handle exceptions.
        """
    )

    agent.run(
        f"""
You're a helpful OSINT and cybersecurity expert named Looker. You're employed by {args.target} to audit their operational security.
Another analyst on your team has aggregated a JSON dictionary containing potential sensitive information on {args.target} found through OSINT.

Your job is to use your visit_website tool to view the contents of each entry, and determine if you believe it is actually potentially sensitive information relating to {args.target}.

Here is the report from your coworker:
```json
{intel}
```

Remove any elements from the report that you don't think are legitamite, and return this audited report as your final answer.
"""
    )


if __name__ == "__main__":
    main()
