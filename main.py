import markdownify
from dotenv import load_dotenv
import requests
import re
import json
import os
import subprocess
import whois
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class WhoIsTool(Tool):
    # Tool Info
    name = "whois_lookup"
    description = """
    This is a tool that queries the WHOIS data for a given domain. It returns the fetched data for the domain including the domain name, registrar, etc.
    """
    inputs = {
        "domain": {
            "type": "string",
            "description": "The domain name to fetch WHOIS data on.",
        },
    }
    output_type = "string"

    # The inference code to be executed
    def forward(self, domain: str):

        domain_info = whois.whois(domain)

        return domain_info


class ExtractDomainsTool(Tool):
    # Tool Info
    name = "extract_domains"
    description = """
    This is a tool that extracts domain names from text or markdown content.
    """
    inputs = {
        "text": {
            "type": "string",
            "description": "The markdown or text based content to parse domain names from.",
        },
    }
    output_type = "set"

    # The inference code to be executed
    def forward(self, site_content: str) -> set:
        # Regex to match URLs (http, https, or www-based)
        url_pattern = re.compile(
            r'https?://[^\s)"\'<>]+|www\.[^\s)"\'<>]+', re.IGNORECASE
        )

        # Find all URL-like strings
        urls = re.findall(url_pattern, site_content)

        domains = set()
        for url in urls:
            try:
                # Ensure URL has scheme for parsing
                if not url.startswith("http"):
                    url = "http://" + url
                parsed_url = urlparse(url)
                hostname = parsed_url.hostname
                if hostname:
                    domains.add(hostname.lower())
            except Exception:
                continue  # Skip bad URLs

        return domains


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
    """
    Uses TruffleHog to scan a GitHub repository and pull JSON output
    Takes a URL string of the repo to scan, returns a list of findings in JSON format
    Relies on trufflehog being installed
    """
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


def scan_repos(repos: list[str], max_workers: int) -> dict:
    """
    Concurrently loops through a list of provided GitHub repos and scans them with trufflehog
    Takes a list of repos, and a max number of workers/threads to use
    Outputs a dict in the following format with any potential findings:
    {
        "<REPO URL1>": {
            "github_findings": [{finding1}, {finding2}]
        },
        "<REPO URL2>": {
            "github_findings": [{finding1}, {finding2}]
        }
    }
    """

    results = {}

    # Using a ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_repo = {
            executor.submit(scan_repo_with_trufflehog, repo): repo for repo in repos
        }
        for future in tqdm(
            as_completed(future_to_repo), total=len(repos), desc="Scanning Repos"
        ):
            repo = future_to_repo[future]
            try:
                findings = future.result()
                if findings:
                    results[repo] = {"github_findings": findings}
                else:
                    results[repo] = {}
            except Exception as exc:
                print(f"Error processing repo {repo}: {exc}")
                results[repo] = {}
    return results


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
            context += f"- The known domains for {args.target} are {args.domains}.\n"
        if args.keywords:
            context += f"- Some additional search keywords for {args.target} are {args.keywords}.\n"

        additional_info = f"""
        **Additional Context:**
        {context}
        - You must search for each of these domains/keywords as you do your OSINT collection. Use each individual domain and keyword to search across all intelligence sources.
        """

    # Collect repositories owned by the org
    repos = agent.run(
        f"""
**Role & Context**
You are Looker, a highly skilled OSINT and cybersecurity expert employed by {args.target}. Your duty is to audit the operational security of {args.target} by gathering comprehensive OSINT, especially by identifying all GitHub repositories that potentially belong to this organization. Your findings should contribute to preventing vulnerabilities that could lead to security breaches, thereby maximizing profit and ensuring operational security.

**Task Description**
Your primary task is to search for GitHub repositories that are owned by or affiliated with {args.target}. Use GitHub dorks and custom search queries based on keywords that are tightly related to {args.target}—this should include the organization’s name, its key domain names, and any additional context provided (e.g., relevant product names, acronyms, or subsidiaries). Do not use generic or unrelated keywords (e.g., "healthcare") and do not generate or simulate fake results.

**Instructions & Guidelines**

**Keyword and Domain Identification:**

- If the target’s domain names are unknown, use appropriate tools to look them up and verify them before including them in your searches.
- Tailor all search queries specifically to {args.target} using verified keywords and domain names.
- If additional context (such as extra keywords or verified alternate domain names) is provided, incorporate those explicitly.

**Search Methodology:**

- Craft diverse search queries (dorks) to explore various angles (e.g., by repository name patterns, mentions in README files, or special configurations) that are likely to point to repositories owned by {args.target}.
- Ensure that each query is self-contained and clearly references {args.target} (e.g., “{args.target} AND <DOMAIN>”, "<DOMAIN>", "{args.target}").

**Avoid Hallucination:**

- Do not generate example repository names or domain names if not confirmed. Only use verified data from tool lookups.
- Validate each keyword and domain used from trusted resources before including it in the search queries.

**Use of Tools:**

- Explicitly call your search tools (such as GitHub search APIs or custom dorking tools) and include a process to log or reference your methodology.
- Aggregate all found results into a final report. The final result format should be a unified list that includes the repository links and a brief comment on the relevance (if applicable).

**Output Structure:**

Aggregate the findings clearly in the following structure:

```py
# Define an array of search queries, each tailored to {args.target} with verified keywords or domains.
queries = [
    "{args.target} AND <verified_domain_or_keyword>",
    "{args.target} AND <additional_verified_keyword>",
    # Add more queries as needed
]

results = []

# Loop through each query in the array and extend the results list with the findings.
for query in queries:
    result = github_search(query=query, mode="repositories")
    results.extend(result)

# Deduplicate the results.
unique_results = list(set(results))
    
final_answer(unique_results)
```

- Ensure that your final answer includes only verified and trustworthy information.

{additional_info}

**Quality Assurance**

- Before finalizing your output, double-check that all search queries are tailored uniquely to {args.target}.
- Make sure that no generic information is included in the final output.
- If any query results in ambiguous or unrelated data, document this and focus only on confirmed findings.
        """
    )

    # Run trufflehog on each one to find secrets
    github_findings = scan_repos(repos, config.max_workers)
    save_report(github_findings, config.outfile)


if __name__ == "__main__":
    main()
