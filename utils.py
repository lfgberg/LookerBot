import requests
from smolagents import OpenAIServerModel, HfApiModel, LiteLLMModel
import whois
from config import Config, Secrets
from typing import Union
import subprocess
import json
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_model(
    mode: str, config: Config, secrets: Secrets
) -> Union[OpenAIServerModel, HfApiModel, LiteLLMModel]:
    """
    Returns a well-formed smolagents model based on a provided mode string
    """
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


def scan_repo_with_trufflehog(url: str, os: str) -> list[str]:
    """
    Uses TruffleHog to scan a GitHub repository and pull JSON output
    Takes a URL string of the repo to scan, returns a list of findings in JSON format
    Relies on trufflehog being installed
    """
    # Use the correct command based on the OS
    if os.lower() == "windows" or os.lower() == "win":
        command = "trufflehog.exe"
    else:
        command = "trufflehog"

    # Run the command and capture the output
    result = subprocess.run(
        [
            command,
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


def scan_repos(repos: dict, max_workers: int, os: str) -> dict:
    """
    Concurrently loops through a dictionary of provided GitHub repos and scans them with trufflehog.
    Appends the results to the existing dictionary.
    Takes a dictionary of repos, and a max number of workers/threads to use.
    Outputs a dict with any potential findings.
    """

    # Using a ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_repo = {
            executor.submit(scan_repo_with_trufflehog, repo, os): repo for repo in repos
        }
        for future in tqdm(
            as_completed(future_to_repo), total=len(repos), desc="Scanning Repos"
        ):
            repo = future_to_repo[future]
            try:
                findings = future.result()
                if findings:
                    repos[repo][
                        "trufflehog_findings"
                    ] = findings  # Append results to the existing repo dict
                else:
                    repos[repo]["trufflehog_findings"] = {}  # Empty dict if no findings
            except Exception as exc:
                print(f"Error processing repo {repo}: {exc}")
                repos[repo][
                    "trufflehog_findings"
                ] = {}  # Append empty findings on error
    return repos


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def save_report(data: dict, filename: str) -> None:
    """
    Saves a dictionary to a JSON file.

    Args:
        data (dict): The dictionary to save.
        filename (str): The path to the JSON file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False, cls=CustomJSONEncoder)
        print(f"Dictionary saved to {filename}")
    except Exception as e:
        print(f"Error saving dictionary to JSON: {e}")


def fetch_github_readme(repo_url: str) -> str:
    """
    Fetches the README.md file from a GitHub repository URL.

    Args:
        repo_url (str): The URL of the GitHub repository (e.g., 'https://github.com/user/repo').

    Returns:
        str: The content of the README.md file, or a message if the file is not found.
    """
    # Extract the repository owner and name from the URL
    parts = repo_url.strip("/").split("/")
    if len(parts) < 2:
        return "Invalid repository URL."

    owner, repo_name = parts[-2], parts[-1]

    # Construct the raw content URL for the README.md file
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/main/README.md"

    try:
        response = requests.get(raw_url)
        response.raise_for_status()  # Check if the request was successful

        # If the request is successful, return the content of the README
        return response.text
    except requests.exceptions.HTTPError as http_err:
        return f"HTTP error occurred: {http_err}"
    except Exception as err:
        return f"An error occurred: {err}"


def get_whois_data(domain: str) -> dict:
    """
    Takes a single domain and returns the WHOIS data
    """
    try:
        whois_data = whois.whois(domain)
        return (domain, whois_data)
    except Exception as e:
        return (domain, "ERROR - MANUALLY VERIFY")


def fetch_whois_concurrently(initial_domains: list[str]) -> dict:
    """
    Takes a list of domains and concurrently generates a report including WHOIS data
    """
    domain_whois_report = {}

    with ThreadPoolExecutor(
        max_workers=3
    ) as executor:  # Hardcoding this as 3 because we're
        # Use tqdm to show progress
        futures = {
            executor.submit(get_whois_data, domain): domain
            for domain in initial_domains
        }

        # Use tqdm for the progress bar
        for future in tqdm(
            as_completed(futures), total=len(futures), desc="Fetching WHOIS data"
        ):
            domain, whois_data = future.result()
            domain_whois_report[domain] = whois_data

    return domain_whois_report
