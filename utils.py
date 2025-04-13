from smolagents import OpenAIServerModel, HfApiModel, LiteLLMModel
from config import Config, Secrets
from typing import Union
import subprocess
import json
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
            "trufflehog_findings": [{finding1}, {finding2}]
        },
        "<REPO URL2>": {
            "trufflehog_findings": [{finding1}, {finding2}]
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
                    results[repo] = {"trufflehog_findings": findings}
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
