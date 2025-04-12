from pydantic import BaseModel
import pathlib
import yaml
import re
import argparse


class HuggingFace(BaseModel):
    """HuggingFace API config class."""

    model_id: str


class GenericModel(BaseModel):
    """LiteLLM/OpenAI config class."""

    model_id: str
    api_base: str


class Config(BaseModel):
    """CLI config class."""

    hugging_face: HuggingFace
    lite_llm: GenericModel
    open_ai: GenericModel
    max_workers: int
    outfile: str


class Secrets(BaseModel):
    """Secrets class to hold API Keys"""

    github: str
    huggingface: str
    openai: str


def load_config(path: str) -> dict:
    """
    Used to load in a config file from YAML
    Returns a dict of the loaded YAML content
    """
    cwd = pathlib.Path(__file__).parent
    config_path = cwd / path

    try:
        return yaml.safe_load(config_path.read_text())
    except FileNotFoundError as error:
        message = "Error: yml config file not found."
        raise FileNotFoundError(error, message) from error


def _validate_arguments(args):
    """
    Used to validate CLI arguments
    Throws exceptions if not valid
    """
    modes = ["openai", "hf", "litellm"]
    comma_seperated_domains_pattern = r"^[^\s,]+(,[^\s,]+)*$"
    comma_seperated_keywords_pattern = r"^\s*[^,]+(\s*,\s*[^,]+)*\s*$"

    # Ensure the mode is a valid selection
    if args.mode.lower() not in modes:
        raise ValueError(
            f"Error: {args.mode} is not a valid mode. Mode must be one of f{modes}."
        )

    # Ensure domains are a comma seperated list
    if args.domains:
        if not bool(re.fullmatch(comma_seperated_domains_pattern, args.domains)):
            raise ValueError(
                f"Error: {args.domains} is not a valid comma seperated string of domains."
            )

    # Ensure keywords are a comma seperated list
    if args.keywords:
        if not bool(re.fullmatch(comma_seperated_keywords_pattern, args.keywords)):
            raise ValueError(
                f"Error: {args.domains} is not a valid comma seperated string of keywords."
            )


def parse_arguments():
    """
    Uses argparse to read CLI arguments and provide help
    Returns a set of arguments
    """
    parser = argparse.ArgumentParser(
        prog="LookerBot",
        description="An AI Agent to help perform OSINT.",
        epilog="My name... Ah, no. I shall inform you only of my code name. My code name, it is Looker. It is what they all call me.",
    )

    parser.add_argument(
        "mode",
        help="The mode to run in, options must be configured in config.yaml - choose one of: [OpenAI, HF, LiteLLM]",
        type=str,
    )
    parser.add_argument(
        "target",
        help="The target organization to perform OSINT on.",
        type=str,
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        help="Path to a config yaml file.",
        default="config.yaml",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--domains",
        dest="domains",
        help="A comma seperated list of domain names for the target organization.",
        type=str,
    )
    parser.add_argument(
        "-k",
        "--keywords",
        dest="keywords",
        help="A comma seperated list of keywords related to the target organization.",
        type=str,
    )

    args = parser.parse_args()

    _validate_arguments(args)

    return args
