# LookerBot

LookerBot is a project that leverages AI Agents to perform OSINT collection on a target organization that's built using [HuggingFace's Smolagents](https://github.com/huggingface/smolagents) library.

## Features

- Domain recon
  - Uses DuckDuckGo searches & WHOIS records to identify domains associated with a target organization
- GitHub recon
  - Uses the GitHub search API to identify repositories attributed to a target organization
  - [TruffleHog](https://github.com/trufflesecurity/trufflehog) Integration for secret identification & verification
- DuckDuckGo recon
  - Uses DuckDuckGo search queries to identify login pages, documents, etc. from identified domains
- Result verification
  - Assigns a confidence score to each Result
  - Removes results that are confidently not associated with the target
  - Provides reasoning as to why a confidence score was assigned

## Installation

1. Create a Python virtual environment, you may want to use [uv](https://github.com/astral-sh/uv) to manage your environments.
2. Install the Python dependencies

```bash
pip install -r requirements.txt
```

3. [Install TruffleHog](https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation) - If on windows just place the binary within the LookerBot folder

## Configuration

1. Create a [GitHub personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) with no permissions
2. Copy `.sample.env` to `.env` - and paste your GitHub PAT
3. If using OpenAI, HuggingFace, or another API to interact with your LLM, include your API key in `.env`
4. Configure your operating system, max workers, etc. in `config.yaml`

## Usage/Examples

```bash
main.py openai "Tesla"
main.py litellm "Penn State"
main.py hf "Minitab"
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
