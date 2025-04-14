import random
import time
import whois
import requests
import re
import markdownify
from smolagents import Tool
from urllib.parse import urlparse
from config import Secrets
from typing import Optional

secrets = Secrets()


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
    output_type = "array"

    # The inference code to be executed
    def forward(self, text: str) -> set:
        # Regex to match URLs (http, https, or www-based)
        url_pattern = re.compile(
            r'https?://[^\s)"\'<>]+|www\.[^\s)"\'<>]+', re.IGNORECASE
        )

        # Find all URL-like strings
        urls = re.findall(url_pattern, text)

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


# TODO: consider grep.app?
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


class BetterDuckDuckGoSearchTool(Tool):
    name = "duckduckgo_search"
    description = """Performs a DuckDuckGo web search based on your query (like Google search) and returns the top search results."""
    inputs = {
        "query": {"type": "string", "description": "The search query to perform."}
    }
    output_type = "string"

    def __init__(
        self,
        max_results: int = 10,
        min_delay: float = 1.0,
        max_delay: float = 3.0,
        retries: int = 3,
        **kwargs,
    ):
        super().__init__()
        self.max_results = max_results
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.retries = retries

        try:
            from duckduckgo_search import DDGS
        except ImportError as e:
            raise ImportError(
                "You must install the `duckduckgo_search` package. Run `pip install duckduckgo-search`."
            ) from e

        self.DDGS = DDGS
        self.kwargs = kwargs

    def _delay(self):
        time.sleep(random.uniform(self.min_delay, self.max_delay))

    def _rotate_user_agent(self) -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1",
        ]
        return random.choice(user_agents)

    def forward(self, query: str) -> str:
        last_exception: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                self._delay()
                with self.DDGS(
                    headers={"User-Agent": self._rotate_user_agent()}, **self.kwargs
                ) as ddgs:
                    results = ddgs.text(query, max_results=self.max_results)
                if not results:
                    raise Exception(
                        "No results found! Try a less restrictive/shorter query."
                    )
                postprocessed = [
                    f"[{r['title']}]({r['href']})\n{r['body']}" for r in results
                ]
                return "## Search Results\n\n" + "\n\n".join(postprocessed)
            except Exception as e:
                last_exception = e
                self._delay()
        raise Exception(f"Failed after {self.retries} attempts: {last_exception}")
