import whois
import requests
import re
import markdownify
from smolagents import Tool
from urllib.parse import urlparse


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
            "Authorization": f"Bearer {secrets.github}",  # TODO - this is obnoxious
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
