import requests
from smolagents import Tool


class GitHubSearchTool(Tool):
    def __init__(self, api_token):
        self.github_api_token = api_token

    # Smolagents tool info
    name = "github_search"
    description = """
    This is a tool that uses the GitHub API to submit a search. It returns the repositories which have results for the submitted query."""
    inputs = {
        "query": {
            "type": "string",
            "description": "The search query to submit to github (A dork such as 'filename:wp-config.php')",
        }
    }
    output_type = "string"

    def query_github(self, query: str):
        url = "https://api.github.com/search/code"

        headers = {
            "Authorization": f"Bearer {self.github_api_token}",  # Replace with your token
        }

        params = {"q": query}  # Number of results per page

        response = requests.get(url, headers=headers, params=params)

        return response

    def parse_response(self, response: requests.Response):
        results = response.json()
        output = []

        for item in results["items"]:
            output.append(
                [item["repository"]["full_name"], item["path"], item["html_url"]]
            )

        return output

    # The inference code to be executed
    def forward(self, query: str):
        response = self.query_github(query)
        results = self.parse_response(response)
        return results
