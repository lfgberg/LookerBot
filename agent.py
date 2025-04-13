from argparse import Namespace
from utils import load_model, scan_repos
from config import Config, Secrets
from smolagents import (
    OpenAIServerModel,
    HfApiModel,
    LiteLLMModel,
    CodeAgent,
    DuckDuckGoSearchTool,
)
from tools import GitHubSearchTool, VisitWebsiteTool


# TODO: This should use pydantic
class Agent:
    """SmolAgent for LookerBot."""

    def __init__(self, args: Namespace, config: Config, secrets: Secrets):
        # Assign attributes
        self.model = load_model(
            args.mode, config, secrets
        )  # Load the appropriate model based on the mode
        self.args = args
        self.config = config
        self.secrets = secrets

        # Create the agent with the created model
        self.agent = CodeAgent(
            tools=[GitHubSearchTool(), VisitWebsiteTool(), DuckDuckGoSearchTool()],
            model=self.model,
            add_base_tools=True,
            additional_authorized_imports=["json"],
        )

    def run(self) -> dict:
        """
        Uses the agent to run various OSINT tasks, generating a dict report
        """

        report = {}
        report["github"] = self._github_osint()

        return report

    def _domain_osint(self) -> dict:
        """
        Has the agent perform OSINT to discover domain names potentially owned by the target
        """

        result = self.agent.run()

    def _github_osint(self) -> dict:
        """
        Has the agent perform OSINT to discover GitHub repos
        Runs found repos through trufflehog
        """

        additional_info = ""

        if self.args.keywords or self.args.domains:
            context = ""
            if self.args.domains:
                context += f"- The known domains for {self.args.target} are {self.args.domains}.\n"
            if self.args.keywords:
                context += f"- Some additional search keywords for {self.args.target} are {self.args.keywords}.\n"

            additional_info = f"""
            **Additional Context:**
            {context}
            - You must search for each of these domains/keywords as you do your OSINT collection. Use each individual domain and keyword to search across all intelligence sources.
            """

        # Collect repositories owned by the org
        repos = self.agent.run(
            f"""
        **Role & Context**
        You are Looker, a highly skilled OSINT and cybersecurity expert employed by {self.args.target}. Your duty is to audit the operational security of {self.args.target} by gathering comprehensive OSINT, especially by identifying all GitHub repositories that potentially belong to this organization. Your findings should contribute to preventing vulnerabilities that could lead to security breaches, thereby maximizing profit and ensuring operational security.

        **Task Description**
        Your primary task is to search for GitHub repositories that are owned by or affiliated with {self.args.target}. Use GitHub dorks and custom search queries based on keywords that are tightly related to {self.args.target}—this should include the organization’s name, its key domain names, and any additional context provided (e.g., relevant product names, acronyms, or subsidiaries). Do not use generic or unrelated keywords (e.g., "healthcare") and do not generate or simulate fake results.

        **Instructions & Guidelines**

        **Keyword and Domain Identification:**

        - If the target’s domain names are unknown, use appropriate tools to look them up and verify them before including them in your searches.
        - Tailor all search queries specifically to {self.args.target} using verified keywords and domain names.
        - If additional context (such as extra keywords or verified alternate domain names) is provided, incorporate those explicitly.

        **Search Methodology:**

        - Craft diverse search queries (dorks) to explore various angles (e.g., by repository name patterns, mentions in README files, or special configurations) that are likely to point to repositories owned by {self.args.target}.
        - Ensure that each query is self-contained and clearly references {self.args.target} (e.g., “{self.args.target} AND <DOMAIN>”, "<DOMAIN>", "{self.args.target}").
        - You must be as thorough as possible with your searches. You must uncover all repositories potentially belonging to {self.args.target} by performing as many targeted queries as you can come up with.

        **Avoid Hallucination:**

        - Do not generate example repository names or domain names if not confirmed. Only use verified data from tool lookups.
        - Validate each keyword and domain used from trusted resources before including it in the search queries.

        **Use of Tools:**

        - Explicitly call your search tools (such as GitHub search APIs or custom dorking tools) and include a process to log or reference your methodology.
        - Aggregate all found results into a final report. The final result format should be a unified list that includes the repository links and a brief comment on the relevance (if applicable).

        **Output Structure:**

        Aggregate the findings clearly in the following structure:

        ```py
        # Define an array of search queries, each tailored to {self.args.target} with verified keywords or domains.
        queries = [
            "{self.args.target} AND <verified_domain_or_keyword>",
            "{self.args.target} AND <additional_verified_keyword>",
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

        - Before finalizing your output, double-check that all search queries are tailored uniquely to {self.args.target}.
        - Make sure that no generic information is included in the final output.
        - If any query results in ambiguous or unrelated data, document this and focus only on confirmed findings.
            """
        )

        # TODO: Have a second run of the ai examine the readmes of the repositories and remove anything that doesn't seem related to the target

        # Run trufflehog on each one to find secrets
        github_findings = scan_repos(repos, self.config.max_workers, self.config.os)

        return github_findings
