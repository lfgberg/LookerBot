from argparse import Namespace
from utils import load_model, scan_repos
from config import Config, Secrets
from smolagents import CodeAgent
from tools import (
    GitHubSearchTool,
    VisitWebsiteTool,
    WhoIsTool,
    ExtractDomainsTool,
    BetterDuckDuckGoSearchTool,
)


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
            tools=[
                GitHubSearchTool(),
                VisitWebsiteTool(),
                BetterDuckDuckGoSearchTool(),
                WhoIsTool(),
                ExtractDomainsTool(),
            ],
            model=self.model,
            add_base_tools=True,
            additional_authorized_imports=["json"],
        )

    def run(self) -> dict:
        """
        Uses the agent to run various OSINT tasks, generating a dict report
        """

        report = {}
        domains = self._domain_osint()
        report["domains"] = domains
        report["github"] = self._github_osint(list(domains.keys()))

        return report

    def _domain_osint(self) -> dict:
        """
        Has the agent perform OSINT to discover domain names potentially owned by the target
        Applies a reasoning pass to filter the results with confidence levels
        """

        # Step 1: Collection - AI runs searches to find domains
        initial_domains = self.agent.run(
            f"""
        **Role & Context**  
        You are Looker, a highly skilled OSINT and cybersecurity expert employed by {self.args.target}. Your task is to discover and aggregate all domain names that may be owned or affiliated with {self.args.target}. These will be gathered through public search results, web scraping, and WHOIS records. Your goal is to produce a structured, verifiable report that can be reviewed by human analysts or reused in future automated analysis.

        **Task Description**  
        Use a multi-stage approach to discover candidate domains related to {self.args.target}:

        1. Use DuckDuckGo to find initial candidate websites and domains.  
        2. Visit these sites to extract additional linked or mentioned domains.  
        3. Run WHOIS lookups on all discovered domains.  
        4. Aggregate a structured final report that links each domain to its full WHOIS record.

        **Instructions & Guidelines**

        **Discovery Methodology:**

        - **Initial Domain Discovery via Search:**  
        Run targeted queries via `BetterDuckDuckGoSearchTool` to discover websites related to {self.args.target}. Parse all result URLs and extract domain names.
        You must be as thorough as possible with your search queries. Include more than just the provided examples to attempt to discover all possible domains.

        - **Web Content Analysis:**  
        Visit each domain and scan for additional domain mentions (in hyperlinks, text, and assets). Extract and collect all unique domains.

        - **WHOIS Lookup:**  
        For each discovered domain, retrieve WHOIS data using the `whois_lookup` tool.  
        Do not attempt to verify or match ownership—just aggregate the data.

        **Avoid Hallucination:**  

        - Do not invent or infer ownership.  
        - Only include domains discovered via search engine results or actual webpage content.  
        - Always fetch real WHOIS data—no mocking or simulating.

        **Output Format:**  
        The final report should be a Python dictionary:

        - **Keys** = discovered domain names (e.g., `example.com`)  
        - **Values** = WHOIS results as returned from the `whois_lookup` tool (raw text or structured string)

        ```python
        search_queries = [
            "{self.args.target} official website",
            "{self.args.target} domains",
            "{self.args.target} contact page",
            "{self.args.target} site",
            "{self.args.target} blog",
        ]

        initial_domains = set()

        # Step 1: DuckDuckGo search
        for query in search_queries:
            search_results = duckduckgo_search(query=query)
            initial_domains.update(extract_domains(text=search_results))

        # Step 2: Visit each domain and extract more
        all_discovered_domains = set(initial_domains)
        for domain in initial_domains:
            try:
                content = visit_website(url=f"http://{{domain}}")
                more_domains = extract_domains(text=content)
                all_discovered_domains.update(more_domains)
            except:
                continue

        # Step 3: WHOIS lookup
        domain_whois_report = {{}}
        for domain in all_discovered_domains:
            try:
                whois_data = whois_lookup(domain=domain)
                domain_whois_report[domain] = whois_data
            except:
                continue

        final_answer(domain_whois_report)
        ```
        """
        )

        # Step 2: Reasoning Pass - AI evaluates and filters domains
        final_report = {}
        initial_domains = dict(initial_domains)

        for domain, whois_data in initial_domains.items():
            confidence_assessment = self.agent.run(
                f"""
                **Role & Context**  
                You are Looker, a cybersecurity OSINT agent. You have received a dictionary of domains and their WHOIS records that were discovered in relation to {self.args.target}. Your job is to assess each domain and determine whether it is likely affiliated with the target organization.

                **Instructions**

                - For each domain, examine the WHOIS record and domain name.
                - YOU MUST EXAMINE EVERY DOMAIN PROVIDED TO YOU.
                - Based on registrant name, email, org name, prior knowledge, or other clues, determine if it appears to belong to {self.args.target}.
                - Assign a confidence flag:  
                - `"yes"` — clearly belongs to the target  
                - `"maybe"` — unclear but possible  
                - `"no"` — unrelated or belongs to someone else
                - Err on the side of caution when assigning a confidence flag. Anything flagged as maybe will be manually verified by another analyst, don't flag something as yes unless you are completely confident it belongs to or is affiliated with {self.args.target}

                **Avoid Hallucination**  
                - Only rely on WHOIS data and other clues. Do not invent data.
                - Use your web search and visit website tools to find more information about a domain if you're unsure of it's relation to {self.args.target}.
                - Do not use general assumptions (e.g., “.org domains are always nonprofits”).  
                - Use reasoning based on actual registrant data or domain naming.

                **Final Output Format**

                Return a Python dictionary with this structure:

                ```python
                result = {{
                    "example.com": {{
                        "confidence": "yes",
                        "whois": "<WHOIS RECORD>"
                    }},
                }}

                final_answer(result)
                ```

                - You must ensure you've included the entire provided whois record in the final report.

                Your input:
                ```python
                {{
                    "{domain}": {whois_data}
                }}
                ```
                """
            )

            # Pull the result - include if it's a yes or maybe
            try:
                confidence_assessment = dict(confidence_assessment)
                confidence = confidence_assessment[domain].get("confidence", "no")
                if confidence in ("yes", "maybe"):
                    final_report[domain] = {
                        "confidence": confidence,
                        "whois": whois_data,
                    }
            except Exception as e:
                final_report[domain] = {
                    "confidence": "ERROR - MANUALLY VERIFY",
                    "whois": whois_data,
                }
                print(f"Error: Failed to determine confidence level for {domain}")

        return final_report

    def _github_osint(self, domains: list[str]) -> dict:
        """
        Has the agent perform OSINT to discover GitHub repos
        Runs found repos through trufflehog
        """

        additional_info = ""

        if self.args.keywords or domains:
            context = ""
            if domains:
                context += (
                    f"- The known domains for {self.args.target} are {domains}.\n"
                )
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
            "{self.args.target}",
            "<verified_domain_or_keyword>",
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
        - The resulting format must be a list of urls as indicated in the example.

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
