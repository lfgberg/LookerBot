from dotenv import load_dotenv
import os
from config import Config, Secrets, load_config, parse_arguments
from agent import Agent
from utils import save_report


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

    # Run agent & save report
    looker = Agent(args, config, secrets)
    report = looker.run()
    save_report(config.outfile)


if __name__ == "__main__":
    main()
