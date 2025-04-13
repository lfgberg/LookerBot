from config import Config, Secrets, load_config, parse_arguments
from agent import Agent
from utils import save_report


def main():
    # Setup
    args = parse_arguments()
    config = Config(**load_config(args.config))
    secrets = Secrets()

    # Run agent & save report
    looker = Agent(args, config, secrets)
    report = looker.run()
    save_report(report, config.outfile)


if __name__ == "__main__":
    main()
