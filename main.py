import sys
import yaml
import argparse
from argparse import RawTextHelpFormatter
import logging
from mikrotik import DnsDevice, Mikrotik
from strategy import (
    MasterPropagationOnlyNew,
    MasterFullMirror,
    Exchange,
    Authoritative,
)


class DnsManager:
    def __init__(self, logger, strategy):
        self._logger = logger
        self._dns_devices = []
        self._strategy = strategy(self._logger, self._dns_devices)

    def analyze(self):
        self._strategy.analyze()

    def add_router(self, router, master=False):
        d = DnsDevice(router, master, self._logger)
        self._dns_devices.append(d)

    def print_pending_for_all_routers(self):
        self._logger.log(
            logging.INFO, f"List of rules which should be executed after analysis"
        )
        for r in self._dns_devices:
            r.print_pending_changes()

    def apply_pending(self):
        self._strategy.apply()


desc = """
Simple python script which can sync DNS Static entries between several MikroTik\'s.\n
Allows different sync modes like:\n
    1) master - Where config from master deployed to all other slave routers.
    2) exchange - Get DNS entries from all routers, analyze them to determine 
        missing ones and synchronize them between all routers to fully identical 
        lists by extending lists

"""


def get_logger():
    logger = logging.getLogger("mikrotik-dns-sync")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d :: %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def main():
    logger = get_logger()
    logger.log(logging.INFO, "Start")

    strategies = [
        MasterPropagationOnlyNew,
        MasterFullMirror,
        Exchange,
        Authoritative,
    ]

    strategy_help = ""
    for s in strategies:
        strategy_help += f"* {s.name()} - {s.help()}\n"

    parser = argparse.ArgumentParser(
        prog="mikrotik-dns-sync",
        description=desc,
        epilog="ALTUCOR @ 2023",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument("--config", required=True, help="path to yaml config file")
    parser.add_argument(
        "--strategy",
        required=True,
        help="algorithm of detecting and exchanging of missing entries.\n"
        + strategy_help,
    )
    parser.add_argument(
        "--show_diff",
        action="store_true",
        help="show calculated missing rules for each router, which can be applyied",
    )
    parser.add_argument(
        "--apply_pending",
        action="store_true",
        help="apply calculated pending rules on the remote routers",
    )
    args = parser.parse_args()

    if args.strategy is None:
        parser.error("strategy argument is not set")

    strategies = [
        MasterPropagationOnlyNew,
        MasterFullMirror,
        Exchange,
        Authoritative,
    ]

    chosen_strategy = None
    for s in strategies:
        if args.strategy == s.name():
            chosen_strategy = s

    if chosen_strategy is None:
        parser.error("Unknown strategy")

    yaml_config = None
    with open(args.config, "r") as stream:
        try:
            yaml_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logger.log(logging.CRITICAL, exc)

    manager = DnsManager(logger, chosen_strategy)
    for _, r in yaml_config["routers"].items():
        master = False
        if "master" in r:
            master = r["master"]
        manager.add_router(
            Mikrotik(logger, r["host"], r["port"], r["username"], r["password"]), master
        )
    manager.analyze()
    if args.show_diff:
        manager.print_pending_for_all_routers()
    if args.apply_pending:
        manager.apply_pending()
    logger.log(logging.INFO, "Finish")


if __name__ == "__main__":
    main()
