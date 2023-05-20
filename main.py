import sys
import yaml
import paramiko
import argparse
from argparse import RawTextHelpFormatter
import logging
import binascii


class DnsEntry:
    def __init__(self):
        self._keys = ["address", "name", "regexp", "disabled"]
        self._body = {}

    def __eq__(self, other):
        for key in self._keys:
            if (key in self._body and key not in other._body) or (
                key not in self._body and key in other._body
            ):
                return False
            if key in self._body and key in other._body:
                if self._body[key] != other._body[key]:
                    return False
        return True

    def __hash__(self):
        full_temp = ""
        for key in self._keys:
            if key not in self._body:
                continue
            full_temp += f"{key}{self._body[key]}"
        return binascii.crc32(full_temp.encode("utf-8"))

    def init_from_line(self, line):
        # line - add address=10.0.0.1 name=gateway.localnet
        # part - address=10.0.0.1
        for part in line.split(" "):
            if "=" not in part:
                continue
            kv = part.split("=")
            # kv = key value
            for key in self._keys:
                if kv[0] == key:
                    self._body[key] = kv[1]
                    break

    def to_command(self):
        cmd = "add "
        for key in self._keys:
            if key not in self._body:
                continue
            cmd += f"{key}={self._body[key]} "
        return cmd


class Mikrotik:
    def __init__(self, logger, host, port, username, password):
        self._logger = logger
        self._host = host
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._logger.log(logging.INFO, f"[ Mikrotik ] Connecting to {self._host}")
        self._client.connect(host, port, username, password, look_for_keys=False)
        self._logger.log(logging.INFO, f"[ Mikrotik ] Connected to {self._host}")

    def __del__(self):
        self._logger.log(
            logging.INFO, f"[ Mikrotik ] Closing connection with {self._host}"
        )
        self._client.close()

    def __eq__(self, other):
        return self.get_host() == other.get_host()

    def get_host(self):
        return self._host

    def run_command(self, cmd):
        stdin, stdout, stderr = self._client.exec_command(cmd)
        if stdout.channel.recv_exit_status() != 0:
            raise Exception("Error running command")
        return stdout.read().decode("utf-8")

    def get_dns_static(self):
        self._logger.log(
            logging.INFO, f"[ Mikrotik ] getting DNS static entries from {self._host}"
        )
        entries = set()
        response = self.run_command("/ip dns static export")
        if response is None or response == "":
            return entries
        for line in response.split("\r\n"):
            if not line.startswith("add"):
                continue
            entry = DnsEntry()
            entry.init_from_line(line)
            entries.add(entry)
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Got {len(entries)} DNS static entries from {self._host}",
        )
        return entries

    def add_dns_static_entry(self, dns_entry):
        # /ip dns static add name=test.test address=10.10.10.10
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Adding DNS static entry to {self._host} :: {dns_entry.to_command()}",
        )
        self.run_command(f"/ip dns static {dns_entry.to_command()}")
        self._logger.log(logging.INFO, f"[ Mikrotik ] Add OK")

    def add_missing_entries(self, entries):
        self._logger.log(
            logging.INFO, f"[ Mikrotik ] Adding DNS static entry list to {self._host}"
        )
        for entry in entries:
            self.add_dns_static_entry(entry)

    def remove_dns_static_entry(self, index):
        # /ip dns static remove numbers=1
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Removing DNS static entry from {self._host} :: index={index}",
        )
        self.run_command(f"/ip dns static remove numbers={index}")


class DnsDevice:
    def __init__(self, device, master, logger):
        self._logger = logger
        self._device = device
        self._master = master
        self._dns_static = self._device.get_dns_static()
        self._pending_updates = set()

    def device(self):
        return self._device

    def is_master(self):
        return self._master

    def dns_static(self):
        return self._dns_static

    def append_pending_updates(self, entry):
        self._pending_updates.add(entry)

    def update_pending_updates(self, diff):
        self._pending_updates.update(diff)

    def is_entry_in_pending_updates(self, entry):
        return entry in self._pending_updates

    def get_pending_updates(self):
        return self._pending_updates

    def print_pending_updates(self):
        for entry in self._pending_updates:
            self._logger.log(
                logging.INFO,
                f"Host {self._device.get_host()} Pending entry :: {entry.to_command()}",
            )


class Strategy:
    def __init__(self, logger, dns_devices):
        self._logger = logger
        self._dns_devices = dns_devices

    @staticmethod
    def name() -> str:
        raise NotImplementedError("Accessing abstract method of base class")

    @staticmethod
    def help() -> str:
        raise NotImplementedError("Accessing abstract method of base class")

    def analyze(self):
        raise NotImplementedError("Accessing abstract method of base class")

    def apply(self):
        for d in self._dns_devices:
            self._logger.log(
                logging.INFO,
                f"Applying missing DNS Static entries for {d.device().get_host()}",
            )
            d.device().add_missing_entries(d.get_pending_updates())
            self._logger.log(logging.INFO, "Done")


def find_master(dns_devices):
    master = None
    for d in dns_devices:
        if d.is_master():
            if master is not None:
                raise Exception("Cannot have several masters")
            master = d
    if master is None:
        raise Exception("Cannot find master router")
    return master


class MasterPropagationOnlyNew(Strategy):
    @staticmethod
    def name():
        return "master-propagation-only-new"

    @staticmethod
    def help() -> str:
        return "Analyzes all routers and only spread new entries which is exist on master but missing specific slave"

    def analyze(self):
        master = find_master(self._dns_devices)
        self._logger.log(
            logging.INFO, f"Found master router: {master.device().get_host()}"
        )

        for d in self._dns_devices:
            if d.is_master():
                continue
            diff = master.dns_static().difference(d.dns_static())
            d.update_pending_updates(diff)


class MasterFullMirror(Strategy):
    @staticmethod
    def name():
        return "master-full-mirror"

    @staticmethod
    def help() -> str:
        return "Adds and removes dns static entries on slaves to match master state"

    def analyze(self):
        master = find_master(self._dns_devices)
        self._logger.log(
            logging.INFO, f"Found master router: {master.device().get_host()}"
        )

        for d in self._dns_devices:
            if d.is_master():
                continue
            diff = master.dns_static().difference(d.dns_static())
            d.update_pending_updates(diff)


class Exchange(Strategy):
    @staticmethod
    def name():
        return "exchange"

    @staticmethod
    def help() -> str:
        return """Ignores master markers. Analyzes all static entries on routers.
        Does full exchange between routers by adding missing rules.
        Hint: Good for situations when you randomly add entries on different routers and then want to deploy them on all routers."""

    def analyze(self):
        for router_first in self._dns_devices:
            for router_second in self._dns_devices:
                if (
                    router_first.device().get_host()
                    == router_second.device().get_host()
                ):
                    continue
                diff = router_first.dns_static().difference(router_second.dns_static())
                router_second.update_pending_updates(diff)

                diff = router_second.dns_static().difference(router_first.dns_static())
                router_first.update_pending_updates(diff)


class VotedEntry:
    def __init__(self, entry, total_voters, votes=1):
        self._entry = entry
        self._total_voters = total_voters
        self._votes = votes

    def __hash__(self):
        return self._entry.__hash__()

    def vote(self):
        self._votes += 1

    def get_entry(self):
        return self._entry

    def get_percent(self):
        return round(self._votes * 100 / self._total_voters, 2)

    def get_info(self):
        return f"{self.get_percent()}% Votes for validity of {self._entry.to_command()}"


class Authoritative(Strategy):
    @staticmethod
    def name():
        return "authoritative"

    @staticmethod
    def help() -> str:
        return "By voting all routers decides who giving truth about actual state"

    def _collect_votes(self):
        voted_entries = dict()
        total_voters = len(self._dns_devices)
        for d in self._dns_devices:
            for dns_record in d.dns_static():
                if dns_record.__hash__() in voted_entries:
                    voted_entries[dns_record.__hash__()].vote()
                else:
                    voted_entries[dns_record.__hash__()] = VotedEntry(
                        dns_record, total_voters
                    )
        return voted_entries

    def analyze(self):
        voted_entries = self._collect_votes()
        for key in voted_entries:
            if voted_entries[key].get_percent() == 100:
                continue
            prefix = "[ AUTHORITATIVE DECLINED ]"
            voted_entries[key].get_info()
            if voted_entries[key].get_percent() >= 50:
                prefix = "[ AUTHORITATIVE APPROVED ]"
                entry = voted_entries[key].get_entry()
                for d in self._dns_devices:
                    if entry not in d.dns_static():
                        d.append_pending_updates(voted_entries[key].get_entry())
            self._logger.log(logging.INFO, f"{prefix} {voted_entries[key].get_info()}")


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
            r.print_pending_updates()

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

    # parser = ArgumentParser(description='test', formatter_class=RawTextHelpFormatter)
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
