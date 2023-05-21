import logging


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
