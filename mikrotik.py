import paramiko
import logging
from dns_entry import DnsEntry


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

    def run_command_str(self, cmd):
        stdin, stdout, stderr = self._client.exec_command(cmd)
        if stdout.channel.recv_exit_status() != 0:
            error_text = stdout.read().decode("utf-8")
            raise Exception(f"Error running command: {error_text}")
        return stdout.read().decode("utf-8")

    def get_dns_static(self):
        self._logger.log(
            logging.INFO, f"[ Mikrotik ] getting DNS static entries from {self._host}"
        )
        entries = list()
        response = self.run_command_str("/ip dns static export")
        if response is None or response == "":
            return entries
        for line in response.split("\r\n"):
            if not line.startswith("add"):
                continue
            entry = DnsEntry()
            entry.init_from_line(line)
            entries.append(entry)
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Got {len(entries)} DNS static entries from {self._host}",
        )
        return entries

    def add_dns_static_entry(self, dns_entry: DnsEntry):
        # /ip dns static add name=test.test address=10.10.10.10
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Adding DNS static entry to {self._host} :: {dns_entry.to_command()}",
        )
        self.run_command_str(f"/ip dns static add {dns_entry.to_command()}")
        self._logger.log(logging.INFO, f"[ Mikrotik ] Add OK")

    def add_missing_entries(self, entries):
        self._logger.log(
            logging.INFO, f"[ Mikrotik ] Adding DNS static entry list to {self._host}"
        )
        for entry in entries:
            self.add_dns_static_entry(entry)

    def remove_dns_static_entries(self, indexes):
        # /ip dns static remove numbers=1,2,3
        indexes_cmd_part = "".join("{:d},".format(i) for i in indexes)[:-1]
        self._logger.log(
            logging.INFO,
            f"[ Mikrotik ] Removing DNS static entry from {self._host} :: indexes={indexes_cmd_part}",
        )
        self.run_command_str(f"/ip dns static remove numbers={indexes_cmd_part}")

    def find_and_remove_static_entries(self, entries):
        static = self.get_dns_static()
        indexes = []
        for item in entries:
            indexes.append(static.index(item))
        if len(indexes) == 0:
            return
        for i in indexes:
            self._logger.log(
                logging.INFO,
                f"[ Mikrotik ] Removing DNS static entry from {self._host} :: {i} = {static[i].to_command()}",
            )
        self.remove_dns_static_entries(indexes)


class DnsDevice:
    def __init__(self, device, master, logger):
        self._logger = logger
        self._device = device
        self._master = master
        self._dns_static = set(self._device.get_dns_static())
        self.pending_add = set()
        self.pending_del = set()

    def device(self):
        return self._device

    def is_master(self):
        return self._master

    def dns_static(self):
        return self._dns_static

    def print_pending_changes(self):
        for entry in self.pending_add:
            self._logger.log(
                logging.INFO,
                f"Host {self._device.get_host()} Pending ADD entry :: {entry.to_command()}",
            )
        for entry in self.pending_del:
            self._logger.log(
                logging.INFO,
                f"Host {self._device.get_host()} Pending DEL entry :: {entry.to_command()}",
            )
