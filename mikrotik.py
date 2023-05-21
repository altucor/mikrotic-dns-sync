import paramiko
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
