import sys
import yaml
import paramiko

class DnsEntry:
    def __init__(self):
        self._keys = ["address", "name", "regexp", "disabled"]
        self._body = {}

    def __eq__(self, other):
        for key in self._keys:
            if (key in self._body and key not in other._body) or (key not in self._body and key in other._body):
                return False
            if key in self._body and key in other._body:
                if self._body[key] != other._body[key]:
                    return False
        return True

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

    def dbg(self):
        print(self.to_command())
        # print(f"address={self._address} name={self._name} regexp={self._regexp} disabled={self._disabled}")


class Mikrotik:
    def __init__(self, host, port, username, password):
        self._host = host
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(host, port, username, password, look_for_keys=False)

    def __del__(self):
        self._client.close()

    def get_host(self):
        return self._host

    def run_command(self, cmd):
        stdin, stdout, stderr = self._client.exec_command(cmd)
        if stdout.channel.recv_exit_status() != 0:
            raise Exception("Error running command")
        return stdout.read().decode('utf-8')

    def get_dns_static(self):
        entries = []
        response = self.run_command("/ip dns static export")
        if response is None or response == "":
            return entries
        for line in response.split("\r\n"):
            if not line.startswith("add"):
                continue
            entry = DnsEntry()
            entry.init_from_line(line)
            # entry.dbg()
            entries.append(entry)
        return entries

    def add_dns_static_entry(self, dns_entry):
        # /ip dns static add name=test.test address=10.10.10.10
        self.run_command(f"/ip dns static {dns_entry.to_command()}")

    def add_missing_entries(self, entries):
        for entry in entries:
            self.add_dns_static_entry(entry)

    def remove_dns_static_entry(self, index):
        # /ip dns static remove numbers=1
        self.run_command(f"/ip dns static {index}")


class DnsManager:
    def __init__(self):
        self._routers = []

    def add_router(self, router, master=False):
        obj = {}
        obj["router"] = router
        obj["master"] = master
        obj["dns_static"] = router.get_dns_static()
        obj["missing_dns_static"] = []
        self._routers.append(obj)

    def _get_missing_for_router(self, router):
        for entry in router["missing_dns_static"]:
            print(f'Host {router["router"].get_host()} Missing entry :: {entry.to_command()}')

    def get_missing_for_host(self, host):
        if host is None or host == "":
            print("Empty host specified")
            return
        for r in self._routers:
            if r["router"].get_host() == host:
                self._get_missing_for_router(r)

    def get_missing_for_all_routers(self):
        for r in self._routers:
            self._get_missing_for_router(r)

    def apply_missing(self):
        for r in self._routers:
            print(f'Applying missing DNS Static entries for {r["router"].get_host()}')
            r["router"].add_missing_entries(r["missing_dns_static"])
            print("Done")


    def sync_push_from_master(self):
        master = None
        for r in self._routers:
            if r["master"]:
                if master is not None:
                    raise Exception("Cannot have several masters")
                master = r
        if master is None:
            raise Exception("Cannot find master router")

        for r in self._routers:
            if r["master"]:
                continue
            slave_config = r["dns_static"]
            for master_entry in master["dns_static"]:
                if master_entry not in slave_config:
                    print(f'Adding missing entry from master to slave {master["router"].get_host()} => {r["router"].get_host()} :: {master_entry.to_command()}')
                    r["missing_dns_static"].append(master_entry)

    def sync_exchange_all(self):
        for router_first in self._routers:
            for entry_first in router_first["dns_static"]:
                for router_second in self._routers:
                    if router_first["router"].get_host() == router_second["router"].get_host():
                        continue
                    if entry_first not in router_second["dns_static"]:
                        print(f'Adding missing entry from master to slave {router_first["router"].get_host()} => {router_second["router"].get_host()} :: {entry_first.to_command()}')
                        router_second["missing_dns_static"].append(entry_first)


def main():
    if len(sys.argv) != 2:
        print("Error need to specify path to yaml config file")
        return
    yaml_config = None
    with open(sys.argv[1], "r") as stream:
        try:
            yaml_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    manager = DnsManager()
    for key, r in yaml_config["routers"].items():
        master = False
        if "master" in r:
            master = r["master"]
        manager.add_router(Mikrotik(r["host"], r["port"], r["username"], r["password"]), master)
    # manager.sync_push_from_master()
    manager.sync_exchange_all()
    manager.get_missing_for_all_routers()
    manager.apply_missing()
    print("end app")

if __name__ == "__main__":
    main()
