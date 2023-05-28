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
        cmd = ""
        for key in self._keys:
            if key not in self._body:
                continue
            cmd += f"{key}={self._body[key]} "
        return cmd
