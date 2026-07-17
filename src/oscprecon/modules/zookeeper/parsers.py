from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ZookeeperFinding:
    kind: str  # access | version | mode | znodes | note
    value: str
    detail: str = ""
    module: str = "zookeeper"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# nmap -sV names the service "zookeeper" on 2181 and, when it can, appends "Zookeeper <version>".
_NMAP_LINE = re.compile(
    r"^\s*\d+/tcp\s+open\s+zookeeper\b(?:.*?zookeeper\s+([\w.\-]+))?", re.IGNORECASE
)


def parse_nmap_zookeeper(text: str) -> list[ZookeeperFinding]:
    out: list[ZookeeperFinding] = []
    for line in text.splitlines():
        match = _NMAP_LINE.search(line)
        if match:
            out.append(ZookeeperFinding("access", "reachable", "ZooKeeper 2181 open"))
            if match.group(1):
                out.append(ZookeeperFinding("version", match.group(1), "from nmap -sV"))
            break
    return out


# 4lw output over nc — `mntr` prints `zk_<key>\t<value>` lines; `stat` prints a
# "Zookeeper version: 3.4.6" header + "Mode: standalone". All unauthenticated + read-only.
_MNTR = re.compile(r"^\s*zk_([a-z_]+)\s+(.+?)\s*$")
_STAT_VERSION = re.compile(r"zookeeper version:\s*([\w.\-]+)", re.IGNORECASE)
_STAT_MODE = re.compile(r"^\s*Mode:\s*(\w+)", re.IGNORECASE)


def parse_zk_4lw(text: str) -> list[ZookeeperFinding]:
    out: list[ZookeeperFinding] = []
    saw = False
    for line in text.splitlines():
        mntr = _MNTR.match(line)
        if mntr:
            saw = True
            key, value = mntr.group(1), mntr.group(2)
            if key == "version":
                out.append(ZookeeperFinding("version", value.split("-")[0], "from mntr"))
            elif key == "server_state":
                out.append(ZookeeperFinding("mode", value, "from mntr"))
            elif key == "znode_count":
                out.append(ZookeeperFinding("znodes", value, "from mntr"))
            continue
        stat_v = _STAT_VERSION.search(line)
        if stat_v:
            saw = True
            out.append(ZookeeperFinding("version", stat_v.group(1), "from stat"))
        stat_m = _STAT_MODE.match(line)
        if stat_m:
            saw = True
            out.append(ZookeeperFinding("mode", stat_m.group(1), "from stat"))
    if saw:
        out.insert(0, ZookeeperFinding("access", "unauth", "4lw answered without auth"))
    return out


_PARSERS = {"nmap-zookeeper": parse_nmap_zookeeper, "zk-4lw": parse_zk_4lw}


def parse_zookeeper_tool(tool: str, text: str) -> list[ZookeeperFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
