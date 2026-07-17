from pathlib import Path

from oscprecon import findings as findings_mod
from oscprecon.graph_data import build_elements
from oscprecon.models import Credential, DiscoveredHost, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def test_pivot_topology_builds_subnets_hosts_and_pivot_edges(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.set_services([DiscoveredService(80, Proto.TCP, "http")])
    prof.add_hosts(
        [
            DiscoveredHost(
                ip="10.10.5.23",
                pivot_source="10.10.10.5",
                services=[DiscoveredService(445, Proto.TCP, "smb")],
            ),
            DiscoveredHost(ip="10.10.5.40", pivot_source="10.10.10.5"),
            DiscoveredHost(
                ip="172.16.8.10",
                pivot_source="10.10.5.23",  # a deeper pivot, reached THROUGH .23
                services=[DiscoveredService(3389, Proto.TCP, "rdp")],
            ),
        ]
    )
    els = build_elements(prof)
    by_id = {n["data"]["id"]: n["data"] for n in els["nodes"]}
    edge_pairs = {
        (e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in els["edges"]
    }
    # /24 chips are plain nodes; hosts declare their /24 via subnetId + a contains-host line
    assert by_id["subnet-10.10.5.0/24"]["type"] == "subnet"
    assert by_id["subnet-172.16.8.0/24"]["type"] == "subnet"
    assert by_id["host-10.10.5.23"]["subnetId"] == "subnet-10.10.5.0/24"
    assert by_id["host-172.16.8.10"]["subnetId"] == "subnet-172.16.8.0/24"
    assert ("subnet-10.10.5.0/24", "host-10.10.5.23", "contains-host") in edge_pairs
    # host services hang off the host by a has-service line, not off the entry target
    assert by_id["hostservice-10.10.5.23-445-tcp"]["type"] == "service"
    hs_edge = next(
        e for e in els["edges"] if e["data"]["target"] == "hostservice-10.10.5.23-445-tcp"
    )
    assert hs_edge["data"]["source"] == "host-10.10.5.23"
    # the chained spider-web: entry -> first subnet, and .23 -> the deeper subnet
    pivots = {
        (e["data"]["source"], e["data"]["target"])
        for e in els["edges"]
        if e["data"]["type"] == "pivots-into"
    }
    assert ("target", "subnet-10.10.5.0/24") in pivots
    assert ("host-10.10.5.23", "subnet-172.16.8.0/24") in pivots


def test_drilldown_data_child_counts_and_service_owner(tmp_path: Path) -> None:
    # the JS drill-down needs: subnet.childCount (# hosts) + host.childCount (# services) for the
    # collapsed-chip labels, and each host-service.owner (its host id) to hide/show per host.
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.add_hosts(
        [
            DiscoveredHost(
                ip="10.10.5.23",
                pivot_source="10.10.10.5",
                services=[
                    DiscoveredService(445, Proto.TCP, "smb"),
                    DiscoveredService(80, Proto.TCP, "http"),
                ],
            ),
            DiscoveredHost(ip="10.10.5.40", pivot_source="10.10.10.5"),
        ]
    )
    by_id = {n["data"]["id"]: n["data"] for n in build_elements(prof)["nodes"]}
    assert by_id["subnet-10.10.5.0/24"]["childCount"] == 2  # two hosts in the /24
    assert by_id["host-10.10.5.23"]["childCount"] == 2  # two services on this host
    assert by_id["host-10.10.5.40"]["childCount"] == 0  # no services yet
    assert by_id["hostservice-10.10.5.23-445-tcp"]["owner"] == "host-10.10.5.23"


def test_target_and_host_nodes_carry_os_for_glyphs(tmp_path: Path) -> None:
    # the OS corner-glyph reads node data("os"); target + pivoted hosts must both carry it
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.0.0.1", os_guess="Windows"))
    prof.add_hosts([DiscoveredHost(ip="10.10.5.40", os_guess="Ubuntu 20.04")])
    by_id = {n["data"]["id"]: n["data"] for n in build_elements(prof)["nodes"]}
    assert by_id["target"]["os"] == "Windows"
    assert by_id["host-10.10.5.40"]["os"] == "Ubuntu 20.04"


def test_entry_reachable_subnet_wires_to_target(tmp_path: Path) -> None:
    # a host with pivot_source="" (entry-reachable, the documented-normal state) must wire its /24
    # to the target: via="target" so it folds when the entry collapses, plus a target->subnet edge
    # so it is connected (breadthfirst can place it; it never floats).
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.add_hosts([DiscoveredHost(ip="172.16.1.5")])  # pivot_source="" by default
    els = build_elements(prof)
    by_id = {n["data"]["id"]: n["data"] for n in els["nodes"]}
    assert by_id["subnet-172.16.1.0/24"]["via"] == "target"
    pivots = {
        (e["data"]["source"], e["data"]["target"])
        for e in els["edges"]
        if e["data"]["type"] == "pivots-into"
    }
    assert ("target", "subnet-172.16.1.0/24") in pivots


def test_pivot_edge_skipped_when_source_host_unknown(tmp_path: Path) -> None:
    # a pivot_source that isn't the target and isn't a known host must not create a dangling edge
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.add_hosts([DiscoveredHost(ip="10.10.5.23", pivot_source="10.9.9.9")])
    els = build_elements(prof)
    assert not [e for e in els["edges"] if e["data"]["type"] == "pivots-into"]


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "htb-active", Target(ip="10.10.10.100", hostname="active.htb"))
    prof.set_services(
        [
            DiscoveredService(445, Proto.TCP, "microsoft-ds"),
            DiscoveredService(161, Proto.UDP, "snmp"),
        ]
    )
    findings_mod.add_findings(
        prof.directory,
        [
            {
                "module": "smb",
                "kind": "share",
                "value": "SYSVOL",
                "detail": "readable",
                "discovered_at": "t",
            },
            {
                "module": "snmp",
                "kind": "community",
                "value": "public",
                "detail": "",
                "discovered_at": "t",
            },
        ],
    )
    prof.add_credential(
        Credential(
            username="svc", secret="Sup3rSecret", domain="active.htb", source="smb-anon-enum"
        )
    )
    return prof


def test_build_elements_structure(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    by_id = {n["data"]["id"]: n for n in els["nodes"]}
    assert by_id["target"]["data"]["type"] == "target"
    assert by_id["target"]["data"]["label"] == "10.10.10.100\nactive.htb"
    assert by_id["service-445-tcp"]["data"]["proto"] == "tcp"
    assert by_id["service-161-udp"]["data"]["proto"] == "udp"
    has = {
        (e["data"]["source"], e["data"]["target"])
        for e in els["edges"]
        if e["data"]["type"] == "has-service"
    }
    assert ("target", "service-445-tcp") in has
    assert ("target", "service-161-udp") in has


def test_findings_link_to_owning_service(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    finds = [n for n in els["nodes"] if n["data"]["type"] == "finding"]
    assert "share: SYSVOL" in {n["data"]["label"] for n in finds}
    smb_fid = next(n["data"]["id"] for n in finds if n["data"]["module"] == "smb")
    smb_edge = next(
        e
        for e in els["edges"]
        if e["data"]["target"] == smb_fid and e["data"]["type"] == "exposes-finding"
    )
    assert smb_edge["data"]["source"] == "service-445-tcp"  # module -> owning service
    snmp_fid = next(n["data"]["id"] for n in finds if n["data"]["module"] == "snmp")
    snmp_edge = next(e for e in els["edges"] if e["data"]["target"] == snmp_fid)
    assert snmp_edge["data"]["source"] == "service-161-udp"


def test_credential_is_redacted(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    cred = next(n for n in els["nodes"] if n["data"]["type"] == "credential")
    assert cred["data"]["label"] == "svc@active.htb"
    assert cred["data"]["secret"] == "<redacted len=11>"
    assert "Sup3rSecret" not in str(els)  # the secret never reaches the graph


def test_graph_overrides_and_user_edges(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.save_graph(
        {
            "user_edges": [
                {"from": "cred-0", "to": "service-445-tcp", "label": "found here"},
                {"from": "cred-0", "to": "service-999-nope"},  # dangling endpoint -> dropped
            ],
            "node_overrides": {
                "service-445-tcp": {
                    "status": "investigating",
                    "note": "weird shares",
                    "position": [320, 180],
                }
            },
        }
    )
    els = build_elements(prof)
    svc = next(n for n in els["nodes"] if n["data"]["id"] == "service-445-tcp")
    assert svc["data"]["status"] == "investigating"
    assert svc["data"]["note"] == "weird shares"
    assert svc["position"] == {"x": 320, "y": 180}
    relates = [e for e in els["edges"] if e["data"]["type"] == "relates-to"]
    assert len(relates) == 1  # the dangling edge is filtered out
    assert relates[0]["data"]["label"] == "found here"


def test_invalid_status_is_ignored(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.save_graph({"node_overrides": {"target": {"status": "bogus"}}})
    target = next(n for n in build_elements(prof)["nodes"] if n["data"]["id"] == "target")
    assert "status" not in target["data"]  # only new/investigating/done/dead-end are accepted


def test_load_graph_coerces_wrong_typed_fields(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    # a hand-edited graph.json with swapped container types must not reach the GraphBridge write
    # path (which indexes user_edges as a list / node_overrides as a dict) — load_graph coerces.
    prof.graph_path.write_text('{"user_edges": {}, "node_overrides": []}', encoding="utf-8")
    graph = prof.load_graph()
    assert graph["user_edges"] == []
    assert graph["node_overrides"] == {}


def test_profile_graph_persistence_roundtrip(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    assert prof.load_graph() == {"user_edges": [], "node_overrides": {}}  # default when absent
    prof.save_graph(
        {"user_edges": [{"from": "a", "to": "b"}], "node_overrides": {"a": {"status": "done"}}}
    )
    reloaded = prof.load_graph()
    assert reloaded["user_edges"] == [{"from": "a", "to": "b"}]
    assert reloaded["node_overrides"]["a"]["status"] == "done"


def test_notable_findings_are_flagged(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.set_services([DiscoveredService(445, Proto.TCP, "microsoft-ds")])
    findings_mod.add_findings(
        prof.directory,
        [
            {"module": "smb", "kind": "signing", "value": "disabled", "discovered_at": "t"},
            {"module": "ftp", "kind": "auth", "value": "anonymous", "discovered_at": "t"},
            {
                "module": "smb",
                "kind": "share",
                "value": "IT",
                "detail": "READ",
                "discovered_at": "t",
            },
            {"module": "smb", "kind": "user", "value": "administrator", "discovered_at": "t"},
        ],
    )
    finds = {
        n["data"]["label"]: n["data"]
        for n in build_elements(prof)["nodes"]
        if n["data"]["type"] == "finding"
    }
    assert finds["signing: disabled"].get("notable") is True  # weak signing highlighted
    assert finds["auth: anonymous"].get("notable") is True  # anon access highlighted
    assert "notable" not in finds["share: IT"]  # a readable share is not itself "notable"
    assert "notable" not in finds["user: administrator"]  # a username is not notable
    # every finding node carries a conservative category from the centralized classifier
    assert finds["signing: disabled"]["category"] == "relay-risk"
    assert finds["auth: anonymous"]["category"] == "access"
    assert finds["share: IT"]["category"] == "info"
    assert finds["user: administrator"]["category"] == "info"


def test_edb_reference_finding_is_not_highlighted_as_a_weakness(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.set_services([DiscoveredService(22, Proto.TCP, "ssh")])
    findings_mod.add_findings(
        prof.directory,
        [
            {"module": "ssh", "kind": "edb", "value": "EDB-12345 OpenSSH", "discovered_at": "t"},
            {"module": "nmap", "kind": "product", "value": "OpenSSH 8.4p1", "discovered_at": "t"},
        ],
    )
    finds = {
        n["data"]["label"]: n["data"]
        for n in build_elements(prof)["nodes"]
        if n["data"]["type"] == "finding"
    }
    edb = finds["edb: EDB-12345 OpenSSH"]
    assert edb["category"] == "reference"  # a reference, not a vuln
    assert "notable" not in edb  # never gets the danger ring
    assert "notable" not in finds["product: OpenSSH 8.4p1"]  # a version banner is never notable
