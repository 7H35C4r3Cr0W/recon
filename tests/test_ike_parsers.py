from pathlib import Path

from oscprecon.modules.ike.parsers import parse_ike_scan, parse_ike_tool

FIX = Path(__file__).parent / "fixtures" / "ike"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_main_mode() -> None:
    findings = parse_ike_scan(_read("ike-scan.txt"))
    kinds = {f.kind for f in findings}
    assert "service" in kinds
    assert "aggressive" not in kinds
    transform = next(f for f in findings if f.kind == "transform")
    assert "Enc=3DES" in transform.value and "Auth=PSK" in transform.value


def test_parse_aggressive_mode() -> None:
    findings = parse_ike_scan(_read("ike-scan-aggressive.txt"))
    assert any(f.kind == "aggressive" and f.value == "enabled" for f in findings)
    # the transform is still captured in aggressive-mode output
    assert any(f.kind == "transform" and "Group=2:modp1024" in f.value for f in findings)


def test_transform_keeps_nested_paren_lifetime() -> None:
    # real ike-scan encodes the lifetime as a nested paren (LifeDuration(4)=0x...) — keep it all
    text = (
        "1.2.3.4\tMain Mode Handshake returned SA=(Enc=3DES Auth=PSK LifeDuration(4)=0x00007080)\n"
    )
    tf = next(f for f in parse_ike_scan(text) if f.kind == "transform")
    assert tf.value == "Enc=3DES Auth=PSK LifeDuration(4)=0x00007080"


def test_no_handshake_no_findings() -> None:
    text = (
        "Starting ike-scan 1.9.5 with 1 hosts\n"
        "Ending ike-scan 1.9.5: 1 hosts scanned. 0 returned handshake; 0 returned notify\n"
    )
    assert parse_ike_scan(text) == []


def test_dispatch_and_garbage() -> None:
    assert parse_ike_tool("unknown", "x") == []
    assert parse_ike_tool("ike-scan", _read("ike-scan.txt"))
    assert parse_ike_tool("ike-scan-aggressive", _read("ike-scan-aggressive.txt"))
