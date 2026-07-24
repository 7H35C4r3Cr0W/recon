def test_web_suggestions_use_the_services_scheme() -> None:
    # review finding: every "Recon next steps" web command hardcoded http://, so on a TLS port the
    # operator copied a command that could not work and doubted the finding.
    from oscprecon.patterns.engine import suggest_for

    https = suggest_for(
        [{"module": "http", "kind": "port", "value": "443", "port": 443, "service": "ssl/http"}],
        target="10.10.10.5",
        domain="",
    )
    commands = " ".join(s.command_template for s in https if s.command_template)
    if commands:
        assert "https://10.10.10.5:443" in commands
        assert "http://10.10.10.5:443" not in commands

    plain = suggest_for(
        [{"module": "http", "kind": "port", "value": "80", "port": 80, "service": "http"}],
        target="10.10.10.5",
        domain="",
    )
    plain_commands = " ".join(s.command_template for s in plain if s.command_template)
    if plain_commands:
        assert "http://10.10.10.5:80" in plain_commands
