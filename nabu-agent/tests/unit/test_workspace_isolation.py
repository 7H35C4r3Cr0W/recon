"""Regression: each (project, target) gets its OWN on-disk Profile. A bug had create() write to
<workspace>/<project_id> (ignoring the target) while open()/exists() looked in the per-target
subfolder, so multiple in-scope hosts collapsed into one findings.json — silently corrupting the
host tier + combined report. This guards the per-host isolation those features depend on."""
from __future__ import annotations


def test_targets_get_isolated_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.engine.workspace import project_root, workspace_for

    pid = "p-iso"
    a = workspace_for(pid, "10.0.0.5").open_or_create()
    b = workspace_for(pid, "10.0.0.6").open_or_create()

    # distinct directories, both under the project root
    assert a.directory != b.directory
    assert a.directory.parent == b.directory.parent == project_root(pid)

    # exists() agrees with create() (the half-applied-fix bug made this False)
    assert workspace_for(pid, "10.0.0.5").exists()
    assert workspace_for(pid, "10.0.0.6").exists()

    # re-opening a host yields ITS OWN target, not whichever host was written last
    assert workspace_for(pid, "10.0.0.5").open().target.ip == "10.0.0.5"
    assert workspace_for(pid, "10.0.0.6").open().target.ip == "10.0.0.6"


def test_findings_do_not_collide_across_hosts(monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine.workspace import workspace_for

    pid = "p-iso2"
    a = workspace_for(pid, "10.0.0.5").open_or_create()
    b = workspace_for(pid, "10.0.0.6").open_or_create()
    ef.add_findings(a.directory, [{"kind": "vuln", "value": "only-on-a", "port": 445}])
    ef.add_findings(b.directory, [{"kind": "vuln", "value": "only-on-b", "port": 445}])

    a_vals = [f["value"] for f in ef.load_findings(a.directory)]
    b_vals = [f["value"] for f in ef.load_findings(b.directory)]
    assert a_vals == ["only-on-a"]
    assert b_vals == ["only-on-b"]
