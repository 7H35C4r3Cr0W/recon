"""Combined multi-host report — aggregate every per-host Profile under a project into one report:
cross-host summary + severity tally + notable next steps + per-host detail. CIDR 'sweep' Profiles are
skipped. Read-only; builds real Profiles on disk under a temp workspace root."""
from __future__ import annotations


def test_render_combined_report(monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine import gateway
    from nabu_agent.engine.workspace import workspace_for

    pid = "proj-combined"
    p5 = workspace_for(pid, "10.10.10.5").open_or_create()
    p6 = workspace_for(pid, "10.10.10.6").open_or_create()
    workspace_for(pid, "10.10.10.0/29").open_or_create()   # CIDR sweep Profile — must be skipped

    ef.add_findings(p5.directory, [
        {"kind": "vuln", "value": "MS17-010 SMB RCE", "port": 445, "severity": "vulnerable"},
        {"kind": "port", "value": "22/tcp open ssh", "port": 22}])            # info, not notable
    ef.add_findings(p6.directory, [
        {"kind": "world-readable", "value": "IPC$ anon readable", "port": 445, "severity": "exposure"}])

    md = gateway.render_combined_report(pid)

    assert "# Combined Recon Report" in md
    assert "## Summary" in md
    assert "## Suggested next steps" in md
    # both hosts have their own detail section
    assert "## Host: 10.10.10.5" in md
    assert "## Host: 10.10.10.6" in md
    # the CIDR sweep Profile is NOT treated as a host
    assert "## Host: 10.10.10.0/29" not in md
    # severity tally lists the notable categories
    assert "**vulnerable**" in md and "**exposure**" in md
    # notable findings surface in next steps, strongest (vulnerable) first
    steps = md.split("## Suggested next steps", 1)[1].split("---", 1)[0]
    assert "MS17-010 SMB RCE" in steps
    assert "IPC$ anon readable" in steps
    assert steps.index("MS17-010 SMB RCE") < steps.index("IPC$ anon readable")  # rank order
    # the info-only port is NOT promoted into next steps
    assert "22/tcp open ssh" not in steps


def test_combined_report_empty_project_raises(monkeypatch, tmp_path):
    """No per-host Profile yet -> ProjectNotFound (the router turns this into a friendly message)."""
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import pytest
    from nabu_agent.engine import gateway
    from nabu_agent.engine.errors import ProjectNotFound

    with pytest.raises(ProjectNotFound):
        gateway.render_combined_report("nonexistent-project")
