from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from oscprecon import branding, config, diagnostics, guide, shell, vault_export
from oscprecon import doctor as doctor_mod
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter
from oscprecon.workspace import portability

if TYPE_CHECKING:  # annotation-only names (imported at call time in the function bodies)
    from oscprecon.models import Command, Port
    from oscprecon.modules.base import Module

app = typer.Typer(
    help=(
        "Nabu — headless recon CLI (recon-only, OSCP exam-legal).\n\n"
        "Run `nabu-cli COMMAND --help` for a command's full syntax, flags, and examples "
        "(e.g. `nabu-cli scan --help`). A **profile** (`-p NAME`) is a folder under your workspace "
        "(`~/oscprecon`) that holds all output for one target.\n\n"
        "**Typical workflow:**\n\n"
        "```\n"
        "nabu-cli doctor                      # check the wrapped tools are installed\n"
        "nabu-cli scan 10.10.10.5 -p box      # staged nmap recon into profile 'box'\n"
        "nabu-cli enum smb 10.10.10.5 -p box  # deeper per-service recon (smb/http/ftp/...)\n"
        "nabu-cli findings -p box             # show what has been discovered so far\n"
        "nabu-cli searchsploit vsftpd 2.3.4   # offline Exploit-DB lookup\n"
        "nabu                                 # or open the desktop GUI for the full workspace\n"
        "```\n\n"
        "**Docker** (any host — Kali/Parrot/Ubuntu/macOS/Windows):\n\n"
        "```\n"
        "docker/nabu-docker.sh doctor | scan 10.10.10.5 -p box | gui | shell\n"
        "```\n\n"
        f"By {branding.AUTHOR_NAME} · {branding.AUTHOR_GITHUB} · ☕ {branding.AUTHOR_COFFEE}"
    ),
    add_completion=False,
    rich_markup_mode="markdown",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{branding.APP_NAME} v{branding.app_version()} ({branding.DIST_NAME})")
        typer.echo(f"Created by {branding.AUTHOR_NAME} · {branding.AUTHOR_EMAIL}")
        typer.echo(branding.AUTHOR_GITHUB)
        typer.echo(f"Buy me a coffee — {branding.AUTHOR_COFFEE}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version + author and exit.", callback=_version_callback
    ),
) -> None:
    # why: a callback keeps `scan` an explicit subcommand — Typer otherwise collapses a
    # single-command app and drops the subcommand name (`oscprecon-cli scan <ip>` would break).
    diagnostics.install("cli")  # capture uncaught crashes to the log; best-effort, never blocks
    config.apply_redaction_policy()  # owner policy: never redact (unless the pref is flipped on)
    # cosmetic owl-furby banner — stderr + TTY only, so it never pollutes piped stdout or tests
    if sys.stderr.isatty():
        sys.stderr.write("\n" + branding.cli_banner() + "\n")


@app.command()
def scan(
    ip: str = typer.Argument(..., help="Target IP or hostname (e.g. 10.10.10.5 or target.htb)."),
    profile: str = typer.Option(
        ...,
        "--profile",
        "-p",
        help="Profile = the ~/oscprecon folder holding this target's output.",
    ),
    hostname: str | None = typer.Option(
        None, help="Optional hostname for the target (feeds vhost/TLS-aware modules)."
    ),
    scan_profile: str | None = typer.Option(
        None,
        "--scan-profile",
        help="nmap battery: quick | default | full | exam (default: your configured preference).",
    ),
    udp_full: bool = typer.Option(
        False, "--udp-full", help="Also run the slow full UDP sweep (65535 ports; adds to top-100)."
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Reuse output from commands that already completed (exit 0); skip re-running them.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Re-run every command even when prior output exists (overrides --resume).",
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Run staged nmap recon against a target and save findings to a profile.

    Discovers open ports, then runs a versioned `nmap -sV -sC` over exactly the ports it found,
    parsing everything into `<workspace>/<profile>/`. Safe to re-run; open the profile in the GUI
    (`nabu`) to keep enumerating each service.

    **Scan batteries** (`--scan-profile`), fastest to most thorough — all pure nmap, exam-legal:

    ```
    quick    Top-1000 TCP only (-T4). Fast triage; no full sweep, no UDP.
    default  Top-1000 + full 65535 TCP (-p- -T4) + UDP top-100, then -sV -sC on open ports.
    full     Same thorough sweep as default.
    exam     Full sweep rate-boosted (-p- --min-rate 1000 -T4) to finish fast under exam time.
    ```

    A profile (`-p/--profile`) is a named folder under the workspace. Re-running scan on an existing
    profile **reuses** it (history preserved); choose a new name to start a fresh scan.

    **Examples:**

    ```
    nabu-cli scan 10.10.10.5 -p box                        # default battery -> profile 'box'
    nabu-cli scan 10.10.10.5 -p box --scan-profile quick   # fast top-1000 triage only
    nabu-cli scan 10.10.10.5 -p box --scan-profile exam    # full sweep, rate-boosted
    nabu-cli scan target.htb -p box --hostname target.htb --udp-full   # + full UDP sweep
    nabu-cli scan 10.10.10.5 -p box --resume               # continue; skip finished commands
    ```
    """
    root = workspace if workspace is not None else config.workspace_root()
    profile_choice = (
        scan_profile if scan_profile is not None else config.load_settings().scan_profile
    )
    if profile_choice not in config.SCAN_PROFILES:
        typer.echo(
            f"[error] unknown --scan-profile '{profile_choice}'; "
            f"choose one of {', '.join(config.SCAN_PROFILES)}.",
            err=True,
        )
        raise typer.Exit(2)
    try:
        target = Target(ip=ip, hostname=hostname)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    directory = Path(root) / profile
    # why: an EXISTING profile is always LOADED, never re-created — Profile.create overwrites
    # profile.json and erases command_history/tags/started_at (bug #2: re-running `scan` on a
    # profile without --resume silently wiped its history, the GUI's New-Project guard has no CLI
    # equivalent). --resume additionally controls whether finished commands re-run (Orchestrator).
    if (directory / "profile.json").exists():
        try:
            prof = Profile.load(directory)
        except (ValueError, OSError) as exc:
            typer.echo(f"[error] cannot read profile '{profile}': {exc}", err=True)
            raise typer.Exit(2) from exc
        # the loaded profile's stored target is authoritative (run_nmap scans it), so a differing
        # ip would be silently ignored — scanning the wrong host. Refuse the mismatch rather than
        # guess (Target() canonicalizes a host-bit CIDR, so 10.10.5.5/24 vs stored 10.10.5.0/24 is
        # not a mismatch); the user opens the right profile or picks a new name for a fresh scan.
        if prof.target.ip != target.ip:
            typer.echo(
                f"[error] target mismatch: profile '{profile}' targets {prof.target.ip}, but you "
                f"gave {ip}. Use the matching IP, or a new profile name to start a fresh scan.",
                err=True,
            )
            raise typer.Exit(2)
        if resume:
            typer.echo(f"[resume] {prof.directory} — {len(prof.command_history)} prior commands")
        else:
            typer.echo(
                f"[profile] reusing {prof.directory} — history preserved "
                f"(use a new name for a fresh profile)"
            )
    else:
        prof = Profile.create(root, profile, target)
    config.add_recent(prof.directory)
    typer.echo(f"[profile] {prof.directory}  (scan profile: {profile_choice})")
    Orchestrator(
        prof,
        on_line=lambda line: typer.echo(line),
        udp_full=udp_full,
        scan_profile=profile_choice,
        resume=resume,
        force=force,
    ).run_nmap()


@app.command("export-vault")
def export_vault_cmd(
    dest: Path = typer.Argument(..., help="Destination folder (an Obsidian vault or any dir)."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Export a profile to an Obsidian vault as linked markdown (creds redacted)."""
    out = vault_export.export_vault(_load_profile(profile, workspace), dest)
    typer.echo(f"[exported] {out} (snapshot — creds.json values redacted)")


@app.command("export-project")
def export_project_cmd(
    dest: Path = typer.Argument(..., help="Destination folder, or an explicit <name>.tar.gz path."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Pack a profile folder into <name>.tar.gz for backup/transfer (includes creds.json)."""
    root = workspace if workspace is not None else config.workspace_root()
    directory = Path(root) / profile
    if not (directory / "profile.json").exists():
        typer.echo(f"[error] no profile at {directory}", err=True)
        raise typer.Exit(2)
    try:
        out = portability.export_project_archive(directory, dest)
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"[exported] {out}  (WARNING: includes creds.json — treat the archive as sensitive)")


@app.command("import-project")
def import_project_cmd(
    archive: Path = typer.Argument(..., help="Project archive (.tar.gz) to import."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Replace an existing profile of the same name."
    ),
) -> None:
    """Extract a project archive into the workspace (path-traversal-safe) and register it."""
    root = workspace if workspace is not None else config.workspace_root()
    try:
        dest = portability.import_project_archive(archive, Path(root), overwrite=overwrite)
    except portability.ProjectExistsError as exc:
        typer.echo(f"[error] {exc} — re-run with --overwrite to replace it.", err=True)
        raise typer.Exit(2) from exc
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    config.add_recent(dest)
    typer.echo(f"[imported] {dest}")


@app.command()
def doctor(
    install: bool = typer.Option(
        False, "--install", help="Offer to apt-install the missing allow-listed tools (asks first)."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt (non-interactive install)."
    ),
    show_versions: bool = typer.Option(
        False, "--versions", help="Also print the installed version of each present tool (slower)."
    ),
) -> None:
    """Check each wrapped tool; print install hints, optionally apt-install the missing ones."""
    report = doctor_mod.scan()
    required = report.required
    # why: group-aware missing — don't report a tool as missing when a present alternative already
    # covers it. Otherwise impacket-scripts looks "missing" because its scripts install as
    # impacket-GetADUsers (no .py), not the .py variant we also allow-list.
    eff_missing = doctor_mod.effective_missing(report)
    req_missing = [tool for tool in eff_missing if not tool.optional]
    spray_missing = [tool for tool in eff_missing if tool.category == "spray"]
    exploit_missing = [tool for tool in eff_missing if tool.category == "exploit"]
    present_ct = sum(1 for tool in required if tool.present)
    typer.echo(f"[doctor] {present_ct}/{len(required)} required tools found on PATH")
    if req_missing:
        typer.echo(f"[doctor] {len(req_missing)} missing (install the ones you need):")
        for tool in req_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")
        # why: alternatives cover the same capability — don't alarm the user about skipping them.
        typer.echo(
            "\nNote: alternatives are fine to skip — netexec covers nxc/crackmapexec, and "
            "GetX.py covers impacket-GetX.py (and vice-versa)."
        )
    else:
        typer.echo("[doctor] all wrapped tools present — exam-ready.")
    if spray_missing:
        typer.echo("\n[doctor] Spray-mode tools (only needed if you enable Spray mode, §2a):")
        for tool in spray_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")
    if exploit_missing:
        typer.echo(
            "\n[doctor] Exploitation-tab tools (§2b — needed only when you run manual attacks):"
        )
        for tool in exploit_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")

    typer.echo("\n[doctor] Reference data (wordlists / NSE / Exploit-DB):")
    for check in doctor_mod.scan_resources():
        mark = "  ok" if check.ok else "  !!"
        typer.echo(f"{mark}  {check.name:28}{'' if check.ok else '  ' + check.detail}")

    typer.echo("\n[doctor] Host readiness:")
    for check in doctor_mod.scan_system():
        mark = "  ok" if check.ok else "  !!"
        typer.echo(f"{mark}  {check.name:30}  {check.detail}")

    if show_versions:
        vers = doctor_mod.versions(report)
        typer.echo("\n[doctor] Installed versions (present tools):")
        for name in sorted(vers):
            typer.echo(f"  {name:22}  {vers[name]}")

    if not req_missing:
        return
    if not install:
        typer.echo("\nRe-run `doctor --install` to apt-install the required ones (asks first).")
        return
    plan = doctor_mod.install_plan(report)
    if plan.manual:
        typer.echo("\n[doctor] install these manually (not apt):")
        for name, hint in plan.manual:
            typer.echo(f"  {name:24}  {hint}")
    code = doctor_mod.install(
        plan,
        assume_yes=yes,
        confirm=lambda command: typer.confirm(f"[doctor] run `{command}`?"),
        echo=typer.echo,
    )
    raise typer.Exit(code)


@app.command("docs")
def docs_cmd(
    topic: str | None = typer.Argument(
        None, help="A topic id or title prefix (e.g. 'graph'). Omit to list all topics."
    ),
    plain: bool = typer.Option(
        False, "--plain", help="Print raw markdown instead of terminal-rendered."
    ),
) -> None:
    """Read the bundled user guide — the same content as the GUI's Help -> Documentation."""
    if topic is None:
        typer.echo("Nabu documentation — run `nabu-cli docs <topic>`:\n")
        for entry in guide.topics():
            typer.echo(f"  {entry.id:16}  {entry.summary}")
        return
    resolved = guide.resolve(topic)
    if resolved is None:
        typer.echo(
            f"[docs] no topic matches '{topic}'. Run `nabu-cli docs` to list them.", err=True
        )
        raise typer.Exit(1)
    markdown = guide.load(resolved.id)
    # pretty-render on a real terminal; fall back to raw markdown when piped or with --plain, so the
    # output stays clean for scripts and tests.
    if plain or not sys.stdout.isatty():
        typer.echo(markdown)
        return
    try:
        from rich.console import Console
        from rich.markdown import Markdown

        Console().print(Markdown(markdown))
    except Exception:  # boundary: rich should be present, but never fail `docs` over rendering
        typer.echo(markdown)


@app.command("exploit")
def exploit_cmd(
    service: str | None = typer.Argument(
        None,
        help="Service key (ad, web, smb, mssql, mysql, ftp, ssh, snmp, redis, rdp, nfs, "
        "linux, windows, shells). Omit to list all services.",
    ),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="Profile to pre-fill {target}/{domain}/{cred} from."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Show exploitation command templates (§2b). CLI is display-only — copy a command to run it."""
    from oscprecon import exploit as exploit_mod
    from oscprecon import ligolo

    values: dict[str, str] = {}
    # mirror the GUI ExploitPanel fill: reverse-shell templates need {lhost}/{lport} filled even
    # without a profile (else a copied command still shows literal {lhost}). tun0 is best-effort.
    lhost = ligolo.detect_tun_ip("tun0") or ligolo.detect_tun_ip("tun1")
    if lhost:
        values["lhost"] = lhost
    values["lport"] = "4444"
    prof: Profile | None = None
    if profile is not None:
        prof = _load_profile(profile, workspace)
        values["target"] = prof.target.ip
        values["dc"] = prof.target.ip
        # no trailing slash: templates use {url}/path — a trailing slash double-slashed them
        # (http://host//CHANGELOG.md). {url}?query still resolves fine.
        values["url"] = f"http://{prof.target.host}"
        if prof.target.hostname and "." in prof.target.hostname:
            values["domain"] = prof.target.hostname.split(".", 1)[1]
        creds = prof.credentials()
        # mirror the GUI's ExploitPanel fill: a hash cred fills {hash} for pass-the-hash actions,
        # a password cred fills {password} — fill both when present so neither kind of template is
        # left with an unfilled brace. user/domain come from the password cred, else the hash cred.
        pw = next((c for c in creds if c.secret_type == "password"), None)
        hc = next((c for c in creds if c.secret_type == "hash"), None)
        primary = pw or hc
        if primary is not None:
            values["user"] = primary.username
            if primary.domain:
                values["domain"] = primary.domain
        if pw is not None:
            values["password"] = pw.secret
        if hc is not None:
            values["hash"] = hc.secret

    if service is None:
        typer.echo("Exploitation services (use `nabu-cli exploit <service>` for actions):\n")
        for key in exploit_mod.service_keys():
            spec = exploit_mod.service_exploits(key)
            if spec is None:
                continue
            ports = ", ".join(str(p) for p in spec.ports) or "—"
            typer.echo(f"  {key:9} {spec.label:22} {len(spec.actions):3} actions   ports: {ports}")
        raise typer.Exit(0)

    # accept the service-name variants nmap/`enum` use (postgresql->postgres, etc.) so
    # `exploit <name>` resolves the same key `enum <name>` and the tree use.
    _ALIASES = {
        "postgresql": "postgres",
        "ms-sql-s": "mssql",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "domain": "dns",
        "http": "web",
        "https": "web",
        "http-proxy": "squid",
    }
    key = _ALIASES.get(service.lower(), service)
    spec = exploit_mod.service_exploits(key)
    if spec is None:
        typer.echo(f"[error] unknown service '{service}'", err=True)
        raise typer.Exit(2)
    if prof is not None:
        # bind {port} to the DISCOVERED port for this service (mirrors the GUI ExploitPanel), so
        # port-parameterised templates aren't left with a literal {port}; fall back to the catalog
        # default. And emit the GUI's "attacks belong to identified services" decision-aid warning.
        open_svcs = [(s.port, s.service) for s in prof.discovered_services if s.state == "open"]
        discovered_port = exploit_mod.port_for_service(open_svcs, key)
        if discovered_port is not None:
            values["port"] = str(discovered_port)
        elif spec.ports:
            values["port"] = str(spec.ports[0])
        from oscprecon import findings as _findings

        fp_texts: list[str] = []
        for s in prof.discovered_services:
            fp_texts.append(f"{s.product} {s.version}")
            if s.nmap_scripts_output:
                fp_texts.append(s.nmap_scripts_output)
        try:
            for f in _findings.load_findings(prof.directory):
                note = str(f.get("note") or f.get("detail") or "")
                if note:
                    fp_texts.append(note)
        except OSError:
            pass
        present = set(exploit_mod.services_present(open_svcs)) | set(
            exploit_mod.web_app_keys_from_fingerprints(fp_texts)
        )
        if spec.ports and key not in present:  # portless catalogs (linux/windows/shells) never warn
            typer.echo(
                f"⚠ {spec.label} was NOT found on this target by the scan — attacks belong to "
                f"identified services; only run this if you confirmed it's really there.\n"
            )
    typer.echo(f"# {spec.label} — {spec.note}\n")
    for category in spec.categories():
        typer.echo(f"── {category} ──")
        for action in spec.by_category(category):
            tag = "RUN " if action.executable else "COPY"  # attacker (run) vs victim (copy)
            typer.echo(f"[{tag}] {action.title}  ({action.tool})")
            typer.echo(f"    {exploit_mod.fill_template(action.template, values)}")
        typer.echo("")
    raise typer.Exit(0)


@app.command("payload")
def payload_cmd(
    payload: str | None = typer.Argument(
        None, help="Payload id (see `nabu-cli payload` with no args) or a raw msfvenom -p string."
    ),
    lhost: str = typer.Option("", "--lhost", "-l", help="Your VPN/tun0 IP (LHOST)."),
    lport: int = typer.Option(4444, "--lport", "-P", help="Listener port (LPORT)."),
    fmt: str = typer.Option("", "--format", "-f", help="Output format (default: payload's own)."),
    encoder: str = typer.Option("", "--encoder", "-e", help="Encoder, e.g. x86/shikata_ga_nai."),
    iterations: int = typer.Option(1, "--iterations", "-i", help="Encoder iterations."),
    badchars: str = typer.Option("", "--badchars", "-b", help=r"Bad chars, e.g. \x00\x0a."),
    out: str = typer.Option("", "--out", "-o", help="Output file (default: shell.<ext>)."),
) -> None:
    """Build an msfvenom reverse-shell payload + its listener (display-only — copy and run it)."""
    from oscprecon.exploit import msfvenom

    if payload is None:
        typer.echo("msfvenom payload builder — pick an id:\n")
        for plat in msfvenom.PLATFORMS:
            typer.echo(f"── {plat.label} ──")
            for p in plat.payloads:
                flag = "  [meterpreter=one-use]" if p.meterpreter else ""
                typer.echo(f"  {p.id:19} {p.payload}{flag}")
            typer.echo("")
        typer.echo("e.g.  nabu-cli payload win-x64-stageless -l 10.10.14.7 -P 443")
        raise typer.Exit(0)

    result = msfvenom.build_command(
        msfvenom.MsfvenomSpec(
            payload=payload,
            fmt=fmt,
            lhost=lhost,
            lport=lport,
            encoder=encoder,
            iterations=iterations,
            badchars=badchars,
            outfile=out,
        )
    )
    typer.echo("# generate the payload (on Kali):")
    typer.echo(result.command)
    typer.echo("\n# catch the shell (start this first):")
    typer.echo(result.listener)
    for note in result.notes:
        typer.echo(f"\n⚠ {note}")
    raise typer.Exit(0)


@app.command("gtfobins")
def gtfobins_cmd(
    binary: str | None = typer.Argument(
        None,
        help="Binary or technique to search (e.g. find, tar, sudo, suid, capabilities). "
        "Omit to list every binary.",
    ),
) -> None:
    """Offline GTFOBins lookup — SUID/sudo/capability abuse for a Unix binary (display-only)."""
    from oscprecon.references import gtfobins as gtfo

    results = gtfo.search(binary or "")
    if not results:
        typer.echo(f"[no match] '{binary}' — try a binary or function (sudo/suid/…)", err=True)
        raise typer.Exit(1)
    if binary is None:
        typer.echo("GTFOBins (use `nabu-cli gtfobins <binary>` for the techniques):\n")
        for b in results:
            typer.echo(f"  {b.name:14} {', '.join(b.functions)}")
        raise typer.Exit(0)
    for b in results:
        typer.echo(f"# {b.name}  —  {b.url}")
        for tech in b.techniques:
            typer.echo(f"  [{tech.func}] {tech.code}")
        typer.echo("")
    raise typer.Exit(0)


@app.command("hashcat")
def hashcat_cmd(
    query: str | None = typer.Argument(
        None, help="Search hash type by name/mode/category (e.g. apr1, ntlm, 1800, kerberos)."
    ),
    attack: str = typer.Option("0", "--attack", "-a", help="Attack mode: 0 dict, 1 combo, 3 mask."),
    hashfile: str = typer.Option("hash.txt", "--hashfile", help="Hash file for the built command."),
    wordlist: str = typer.Option(
        "/usr/share/wordlists/rockyou.txt", "--wordlist", "-w", help="Wordlist (attack 0/1/6/7)."
    ),
    mask: str = typer.Option("?a?a?a?a?a?a", "--mask", help="Mask (attack 3/6/7)."),
) -> None:
    """Hashcat mode helper — find the -m for a hash and build the crack command (display-only)."""
    from oscprecon.references import hashcat as hc

    results = hc.search(query or "")
    if not results:
        typer.echo(f"[no match] '{query}' — try apr1 / ntlm / kerberos / a -m number", err=True)
        raise typer.Exit(1)
    if query is None:
        typer.echo("Hashcat modes (use `nabu-cli hashcat <search>` to narrow + build a command):\n")
        cat = ""
        for m in results:
            if m.category != cat:
                cat = m.category
                typer.echo(f"── {cat} ──")
            typer.echo(f"  -m {m.mode:<6} {m.name}")
        typer.echo("\nAttack modes: " + " · ".join(f"-a {a} {n}" for a, n, _ in hc.ATTACK_MODES))
        raise typer.Exit(0)
    typer.echo(f"# matches for '{query}':\n")
    for m in results:
        cmd = hc.build_command(
            m.mode, attack=attack, hashfile=hashfile, wordlist=wordlist, mask=mask
        )
        typer.echo(f"  -m {m.mode:<6} {m.name}  [{m.category}]")
        typer.echo(f"      {cmd}")
    typer.echo("")
    raise typer.Exit(0)


@app.command("pivot")
def pivot_cmd(
    lhost: str = typer.Option(
        "", "--lhost", "-l", help="Your VPN/tun0 IP (the agent dials back here). Auto from tun0."
    ),
    routes: str = typer.Option("", "--routes", "-r", help="Internal /24(s), comma-separated."),
    agent_os: str = typer.Option("linux", "--os", help="Pivot host OS: linux | windows."),
    port: int = typer.Option(11601, "--port", "-P", help="Proxy listen port."),
    iface: str = typer.Option("ligolo", "--iface", help="Tun interface name."),
) -> None:
    """Show the ligolo-ng pivot workflow as copy-paste steps (display-only; same as the Pivot tab)."""  # noqa: E501
    from oscprecon import ligolo

    # normalize up front: build_ligolo_steps() falls back to the Linux workflow for any unknown
    # value, so the header must match — else `--os bogus` prints "bogus pivot" over Linux steps.
    agent_os = agent_os.strip().lower()
    if agent_os not in ("linux", "windows"):
        agent_os = "linux"
    ip = lhost.strip() or ligolo.detect_tun_ip("tun0") or ligolo.detect_tun_ip("tun1")
    route_list = [r.strip() for r in routes.replace(";", ",").split(",") if r.strip()]
    typer.echo(f"# ligolo-ng — reach an internal network ({agent_os} pivot)")
    typer.echo(f"# GitHub: {ligolo.LIGOLO_GITHUB}  ·  Releases: {ligolo.LIGOLO_RELEASES}")
    typer.echo(
        f"# syntax checked vs {ligolo.LIGOLO_REF_VERSION} ({ligolo.LIGOLO_REF_VERIFIED}) — "
        "check releases if stale\n"
    )
    for step in ligolo.build_ligolo_steps(
        ip, port=port, iface=iface, routes=route_list, agent_os=agent_os
    ):
        typer.echo(f"── {step.n}. {step.title}  (on {step.where}) ──")
        for line in step.commands:
            typer.echo(f"  {line}")
        if step.note:
            typer.echo(f"  # {step.note}")
        typer.echo("")
    typer.echo("# ═══ Ligolo reference — serve · transfer · tunnel · console ═══\n")
    for section in ligolo.ligolo_reference_sections(ip, port=port, agent_os=agent_os):
        typer.echo(f"── {section.title} ──")
        typer.echo(f"  # {section.subtitle}")
        for item in section.items:
            typer.echo(f"  • {item.label}")
            for line in item.command.split("\n"):
                typer.echo(f"      {line}")
        typer.echo("")
    typer.echo("# ── Other pivot methods (when ligolo isn't an option) ──")
    for method in ligolo.PIVOT_METHODS:
        typer.echo(f"── {method.name}  —  {method.when} ──")
        for line in method.commands:
            typer.echo(f"  {line}")
        typer.echo("")
    raise typer.Exit(0)


def _profile_dir(profile: str, workspace: Path | None) -> Path:
    root = workspace if workspace is not None else config.workspace_root()
    directory = Path(root) / profile
    if not (directory / "profile.json").exists():
        typer.echo(f"[error] no profile '{profile}' in {root}", err=True)
        raise typer.Exit(2)
    return directory


def _load_profile(profile: str, workspace: Path | None) -> Profile:
    # a corrupt / foreign profile.json makes Profile.load raise ValueError; catch it and exit with
    # the clean `[error] … / exit 2` convention instead of dumping a traceback (bug #17).
    directory = _profile_dir(profile, workspace)
    try:
        return Profile.load(directory)
    except (ValueError, OSError) as exc:
        typer.echo(f"[error] cannot read profile '{profile}': {exc}", err=True)
        raise typer.Exit(2) from exc


# the richer recon modules (their own commands()/parse(), not simple-spec steps). enum runs the
# LIGHT Tier-1 battery each emits (banner/whatweb/curl/nmap-scripts) headlessly — the same engine
# the GUI panels drive. default ports pick the module's port when the profile hasn't discovered one.
_FULL_ENUM_MODULES: dict[str, int] = {
    "ssh": 22,
    "ftp": 21,
    "http": 80,
    "smb": 445,
    "ldap": 389,
    "dns": 53,
    "smtp": 25,
    "vhost": 80,
}


def _tier1_enum_steps(
    service: str, module: Module, target: Target, port: int, ports: list[Port]
) -> list[tuple[Command, str]]:
    # Mirror the GUI's bespoke recon workers: use each module's native step methods, which tag every
    # step with the correct parser key (`.tool`). The output-file STEM must NOT be used as the key —
    # stems don't match the _PARSERS dispatch keys (smb `users.txt` vs the "netexec-users" parser,
    # ldap `rootdse.txt` vs "ldapsearch-rootdse", ftp `curl-root.txt` vs "curl-list", …), so a
    # stem-keyed raw dict silently parses to zero findings. http/vhost are commands()-driven and
    # their parse() keys on "<tool>:<port>" / "<tool>:<domain>", so those keys are built explicitly.
    from oscprecon.modules.dns import DnsModule
    from oscprecon.modules.ftp import FtpModule
    from oscprecon.modules.ldap import LdapModule
    from oscprecon.modules.smb import SmbModule
    from oscprecon.modules.smtp import SmtpModule
    from oscprecon.modules.ssh import SshModule

    domain = target.hostname or ""
    if isinstance(module, SshModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, port)]
    if isinstance(module, SmtpModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, port)]
    if isinstance(module, DnsModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, domain or None, port)]
    if isinstance(module, FtpModule):
        ftp_steps = [*module.banner_steps(target, port), *module.anon_steps(target, port)]
        return [(s.command, s.tool) for s in ftp_steps]
    if isinstance(module, LdapModule):
        return [(s.command, s.tool) for s in module.rootdse_steps(target, port)]
    if isinstance(module, SmbModule):
        smb_steps = [
            *module.banner_steps(target),
            *module.null_session_steps(target),
            *module.guest_steps(target),
        ]
        return [(s.command, s.tool) for s in smb_steps]
    if service == "vhost":  # parse() does label.partition(":") -> (tool, domain)
        return [(c, f"{Path(c.output_file).stem}:{domain}") for c in module.commands(target, ports)]
    # http (and any commands()-driven fallback): parse() keys on "<tool>:<port>" where port is the
    # per-port output subdir; the whatweb/robots battery uses clean stems so stem:port is correct.
    out: list[tuple[Command, str]] = []
    for c in module.commands(target, ports):
        of = Path(c.output_file)
        key = f"{of.stem}:{of.parent.name}" if of.parent.name.isdigit() else of.stem
        out.append((c, key))
    return out


def _run_full_module_enum(service: str, profile: str, workspace: Path | None, port: int) -> None:
    # run a full recon Module (native Tier-1 steps -> shell.run -> parse -> record findings),
    # mirroring the GUI's bespoke workers so http/ssh/ftp/dns/ldap/smb/smtp/vhost are enum-runnable.
    import importlib
    import inspect
    from datetime import UTC, datetime

    from oscprecon import findings as findings_mod
    from oscprecon.models import Port, Proto
    from oscprecon.modules.base import Module
    from oscprecon.parsing import run_parser

    mod = importlib.import_module(f"oscprecon.modules.{service}")
    cls = next(
        (
            obj
            for _, obj in inspect.getmembers(mod, inspect.isclass)
            if issubclass(obj, Module)
            and obj is not Module
            and obj.__module__.startswith(mod.__name__)
        ),
        None,
    )
    if cls is None:
        typer.echo(f"[error] no recon module class for '{service}'", err=True)
        raise typer.Exit(2)
    module = cls()
    prof = _load_profile(profile, workspace)
    # ports for this module: the discovered ports whose service name matches, else the CLI override
    # or the module's default port — so it still runs a Tier-1 pass even before a versioned scan.
    default_port = port or _FULL_ENUM_MODULES[service]
    # match discovered services through the SAME name-alias table the simple-spec path uses, so
    # nmap's name (dns->"domain", smb->"microsoft-ds") is recognised — an exact string compare made
    # `enum dns` (etc.) miss the real port and fall back to the default.
    from oscprecon.exploit import services_present

    ports = [
        Port(number=s.port, proto=s.proto, service=s.service, product=s.product, version=s.version)
        for s in prof.discovered_services
        if s.proto == Proto.TCP
        and (
            s.service == service
            or (service == "http" and "http" in s.service)
            or service in services_present([(s.port, s.service)])
        )
    ]
    if not ports:
        ports = [Port(number=default_port, proto=Proto.TCP, service=service)]
    # the scalar port the single-port step modules (ssh/ftp/ldap/smtp/dns/smb) actually probe: an
    # explicit --port wins (bug #15: it was silently ignored once the service was discovered), else
    # the DISCOVERED port when the scan found the service on a non-standard port, else the default.
    probe_port = port or ports[0].number
    if service == "http":
        # an unresolved profile hostname makes every http probe fail with "no address" — warn and
        # let the module fall back to the IP so recon still works (add /etc/hosts for a real vhost).
        from oscprecon.modules.http import effective_web_host

        _, unresolved = effective_web_host(prof.target)
        if unresolved:
            typer.echo(
                f"⚠ hostname '{prof.target.hostname}' does not resolve — probing the IP "
                f"{prof.target.ip} instead. For a name-based vhost, add "
                f"'{prof.target.ip} {prof.target.hostname}' to /etc/hosts and re-run."
            )
    raw: dict[str, str] = {}
    issues: list[str] = []
    for command, key in _tier1_enum_steps(service, module, prof.target, probe_port, ports):
        out = prof.directory / command.output_file
        result = shell.run(command.shell_line, out, cwd=prof.directory, on_line=typer.echo)
        if result.missing_tool is not None:
            issues.append(f"{result.missing_tool} not installed")
        elif result.blocked is not None:
            issues.append("a step was blocked by the recon-only policy")
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if key:  # unparsed steps (e.g. smb nmap-smb, http headers) run but carry no parser key
            # ACCUMULATE, don't overwrite: several steps legitimately share one parser key (smb's
            # null-session AND guest steps are both "netexec-shares"/"smbclient-shares"), so a plain
            # raw[key]=text let the guest run (often LOGON_FAILURE) clobber the null findings.
            raw[key] = raw[key] + "\n" + text if key in raw else text
    # WordPress follow-up (CLAUDE.md §9): when a web port's fingerprint shows WordPress, run wpscan
    # enumeration (never brute) for that port and fold its JSON into the same parse pass, so users /
    # plugins / themes / version land in findings.json instead of only being suggested as text.
    if service == "http":
        from oscprecon.modules.http import detect_wordpress, is_tls, wordpress_command

        for web_port in ports:
            port_texts = [v for k, v in raw.items() if k.endswith(f":{web_port.number}")]
            if not detect_wordpress(*port_texts):
                continue
            wp_cmd = wordpress_command(
                prof.target, web_port.number, is_tls(web_port.service, web_port.number)
            )
            typer.echo(
                f"\n[wordpress] detected on port {web_port.number} — running wpscan enumeration "
                f"(plugins/themes/users; never brute)…"
            )
            wp_out = prof.directory / wp_cmd.output_file
            wp_result = shell.run(wp_cmd.shell_line, wp_out, cwd=prof.directory, on_line=typer.echo)
            if wp_result.missing_tool is not None:
                issues.append(f"{wp_result.missing_tool} not installed")
            elif wp_result.blocked is not None:
                issues.append("a step was blocked by the recon-only policy")
            try:
                wp_text = wp_out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                wp_text = ""
            raw[f"wpscan:{web_port.number}"] = wp_text
    found = run_parser(lambda: module.parse(raw), label=service, raw="\n".join(raw.values()))
    if found:
        now = datetime.now(UTC).isoformat()
        findings_mod.add_findings(
            prof.directory,
            [
                {
                    "module": f.service,
                    "kind": f.fields.get("kind", ""),
                    "value": f.fields.get("value", ""),
                    "detail": f.detail,
                    "discovered_at": now,
                }
                for f in found
            ],
        )
    if issues:
        typer.echo(
            f"\n⚠ {len(dict.fromkeys(issues))} step(s) did not run — "
            f"{'; '.join(dict.fromkeys(issues))}. Findings may be INCOMPLETE."
        )
    typer.echo(f"\n[enum] {service}: {len(found)} finding(s)")
    for f in found:
        typer.echo(
            f"  • {f.fields.get('kind', '?')}: {f.fields.get('value', '')}  {f.detail}".rstrip()
        )
    for tip in module.suggest(found):
        typer.echo(f"  → {tip}")
    Reporter(prof).write()


@app.command("enum")
def enum_cmd(
    service: str | None = typer.Argument(
        None, help="Service to enumerate (see the no-arg list). Omit to list runnable services."
    ),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    port: int = typer.Option(0, "--port", help="Override the discovered port (0 = the default)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Run a service's Tier-1 recon headlessly (the same enumeration the GUI service panels run)."""
    from datetime import UTC, datetime

    from oscprecon import findings as findings_mod
    from oscprecon.gui.simple_recon import SIMPLE_SPECS  # Qt-free: importing it never loads PySide6
    from oscprecon.parsing import run_parser

    if service is None:
        typer.echo("Runnable services (`nabu-cli enum <service> -p <profile>`):\n")
        typer.echo("  " + ", ".join(sorted(set(SIMPLE_SPECS) | set(_FULL_ENUM_MODULES))))
        raise typer.Exit(0)
    spec = SIMPLE_SPECS.get(service)
    if spec is None:
        # not a simple-spec service — try the richer full recon modules (http/ssh/ftp/dns/ldap/…)
        if service in _FULL_ENUM_MODULES:
            _run_full_module_enum(service, profile, workspace, port)
            raise typer.Exit(0)
        runnable = ", ".join(sorted(set(SIMPLE_SPECS) | set(_FULL_ENUM_MODULES)))
        typer.echo(
            f"[error] '{service}' is not a runnable enum service. Choose one of: {runnable}",
            err=True,
        )
        raise typer.Exit(2)
    prof = _load_profile(profile, workspace)
    # use the DISCOVERED port when the scan found this service on a non-standard port (mirrors the
    # GUI, which passes service.port). Was a bug: the raw --port default (0) made steps_fn fall back
    # to the module default and miss a service on an odd port. Same fix as _run_full_module_enum.
    from oscprecon.exploit import services_present
    from oscprecon.models import Proto as _Proto

    probe_port = port
    if probe_port == 0:
        # match through the service-name alias table (bug #16): the enum key is mssql/rdp/winrm
        # but nmap names the port "ms-sql-s"/"ms-wbt-server"/"wsman" — an exact compare missed those
        # and fell back to the default port, so a scan that found the service was ignored.
        probe_port = next(
            (
                s.port
                for s in prof.discovered_services
                if s.proto == _Proto.TCP
                and s.state == "open"
                and (s.service == service or service in services_present([(s.port, s.service)]))
            ),
            0,
        )
    raw: dict[str, str] = {}
    issues: list[str] = []
    for command, tool in spec.steps_fn(prof.target, probe_port):
        out = prof.directory / command.output_file
        result = shell.run(command.shell_line, out, cwd=prof.directory, on_line=typer.echo)
        if result.missing_tool is not None:
            issues.append(f"{result.missing_tool} not installed")
        elif result.blocked is not None:
            issues.append("a step was blocked by the recon-only policy")
        if tool:
            try:
                raw[tool] = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                raw[tool] = ""
    module = spec.factory()
    found = run_parser(lambda: module.parse(raw), label=spec.module, raw="\n".join(raw.values()))
    if found:
        now = datetime.now(UTC).isoformat()
        findings_mod.add_findings(
            prof.directory,
            [
                {
                    "module": f.service,
                    "kind": f.fields.get("kind", ""),
                    "value": f.fields.get("value", ""),
                    "detail": f.detail,
                    "discovered_at": now,
                }
                for f in found
            ],
        )
    if issues:
        typer.echo(
            f"\n⚠ {len(dict.fromkeys(issues))} step(s) did not run — "
            f"{'; '.join(dict.fromkeys(issues))}. Findings may be INCOMPLETE."
        )
    typer.echo(f"\n[enum] {spec.module}: {len(found)} finding(s)")
    for f in found:
        kind = f.fields.get("kind", "?")
        typer.echo(f"  • {kind}: {f.fields.get('value', '')}  {f.detail}".rstrip())
    for tip in module.suggest(found):
        typer.echo(f"  → {tip}")
    Reporter(prof).write()


@app.command("list")
def list_cmd(
    ip: str | None = typer.Option(None, "--ip", help="Only profiles whose target IP matches."),
    archived: bool = typer.Option(
        True, "--archived/--no-archived", help="Include archived profiles."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """List workspace projects (name · IP · status · service/finding/cred counts)."""
    from oscprecon.workspace import index, portability

    root = workspace if workspace is not None else config.workspace_root()
    if ip is not None:
        matches = portability.find_profiles_by_ip(Path(root), ip)
        if not matches:
            typer.echo(f"[list] no profile targets {ip} in {root}")
            raise typer.Exit(0)
        for directory in matches:
            typer.echo(f"  {directory.name}  ({directory})")
        raise typer.Exit(0)
    summaries = index.scan_workspace(Path(root), include_archived=archived)
    if not summaries:
        typer.echo(f"[list] no projects in {root}")
        raise typer.Exit(0)
    typer.echo(f"{'NAME':22} {'TARGET':18} {'STATUS':10}  SVC/FIND/CRED")
    for s in summaries:
        flag = " (archived)" if s.archived else ""
        counts = f"{s.service_count}/{s.finding_count}/{s.credential_count}"
        typer.echo(f"{s.name[:22]:22} {s.target[:18]:18} {s.status[:10]:10}  {counts}{flag}")


@app.command("findings")
def findings_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    service: str | None = typer.Option(None, "--service", help="Only findings from this module."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Print the structured findings a profile has collected (the Findings view, headless)."""
    from oscprecon import finding_severity
    from oscprecon import findings as findings_mod
    from oscprecon.modules.http.parsers import interesting_path_reason

    rows = findings_mod.load_findings(_profile_dir(profile, workspace))
    if service is not None:
        rows = [r for r in rows if str(r.get("module", "")) == service]
    if not rows:
        typer.echo("[findings] none recorded yet.")
        raise typer.Exit(0)
    for r in rows:
        mod = str(r.get("module", "?"))
        head = str(r.get("kind") or r.get("path") or "").strip()
        val = str(r.get("value") or r.get("status") or "").strip()
        detail = str(r.get("detail") or r.get("note") or "").replace("\n", " ").strip()
        # parity with the GUI FindingsView / DiscoveredUrlsPanel: show the severity category + a
        # notable mark, and flag a source/backup/VCS disclosure or upload dir (was CLI-silent).
        category = finding_severity.classify(str(r.get("kind", "")), val, detail)
        mark = "‼" if finding_severity.is_notable(category) else " "
        reason = interesting_path_reason(str(r.get("path", ""))) if r.get("path") else ""
        warn = f"   ⚠ {reason}" if reason else ""
        typer.echo(f"{mark} [{category}][{mod}] {head} {val}  {detail}{warn}".rstrip())


@app.command("health")
def health_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    repair: bool = typer.Option(
        False, "--repair", help="Fix the repairable issues (creds perms, stale temp)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Check a profile's health (creds perms, stale temp, lock/schema) — optionally repair it."""
    from oscprecon.workspace import health as health_mod

    root = workspace if workspace is not None else config.workspace_root()
    directory = _profile_dir(profile, workspace)
    issues = health_mod.check_profile(directory, workspace_root=Path(root))
    if not issues:
        typer.echo("[health] no issues — profile is clean.")
        raise typer.Exit(0)
    for issue in issues:
        mark = {"error": "!!", "warning": " !", "info": "  "}.get(issue.severity, "  ")
        typer.echo(f"{mark} [{issue.severity}] {issue.code}: {issue.message}")
    if repair:
        fixed = health_mod.repair_creds_permissions(directory)
        removed = health_mod.repair_remove_stale_temp(directory)
        typer.echo(
            f"[health] repaired: creds perms {'set' if fixed else 'ok'}; "
            f"removed {len(removed)} stale temp file(s)."
        )


@app.command("activity")
def activity_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    limit: int = typer.Option(50, "--limit", "-n", help="Most-recent N events."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Print the profile's audit-trail timeline (audit.jsonl) — the Activity view, headless."""
    from oscprecon.workspace import activity as activity_mod

    events, total = activity_mod.load_activity(_profile_dir(profile, workspace), limit=limit)
    if not events:
        typer.echo("[activity] no recorded activity.")
        raise typer.Exit(0)
    for event in events:
        typer.echo(f"  {event.timestamp}  {event.event_type:16} {event.description}")
    if total > len(events):
        typer.echo(f"  … {total - len(events)} older event(s) not shown (raise --limit).")


@app.command("delete-project")
def delete_project_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Permanently delete a project folder (lock-safe). Destructive — asks first unless --yes."""
    from oscprecon.workspace import portability

    root = workspace if workspace is not None else config.workspace_root()
    directory = _profile_dir(profile, workspace)
    if not yes and not typer.confirm(f"Permanently delete {directory}? This cannot be undone."):
        typer.echo("[delete] cancelled.")
        raise typer.Exit(0)
    try:
        portability.delete_project(directory, Path(root))
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"[deleted] {directory}")


@app.command("searchsploit")
def searchsploit_cmd(
    product: str = typer.Argument(..., help="Product name, e.g. 'vsftpd' or 'apache'."),
    version: str = typer.Argument("", help="Optional version, e.g. '2.4.49'."),
) -> None:
    """Version-aware Exploit-DB lookup (display-only — never downloads or runs a PoC, §14)."""
    import tempfile

    from oscprecon import references

    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        result = references.search_exploits(product, version, Path(tmp.name))
    if not result.hits:
        typer.echo(f"[searchsploit] no hits for '{product} {version}'.".rstrip())
        raise typer.Exit(0)
    scope = {"version": "version-specific", "product": "product-wide (version had no title match)"}
    typer.echo(
        f"# {result.query}  —  {scope.get(result.scope, result.scope)}  ({result.total} total)\n"
    )
    for hit in result.hits:
        star = "★ " if hit.version_match else "  "
        badge = f"[{hit.type or '?'}/{hit.platform or '?'}]"
        typer.echo(f"{star}EDB-{hit.edb_id:7} {badge:20} {hit.title}")
        typer.echo(f"     {hit.url}")


@app.command("hosts")
def hosts_cmd(
    ip: str = typer.Argument(..., help="IP to map (usually the target IP)."),
    names: list[str] = typer.Argument(
        ..., help="One or more hostnames/vhosts, e.g. research.bedside.htb admin.bedside.htb"
    ),
    hosts_file: Path = typer.Option(
        Path("/etc/hosts"), "--file", help="hosts file to edit (default /etc/hosts)."
    ),
) -> None:
    """Add a discovered vhost/hostname to /etc/hosts so it resolves (idempotent).

    Needs root to write /etc/hosts — if it can't, it prints the exact sudo command to run instead.

    Example:

    ```
    nabu-cli hosts 10.10.10.5 research.bedside.htb   # sudo nabu-cli hosts ... to write directly
    ```
    """
    from oscprecon import hosts as hosts_mod

    try:
        result = hosts_mod.add_entry(ip, names, hosts_file)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    except OSError:
        cmd = hosts_mod.sudo_append_command(ip, names)
        typer.echo(
            f"[hosts] can't write {hosts_file} (need root). Run this instead:\n  {cmd}", err=True
        )
        raise typer.Exit(1) from None
    typer.echo(f"[hosts] {result.message}")


creds_app = typer.Typer(help="Manage the profile credential vault (creds.json, chmod 600).")
app.add_typer(creds_app, name="creds")


@creds_app.command("list")
def creds_list_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """List stored credentials (secrets masked, like the GUI vault)."""
    prof = _load_profile(profile, workspace)
    entries = prof.credentials()
    if not entries:
        typer.echo("[creds] none stored.")
        raise typer.Exit(0)
    for c in entries:
        who = f"{c.domain}\\{c.username}" if c.domain else c.username
        masked = f"<{c.secret_type} len={len(c.secret)}>"
        typer.echo(f"  {who:32} {masked:20} {c.source}")


@creds_app.command("add")
def creds_add_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    username: str = typer.Option(..., "--user", "-u", help="Username."),
    secret: str = typer.Option(..., "--secret", "-s", help="Password or hash."),
    secret_type: str = typer.Option("password", "--type", help="password | hash."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain (optional)."),
    source: str = typer.Option("cli", "--source", help="Where it came from."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Record a credential in the vault (creds.json is written chmod 600)."""
    from oscprecon.models import Credential

    prof = _load_profile(profile, workspace)
    prof.add_credential(
        Credential(
            username=username, secret=secret, secret_type=secret_type, domain=domain, source=source
        )
    )
    typer.echo(f"[creds] stored {domain + chr(92) if domain else ''}{username} ({secret_type}).")


@creds_app.command("rm")
def creds_rm_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    username: str = typer.Option(..., "--user", "-u", help="Username to remove."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain (to disambiguate)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Delete a credential from the vault by username (+ optional domain)."""
    prof = _load_profile(profile, workspace)
    matches = [
        c
        for c in prof.credentials()
        if c.username == username and (not domain or c.domain == domain)
    ]
    if not matches:
        typer.echo(f"[creds] no credential for '{username}'.", err=True)
        raise typer.Exit(1)
    for c in matches:
        prof.delete_credential(c)
    typer.echo(f"[creds] removed {len(matches)} credential(s) for '{username}'.")


@app.command("config")
def config_cmd(
    spray: bool | None = typer.Option(
        None, "--spray/--no-spray", help="Enable/disable Spray mode (§2a)."
    ),
    exploit: bool | None = typer.Option(
        None, "--exploit/--no-exploit", help="Enable/disable exploit execution (§2b)."
    ),
) -> None:
    """Show or toggle the opt-in mode gates (Spray mode / Exploit execution). No arg = show."""
    from dataclasses import replace

    settings = config.load_settings()
    if spray is None and exploit is None:
        typer.echo(f"spray_enabled   = {settings.spray_enabled}")
        typer.echo(f"exploit_enabled = {settings.exploit_enabled}")
        raise typer.Exit(0)
    updated = replace(
        settings,
        spray_enabled=settings.spray_enabled if spray is None else spray,
        exploit_enabled=settings.exploit_enabled if exploit is None else exploit,
    )
    config.save_settings(updated)
    typer.echo(
        f"[config] spray_enabled={updated.spray_enabled} exploit_enabled={updated.exploit_enabled}"
    )


@app.command("spray")
def spray_cmd(
    service: str = typer.Argument(..., help="Service key: smb | winrm | ldap | ssh | ftp | rdp."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    port: int = typer.Option(0, "--port", help="Override the discovered port (0 = tool default)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Password-spray a service using the vault creds (opt-in Spray mode, §2a — OFF by default)."""
    from oscprecon import spray as spray_mod

    if not config.spray_enabled():
        typer.echo(
            "[error] Spray mode is OFF (exam-legal default). Enable it with "
            "`nabu-cli config --spray`, then re-run. Only spray your own authorized target.",
            err=True,
        )
        raise typer.Exit(2)
    prof = _load_profile(profile, workspace)
    users, passwords = spray_mod.vault_material(prof.credentials())
    if not users or not passwords:
        typer.echo(
            "[error] the vault has no usernames/passwords to spray — add some with `creds add`.",
            err=True,
        )
        raise typer.Exit(2)
    try:
        user_file, pass_file = spray_mod.write_spray_lists(prof.directory, users, passwords)
        command = spray_mod.build_spray_command(
            service, prof.target.ip, user_file, pass_file, port or None
        )
        typer.echo(f"[spray] {command}")
        redactor = spray_mod.make_redactor(passwords)
        out = prof.directory / f"spray/{service}.txt"
        spray_mod.secure_output_file(
            out
        )  # 0600 — the spray log holds the winning cred in cleartext
        shell.run(
            command,
            out,
            cwd=prof.directory,
            spray=True,
            on_line=lambda line: typer.echo(redactor(line)),
        )
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    finally:
        spray_mod.clean_spray_artifacts(prof.directory)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
