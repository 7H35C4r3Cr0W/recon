"""JSON-serializable I/O shapes for the agent tools.

Every tool returns plain dict/list/str/int/bool so the result can be handed to an
OpenAI-compatible tool-call response verbatim. Engine dataclasses (DiscoveredService,
ShellResult, Scored, ...) are converted here — the LLM never sees an engine object.

TypedDicts document the contract; the ``to_*`` functions do the conversion. We avoid a
hard pydantic dependency in the adapter itself so the engine seam stays import-light; the
API dimension may wrap these in pydantic models at the HTTP boundary.
"""

from __future__ import annotations

from typing import Any, TypedDict


class ServiceDTO(TypedDict):
    port: int
    proto: str
    service: str
    product: str
    version: str
    state: str
    scripts: str


class ShellResultDTO(TypedDict):
    shell_line: str
    exit_code: int
    output_file: str
    duration_s: float
    blocked: str | None
    missing_tool: str | None
    cancelled: bool


class CatalogActionDTO(TypedDict):
    id: str
    title: str
    category: str
    command: str            # template pre-filled from profile evidence (fill_template)
    unfilled: list[str]     # still-missing placeholders
    tool: str
    ports: list[int]
    port_provenance: str
    runs_on: str            # 'attacker' | 'victim'
    executable: bool        # runs_on == 'attacker' (display flag only — NEVER auto-run)
    suggested: bool         # in the evidence-ranked ★ set
    score: int
    why: str
    source: str


def to_service_dto(svc: Any) -> ServiceDTO:
    """oscprecon.models.DiscoveredService -> ServiceDTO. Note: .port not .number."""
    return ServiceDTO(
        port=int(svc.port),
        proto=str(svc.proto),
        service=svc.service or "",
        product=svc.product or "",
        version=svc.version or "",
        state=svc.state or "open",
        scripts=svc.nmap_scripts_output or "",
    )


def to_shell_dto(result: Any) -> ShellResultDTO:
    """oscprecon.shell.ShellResult -> ShellResultDTO."""
    return ShellResultDTO(
        shell_line=result.shell_line,
        exit_code=int(result.exit_code),
        output_file=str(result.output_file),
        duration_s=float(result.duration_s),
        blocked=result.blocked,
        missing_tool=result.missing_tool,
        cancelled=bool(result.cancelled),
    )
