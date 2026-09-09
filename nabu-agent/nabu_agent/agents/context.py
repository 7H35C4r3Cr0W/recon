"""ContextAssembler — builds the read-only prompt context from the engine (Phase 3).

Pulls discovered_services, findings ranked by finding_severity, exploit.services_present /
suggested_action_ids, references.match — never re-derived. Research fans out over NOTABLE findings
only (finding_severity.is_notable); nmap_scripts_output is summarised, not dumped; ``budget_fit``
truncates by severity/score to the role's token budget.
"""

from __future__ import annotations


class ContextAssembler:
    def __init__(self, project_id: str, scope: str) -> None:
        self.project_id = project_id
        self.scope = scope

    def build(self, role: str, budget_tokens: int) -> dict:
        raise NotImplementedError
