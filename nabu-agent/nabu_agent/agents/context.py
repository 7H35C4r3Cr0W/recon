"""ContextAssembler — builds the read-only prompt-context bundle from the engine (never re-derived).

For the MVP this is a compact JSON summary the role prompt renders; Phase 3+ adds notable-only
research fan-out and severity/score-based budget truncation.
"""

from __future__ import annotations

import asyncio
from typing import Any

from nabu_agent.engine import gateway
from nabu_agent.engine.errors import ProjectNotFound


class ContextAssembler:
    def __init__(self, project_id: str, target: str) -> None:
        self.project_id = project_id
        self.target = target

    async def build(self) -> dict[str, Any]:
        try:
            services = await asyncio.to_thread(gateway.list_services, self.project_id, self.target, None)
            findings = await asyncio.to_thread(gateway.list_findings, self.project_id, self.target, None)
        except ProjectNotFound:
            services, findings = [], []
        return {"target": self.target, "services": services, "findings": findings}
