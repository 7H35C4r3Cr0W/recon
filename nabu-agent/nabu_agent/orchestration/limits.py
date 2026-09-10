"""Concurrency, budget, and IP-range-explosion caps for a run.

These are the safety valves that stop a /24 (or a chatty LLM) from turning one
click into thousands of tool executions or an unbounded token bill. Defaults are
conservative; per-run overrides are clamped to these ceilings.

The engine already supplies a per-STEP watchdog (service_enum._STEP_TIMEOUT_S =
300s) and shell.run kills the whole process group on timeout/cancel. These limits
sit ABOVE that: per-agent wall clock, per-run fan-out width, and LLM budgets.
"""
from __future__ import annotations

from dataclasses import dataclass

# oscprecon clamps its own worker count to config.CONCURRENCY_RANGE; we never
# ask the engine for more than the operator's Settings.max_concurrency.
DEFAULT_MAX_HOSTS_PER_RUN = 32          # alive-check may return a whole /24; cap the fan-out
APPROVAL_REQUIRED_ABOVE_HOSTS = 16      # more than this needs an explicit "yes, scan all N"
DEFAULT_MAX_CONCURRENT_SERVICE_AGENTS = 8   # run-scoped semaphore (Arq max_jobs is global)
DEFAULT_MAX_CONCURRENT_HOSTS = 4            # hosts scanned in parallel for a CIDR run
DEFAULT_MAX_ENUM_PER_HOST = 4           # avoid hammering one host in parallel
DEFAULT_AGENT_WALL_CLOCK_S = 900        # per service/research agent, above the 300s step watchdog
DEFAULT_RUN_WALL_CLOCK_S = 4 * 3600
DEFAULT_MAX_LLM_TOKENS_PER_AGENT = 60_000
DEFAULT_MAX_LLM_TOKENS_PER_RUN = 1_000_000
DEFAULT_MAX_LLM_STEPS_PER_AGENT = 12    # tool-call/plan loop cap per agent
DEFAULT_MAX_TOTAL_TASKS = 512           # hard ceiling on hosts x services fan-out for one run


@dataclass(frozen=True)
class RunLimits:
    max_hosts: int = DEFAULT_MAX_HOSTS_PER_RUN
    approval_required_above_hosts: int = APPROVAL_REQUIRED_ABOVE_HOSTS
    max_concurrent_service_agents: int = DEFAULT_MAX_CONCURRENT_SERVICE_AGENTS
    max_concurrent_hosts: int = DEFAULT_MAX_CONCURRENT_HOSTS
    max_enum_per_host: int = DEFAULT_MAX_ENUM_PER_HOST
    agent_wall_clock_s: int = DEFAULT_AGENT_WALL_CLOCK_S
    run_wall_clock_s: int = DEFAULT_RUN_WALL_CLOCK_S
    max_llm_tokens_per_agent: int = DEFAULT_MAX_LLM_TOKENS_PER_AGENT
    max_llm_tokens_per_run: int = DEFAULT_MAX_LLM_TOKENS_PER_RUN
    max_llm_steps_per_agent: int = DEFAULT_MAX_LLM_STEPS_PER_AGENT
    max_total_tasks: int = DEFAULT_MAX_TOTAL_TASKS

    @classmethod
    def from_settings(cls, max_concurrency: int, **overrides: int) -> RunLimits:
        """Build limits, clamping concurrency to the operator's engine Settings.

        max_concurrency comes from oscprecon.config.Settings (already clamped to
        CONCURRENCY_RANGE). We never spawn more service agents than that.
        """
        capped = {
            "max_concurrent_service_agents": min(
                overrides.pop("max_concurrent_service_agents", DEFAULT_MAX_CONCURRENT_SERVICE_AGENTS),
                max(1, max_concurrency),
            )
        }
        return cls(**{**capped, **overrides})
