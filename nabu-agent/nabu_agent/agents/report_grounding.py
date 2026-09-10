"""Report-grounding validator (Phase 2) — the hard backstop behind "cite your sources".

Rejects/flags any AI-narrative claim not backed by an engine artifact id: a CVE not in edb.json, a
credential not in creds.json, a port not in discovered_services. AI sections are visually delimited
so an operator never mistakes synthesis for ground truth.
"""

from __future__ import annotations


def validate_claims(narrative: str, *, edb_ids: set[str], cred_refs: set[str],
                    open_ports: set[int]) -> list[str]:
    """Return a list of unbacked claims (empty == fully grounded). Wired in Phase 2."""
    raise NotImplementedError
