from __future__ import annotations

# Conservative finding classification — the ONE place that decides how a finding is visually framed
# (graph rings, badges, report callouts). Deliberately cautious: a finding is only ever framed as a
# weak posture when the finding KIND itself is evidence of it. An open port, a product/version
# banner, or an Exploit-DB search hit is NEVER, on its own, called a vulnerability — those are
# neutral facts / references. Pure data, no Qt, fully unit-tested.
#
# Categories (weakest visual weight first):
#   info       neutral fact: open port, product/version, banner, username, share name
#   reference  an Exploit-DB / searchsploit lookup — a pointer to read, NOT a confirmed vuln
#   access     anonymous / guest auth or anonymous bind SUCCEEDED (misconfigured access)
#   exposure   readable/writable data reachable without creds (null session, world-readable, …)
#   relay-risk weak security posture (SMB signing disabled, open relay, weak algorithm)

INFO = "info"
REFERENCE = "reference"
ACCESS = "access"
EXPOSURE = "exposure"
RELAY_RISK = "relay-risk"

# categories that deserve a "look here" highlight in the graph (the red ring). info + reference do
# NOT — they must never masquerade as a confirmed weakness.
NOTABLE_CATEGORIES = frozenset({ACCESS, EXPOSURE, RELAY_RISK})

# finding kinds that are purely informational, no matter their value (guards against an open port or
# a version string ever being highlighted)
_INFO_KINDS = frozenset(
    {"port", "service", "product", "version", "os", "banner", "user", "share", "hostname", "vhost"}
)
_REFERENCE_KINDS = frozenset({"edb", "exploit", "searchsploit", "reference", "cve-ref"})
_RELAY_KINDS = frozenset({"open-relay", "algo-weak", "signing"})
_EXPOSURE_KINDS = frozenset({"world-readable", "writable"})
_ACCESS_KINDS = frozenset({"auth", "bind", "access"})

_EXPOSURE_TEXT = ("null session", "world-readable", "world readable", "writable", "no_root_squash")
_ACCESS_TEXT = ("anonymous", "anon ", "guest login")
# a negated signal ('anonymous login DISABLED', 'null session NOT allowed') is a hardened posture,
# not a weakness — suppress the text-fallback escalation when any of these appears in value/detail.
_NEGATION_TEXT = ("disabl", "not allowed", "denied", "rejected", "refused", "no anonymous")


def classify(kind: str, value: str = "", detail: str = "") -> str:
    kind = kind.lower().strip()
    value_l = value.lower()
    text = f"{value_l} {detail}".lower()

    # a share's mere existence is neutral info, but a guest/anon-WRITABLE share is a real exposure
    # (upload / print-job / wide-link write vector — HTB Abducted's foothold) — escalate on write.
    if kind == "share":
        return EXPOSURE if "write" in text else INFO

    # explicit informational / reference kinds win first — never escalate these
    if kind in _INFO_KINDS:
        return INFO
    if kind in _REFERENCE_KINDS:
        return REFERENCE

    # signing is only a risk when it is OFF; on/required is just info
    if kind == "signing":
        return RELAY_RISK if "disabl" in text else INFO
    if kind in _RELAY_KINDS:
        return RELAY_RISK
    if kind in _EXPOSURE_KINDS:
        return EXPOSURE

    if kind in _ACCESS_KINDS and ("anon" in value_l or "null" in value_l or "guest" in value_l):
        # null-session enumeration is an exposure; anonymous/guest auth is an access misconfig
        return EXPOSURE if "null" in value_l else ACCESS

    # value/detail text signals (parser-agnostic), conservative. Skip when the text negates the
    # signal ('anonymous access DISABLED') so a hardened posture stated in a banner/note isn't
    # mis-escalated to a weakness with the red 'look here' ring.
    if not any(neg in text for neg in _NEGATION_TEXT):
        if any(sig in text for sig in _EXPOSURE_TEXT):
            return EXPOSURE
        if any(sig in text for sig in _ACCESS_TEXT):
            return ACCESS

    return INFO


def is_notable(category: str) -> bool:
    return category in NOTABLE_CATEGORIES


ALL_CATEGORIES: tuple[str, ...] = (INFO, REFERENCE, ACCESS, EXPOSURE, RELAY_RISK)


def category_of(finding: dict[str, object]) -> str:
    # ONE place that decides a finding's category, for parsed and operator-entered findings alike.
    # A hand-written finding may carry an explicit `severity` (the operator judged it — they saw
    # the box); anything else is classified conservatively from its kind/value/detail.
    severity = str(finding.get("severity", "")).strip().lower()
    if severity in ALL_CATEGORIES:
        return severity
    return classify(
        str(finding.get("kind", "")),
        str(finding.get("value", "")),
        str(finding.get("detail", "")),
    )
