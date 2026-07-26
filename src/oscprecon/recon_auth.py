from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import quote

from oscprecon.models import Credential

# Who the recon authenticates AS.
#
# Every service module used to be anonymous-only: null session, guest, anonymous FTP, anonymous LDAP
# bind. That is the right FIRST move, but it is not the only one — the moment you find a credential
# anywhere (a config file on a web server, a share, a password in a PDF), the same enumeration is
# worth running again as that user, and it returns far more. There was no way to do that: the vault
# existed but only the Exploitation tab read it, so recon stayed stuck on "anon shit".
#
# This is NOT a change to the §11 tier model. That model is about GUESSING: Tier 1 is anonymous,
# Tier 2 is a single attempt against a well-known account with an empty/default password, Tier 3 is
# iterating a list. Supplying a credential the operator already possesses is none of those — it is
# authenticated enumeration, exactly what you do after a foothold, and `shell.policy_violation`
# already allows a single `-u user -p pass` while refusing a list file. Nothing is relaxed here.


@dataclass(frozen=True)
class ReconAuth:
    username: str = ""
    secret: str = ""
    secret_type: str = "password"  # "password" | "hash" (NTLM, for pass-the-hash enumeration)
    domain: str = ""
    kind: str = "null"  # "null" | "guest" | "cred"

    @property
    def anonymous(self) -> bool:
        return self.kind in ("null", "guest")

    @property
    def is_hash(self) -> bool:
        return self.secret_type == "hash" and bool(self.secret)

    @property
    def label(self) -> str:
        if self.kind == "null":
            return "null session"
        if self.kind == "guest":
            return "guest"
        who = f"{self.domain}\\{self.username}" if self.domain else self.username
        return f"{who} ({'hash' if self.is_hash else 'password'})"

    @property
    def output_slug(self) -> str:
        """Output-directory name for this identity — keeps one user's findings out of another's."""
        if self.anonymous:
            return self.kind if self.kind == "guest" else "null-session"
        safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in self.username)
        return f"as-{safe or 'user'}"

    # --- per-tool argument forms -----------------------------------------------------------------
    # One place that knows how each wrapped tool spells "authenticate as this identity", so a module
    # never hand-builds credential syntax and can never leak a password into the wrong flag.

    def netexec_args(self) -> str:
        user = self.username if self.kind != "null" else ""
        if self.kind == "guest":
            user = "guest"
        secret = f"-H '{self.secret}'" if self.is_hash else f"-p '{self.secret}'"
        # why: pass the recorded domain explicitly. Without -d, netexec authenticates against the
        # domain it discovered on the target, which is usually right but silently wrong when the
        # credential belongs to a different domain. A LOCAL account still needs --local-auth — that
        # stays a Tier-2 manual follow-up, not something inferred from a vault entry.
        domain = f" -d '{self.domain}'" if self.domain and self.kind == "cred" else ""
        return f"-u '{user}' {secret}{domain}"

    def smbclient_auth(self) -> str:
        # smbclient wants -N for a true null session; anything else is -U 'DOMAIN/user%secret'.
        # why: the forward-slash domain separator, not a backslash — §11's UNC toggle keeps commands
        # backslash-free so they paste into bash without escaping, and smbclient accepts both.
        if self.kind == "null":
            return "-N"
        if self.kind == "guest":
            return "-U 'guest%'"
        who = f"{self.domain}/{self.username}" if self.domain else self.username
        if self.is_hash:
            # --pw-nt-hash tells smbclient the "password" it was given IS the NT hash
            return f"-U '{who}%{self.secret}' --pw-nt-hash"
        return f"-U '{who}%{self.secret}'"

    def smbmap_args(self) -> str:
        # smbmap takes an NTLM hash in -p exactly like a password
        if self.anonymous:
            user = "guest" if self.kind == "guest" else ""
            return f"-u '{user}' -p ''"
        base = f"-u '{self.username}'"
        if self.domain:
            base += f" -d '{self.domain}'"
        return f"{base} -p '{self.secret}'"

    def rpcclient_auth(self) -> str:
        if self.kind == "null":
            return "-U '' -N"
        if self.kind == "guest":
            return "-U 'guest%'"
        who = f"{self.domain}/{self.username}" if self.domain else self.username
        if self.is_hash:
            return f"-U '{who}%{self.secret}' --pw-nt-hash"
        return f"-U '{who}%{self.secret}'"

    def ldapsearch_args(self) -> str:
        if self.anonymous:
            return "-x"  # simple anonymous bind
        who = f"{self.username}@{self.domain}" if self.domain else self.username
        return f"-x -D '{who}' -w '{self.secret}'"

    def curl_userpass(self) -> str:
        # why: EMPTY for anonymous, not `-u anonymous:anonymous` — curl already logs in anonymously
        # by default, and adding the flag would change every existing anonymous FTP command.
        if self.anonymous:
            return ""
        return f"-u '{self.username}:{self.secret}'"

    def psql_uri(self, host: str, port: int, database: str = "postgres") -> str:
        # why: a connection URI rather than `-U … -w`, because psql reads a password ONLY from
        # PGPASSWORD/.pgpass or a URI — `-w` (never prompt) with neither present just fails. The
        # secret is in argv, exactly as it is for mysql -p and netexec -p; §6 does not redact.
        user = quote(self.username, safe="")
        secret = quote(self.secret, safe="")
        return f"postgresql://{user}:{secret}@{host}:{port}/{database}"

    @classmethod
    def null(cls) -> ReconAuth:
        return cls(kind="null")

    @classmethod
    def guest(cls) -> ReconAuth:
        return cls(username="guest", kind="guest")

    @classmethod
    def from_credential(cls, cred: Credential) -> ReconAuth:
        return cls(
            username=cred.username,
            secret=cred.secret,
            secret_type=cred.secret_type or "password",
            domain=cred.domain,
            kind="cred",
        )


def from_method(method: str) -> ReconAuth:
    """Bridge for the old `method: str` ("null" / "guest") the SMB module threaded around."""
    return ReconAuth.guest() if method == "guest" else ReconAuth.null()


def prefill_identity(
    auth: ReconAuth | None, creds: Sequence[Credential], hostname: str = ""
) -> tuple[str, str, str]:
    """(user, secret, domain) for filling a Tier-2 `{user}/{password}/{domain}` template.

    Prefers the identity the operator PICKED in the "Run as" control — otherwise the Tier-2
    commands would stay filled with an unrelated vault entry while the Tier-1 button above them
    ran as someone else. Falls back to the first usable password credential, as before.
    """
    if auth is not None and not auth.anonymous:
        return auth.username, auth.secret, auth.domain or hostname
    cred = next((c for c in creds if c.secret_type == "password" and c.secret), None)
    if cred is None:
        return "", "", hostname
    return cred.username, cred.secret, cred.domain or hostname
