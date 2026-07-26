from __future__ import annotations

from PySide6.QtCore import Signal

from oscprecon.gui.workers.base import CancellableThread
from oscprecon.profile import Profile
from oscprecon.recon_auth import ReconAuth
from oscprecon.service_enum import (
    CANCELLED_NOTE,
    DnsEnum,
    DnsReconResult,
    FtpEnum,
    FtpReconResult,
    LdapEnum,
    LdapReconResult,
    SmbEnum,
    SmbReconResult,
    SshEnum,
    SshReconResult,
)

# Qt wrappers around the Tier-1 enumeration engines in `service_enum`. The recon itself — the SMB
# null/guest/follow-up/share-walk sequence, FTP's bounded BFS, the peeks, the summaries — lives
# there, Qt-free, so `nabu-cli enum` runs exactly the same code instead of a shallower copy of it.
# These classes exist only to run it on a QThread and turn its output into signals.

__all__ = [
    "DnsReconResult",
    "DnsReconWorker",
    "FtpReconResult",
    "FtpReconWorker",
    "LdapReconResult",
    "LdapReconWorker",
    "SmbReconResult",
    "SmbReconWorker",
    "SshReconResult",
    "SshReconWorker",
]


class _ReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def _build(self) -> object:
        raise NotImplementedError

    def run(self) -> None:
        try:
            engine = self._build()
            result = engine.run()  # type: ignore[attr-defined]
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        if self._cancel.is_set():
            # a cancelled walk broke out of its step loops but still collected + persisted partial
            # findings — mark the run interrupted so the UI/report doesn't read it as a complete
            # enumeration (a half-walked share tree looking 'done'). [#38]
            result.summary.insert(0, CANCELLED_NOTE)
        self.done.emit(result)


class SmbReconWorker(_ReconWorker):
    def __init__(self, profile: Profile, mode: str, auth: ReconAuth | None = None) -> None:
        super().__init__()
        self._profile = profile
        self._mode = mode
        self._auth = auth

    def _build(self) -> SmbEnum:
        return SmbEnum(self._profile, self._mode, self.line.emit, self._cancel, self._auth)


class FtpReconWorker(_ReconWorker):
    def __init__(
        self, profile: Profile, mode: str, port: int, auth: ReconAuth | None = None
    ) -> None:
        super().__init__()
        self._profile = profile
        self._mode = mode
        self._port = port
        self._auth = auth

    def _build(self) -> FtpEnum:
        return FtpEnum(
            self._profile, self._mode, self._port, self.line.emit, self._cancel, self._auth
        )


class SshReconWorker(_ReconWorker):
    def __init__(self, profile: Profile, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._port = port

    def _build(self) -> SshEnum:
        return SshEnum(self._profile, self._port, self.line.emit, self._cancel)


class DnsReconWorker(_ReconWorker):
    def __init__(self, profile: Profile, domain: str, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._domain = domain
        self._port = port

    def _build(self) -> DnsEnum:
        return DnsEnum(self._profile, self._domain, self._port, self.line.emit, self._cancel)


class LdapReconWorker(_ReconWorker):
    def __init__(
        self, profile: Profile, basedn: str, port: int, auth: ReconAuth | None = None
    ) -> None:
        super().__init__()
        self._profile = profile
        self._basedn = basedn
        self._port = port
        self._auth = auth

    def _build(self) -> LdapEnum:
        return LdapEnum(
            self._profile, self._basedn, self._port, self.line.emit, self._cancel, self._auth
        )
