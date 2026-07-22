from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QDialog, QMessageBox

from oscprecon import config, spray
from oscprecon.gui.dialogs import SprayDialog
from oscprecon.gui.workers import CommandWorker
from oscprecon.profile import Profile

if TYPE_CHECKING:
    from oscprecon.gui.main_window import MainWindow


class SprayController:
    """Owns the opt-in credential-spray flow (§2a): dialog → launch → per-worker cleanup + loot.

    Extracted from MainWindow to shrink the window and keep the spray subsystem in one cohesive
    unit. It drives the shared command-running infrastructure through the window (`_start`,
    `_tasks`, `_command_done`, `_audit_action`) — behaviour is identical to the inlined version.
    The single spray gate (`config.spray_enabled`) is re-read at launch; nothing here relaxes it.
    """

    def __init__(self, window: MainWindow) -> None:
        self._w = window
        self._pending = 0  # launched sprays still running; clean input lists when it hits 0

    def launch(self) -> None:
        w = self._w
        if w._profile is None:
            QMessageBox.information(w, "No profile", "Open or create a profile first.")
            return
        if w._profile.read_only:
            QMessageBox.information(w, "Read-only", "This profile is open read-only.")
            return
        if self._pending > 0:
            # a batch is already running against the shared spray/users.txt+passwords.txt lists — a
            # second launch would clobber _pending and truncate the in-use lists mid-spray
            QMessageBox.information(
                w, "Spray running", "A credential spray is already running — wait or Stop it."
            )
            return
        dialog = SprayDialog(w._profile, config.load_settings().spray_enabled, w)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        # re-read the setting at launch — the single gate; never pass spray=True otherwise.
        if not config.load_settings().spray_enabled:
            return
        # spray ONLY the user-selected subset of the vault (§2a: the operator picks which creds)
        users = dialog.selected_users()
        passwords = dialog.selected_passwords()
        if not users or not passwords:
            QMessageBox.warning(
                w,
                "No credentials selected",
                "Select at least one username and password (add them in the Credential Vault).",
            )
            return
        users_path, passwords_path = spray.write_spray_lists(w._profile.directory, users, passwords)
        profile = w._profile  # capture: results/cleanup always target the ORIGINATING profile
        target = profile.target.ip
        redact = spray.make_redactor(passwords)  # mask winning secrets in streamed tool output
        selected = list(dialog.selected_services())
        launched = 0
        skipped: list[str] = []
        for service in selected:
            if not w._tasks.can_start():
                skipped.append(service)
                continue  # keep scanning the list so the skipped set is complete for the message
            port = spray.discovered_port(service, profile.discovered_services)
            command = spray.build_spray_command(service, target, users_path, passwords_path, port)
            output_file = profile.directory / "spray" / f"{service}.txt"
            spray.secure_output_file(output_file)  # 0600 — it can hold plaintext secrets
            w._tool_panel.append_output(f"$ [spray] {command}")
            w._audit_action("credential-spray", service=service, target=target)
            worker = CommandWorker(command, output_file, cwd=profile.directory, spray=True)
            w._start(
                worker,
                f"spray:{service}",
                partial(self._done, profile=profile, service=service, output_file=output_file),
                on_failed=partial(self._failed, profile=profile),
                line_filter=redact,
            )
            launched += 1
        self._pending = launched  # set before any queued done-callback runs (GUI thread)
        if skipped:  # no silent failures (§24): tell the operator which sprays did not start
            w._tool_panel.append_output(
                f"[spray] deferred {len(skipped)} service(s) — task pool full or a scan is "
                f"running: {', '.join(skipped)}. Re-run spray once it frees up."
            )
        if launched == 0:
            # nothing ran — don't leave the plaintext users/passwords lists orphaned with no worker
            spray.clean_spray_artifacts(profile.directory)

    def _done(self, code: int, profile: Profile, service: str, output_file: Path) -> None:
        # a creds.json write error in _record_success must NOT jam the subsystem (bug #5): without
        # this guard _worker_finished never ran, _pending never reached 0, and the plaintext spray
        # lists were never cleaned. Surface the error, but always finish the worker.
        try:
            self._record_success(profile, service, output_file)
        except Exception as exc:  # noqa: BLE001 — best-effort; never let it wedge the spray pool
            if profile is self._w._profile:
                self._w._tool_panel.append_output(f"[spray] could not record result: {exc}")
        self._w._command_done(code, None)
        self._worker_finished(profile)

    def _failed(self, message: str, profile: Profile) -> None:
        # a spray worker that raised (missing tool, policy refusal) still counts as finished — clean
        # up on this path too, else _pending never reaches 0 and the plaintext lists leak
        self._w._on_run_failed(message)
        self._worker_finished(profile)

    def _worker_finished(self, profile: Profile) -> None:
        self._pending -= 1
        if self._pending <= 0:  # last spray of this launch finished -> drop the input lists
            self._pending = 0
            removed = spray.clean_spray_artifacts(profile.directory)
            if removed and profile is self._w._profile:
                self._w._tool_panel.append_output(
                    f"[spray] removed input lists: {', '.join(removed)}"
                )

    def _record_success(self, profile: Profile, service: str, output_file: Path) -> None:
        # ADD-only confirmation into the originating project's creds.json — never removes a
        # credential, never touches a different active project, never logs the secret.
        try:
            output = Path(output_file).read_text(encoding="utf-8")
        except OSError:
            return
        cred_list = profile.credentials()
        candidates = [(c.username, c.secret) for c in cred_list if c.secret_type == "password"]
        confirmed = set(spray.parse_spray_success(service, output, candidates))
        if not confirmed or profile.read_only:
            return
        label = f"spray-confirmed:{service}"
        changed = False
        for cred in cred_list:
            if (cred.username, cred.secret) in confirmed and label not in cred.tested_against:
                cred.tested_against.append(label)
                changed = True
        if changed:
            profile.set_credentials(cred_list)
            if profile is self._w._profile:
                self._w._tool_panel.append_output(
                    f"[spray] confirmed {len(confirmed)} credential(s)"
                )
                # audit the OUTCOME (a credential validated) — service + count only, no secret
                self._w._audit_action("spray-confirmed", service=service, count=len(confirmed))
