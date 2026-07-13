import json
from pathlib import Path

from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace.models import Organization, normalize_status, normalize_tags


def _profile(tmp_path: Path) -> Profile:
    return Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))


def test_old_profile_without_organization_loads_with_defaults(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    # simulate a pre-feature profile.json (no organization key)
    raw = json.loads(prof.profile_json_path.read_text())
    raw.pop("organization", None)
    prof.profile_json_path.write_text(json.dumps(raw))
    reloaded = Profile.load(prof.directory)
    org = reloaded.organization_meta()
    assert org.status == "active" and org.tags == [] and not org.pinned and not org.archived


def test_unknown_org_fields_do_not_break_loading(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    raw = json.loads(prof.profile_json_path.read_text())
    raw["organization"] = {"status": "active", "bogus_field": 1, "tags": ["web"]}
    prof.profile_json_path.write_text(json.dumps(raw))
    reloaded = Profile.load(prof.directory)  # must not raise
    assert reloaded.organization_meta().tags == ["web"]


def test_corrupt_organization_value_falls_back(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    raw = json.loads(prof.profile_json_path.read_text())
    raw["organization"] = "not-a-dict"
    prof.profile_json_path.write_text(json.dumps(raw))
    reloaded = Profile.load(prof.directory)
    assert reloaded.organization_meta().status == "active"


def test_status_validation() -> None:
    assert normalize_status("Needs Review") == "needs-review"
    assert normalize_status("bogus") == "active"  # invalid -> default
    assert normalize_status("") == "active"
    assert normalize_status(None) == "active"


def test_tags_normalized_deduped_capped() -> None:
    tags = normalize_tags(["Web", "web", "  ", "LINUX", "linux ", "a" * 200])
    assert tags == ["Web", "LINUX", "a" * 40]  # dedup case-insensitive, empty dropped, len capped
    assert normalize_tags("not-a-list") == []
    assert len(normalize_tags([str(i) for i in range(100)])) == 30  # count capped


def test_add_remove_tag_persists_and_dedups(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    assert prof.add_tag("Web") is True
    assert prof.add_tag("web") is False  # case-insensitive duplicate rejected
    assert prof.add_tag("  ") is False  # empty rejected
    assert Profile.load(prof.directory).organization_meta().tags == ["Web"]
    assert prof.remove_tag("WEB") is True
    assert Profile.load(prof.directory).organization_meta().tags == []


def test_set_status_and_pin_and_archive_persist_atomically(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.set_status("completed")
    prof.set_pinned(True)
    prof.set_archived(True)
    prof.set_display_name("  Example  Web  Server  ")
    reloaded = Profile.load(prof.directory)
    org = reloaded.organization_meta()
    assert org.status == "completed" and org.pinned and org.archived
    assert org.display_name == "Example Web Server"  # whitespace collapsed
    assert not list(prof.directory.glob("*.tmp"))  # atomic temp+rename left nothing behind


def test_organization_never_carries_secret_material(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.set_display_name("x")
    dumped = Organization.from_dict(prof.organization).to_dict()
    assert set(dumped) == {"status", "tags", "pinned", "archived", "display_name"}
