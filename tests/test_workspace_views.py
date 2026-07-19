from pathlib import Path

import pytest

from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.workspace import views


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))


def test_builtins_present_and_saved_views_are_filter_only() -> None:
    names = {v.name for v in views.all_views()}
    assert {"Pinned", "Confirmed credentials", "Archived", "PostgreSQL targets"} <= names
    # a SavedView is pure filter config — no profile data / secret fields
    from dataclasses import asdict

    keys = set(asdict(views.BUILTIN_VIEWS[0]))
    assert "secret" not in keys and "credentials" not in keys and "directory" not in keys


def test_crud_and_default(tmp_path: Path) -> None:
    assert views.create_view(views.SavedView("My HTB", tags=["htb"], statuses=["active"]))
    assert not views.create_view(views.SavedView("My HTB"))  # duplicate name rejected
    assert not views.create_view(views.SavedView("   "))  # empty name rejected
    assert views.rename_view("My HTB", "HTB active")
    assert any(v.name == "HTB active" for v in views.load_user_views())
    views.set_default("HTB active")
    assert views.get_default_name() == "HTB active"
    assert views.update_view("HTB active", views.SavedView("HTB active", pinned=True))
    assert views.load_user_views()[0].pinned is True
    assert views.delete_view("HTB active")
    assert views.load_user_views() == []


def test_corrupt_views_file_falls_back_safely(tmp_path: Path) -> None:
    from oscprecon import config

    (config.config_dir() / "saved_views.json").write_text("{ not json")
    assert views.load_user_views() == []  # safe fallback
    assert {v.name for v in views.all_views()}  # built-ins still available


def test_invalid_filter_values_normalized(tmp_path: Path) -> None:
    from oscprecon import config

    (config.config_dir() / "saved_views.json").write_text(
        '{"views": [{"name": "x", "statuses": ["bogus"], "tags": ["Web", "web"], "pinned": "yes"}]}'
    )
    view = views.load_user_views()[0]
    assert view.statuses == ["active"]  # invalid status -> default
    assert view.tags == ["Web"]  # deduped
    assert view.pinned is None  # non-bool coerced to None


def test_restore_defaults_clears_user_views(tmp_path: Path) -> None:
    views.create_view(views.SavedView("temp"))
    assert views.load_user_views()
    views.restore_defaults()
    assert views.load_user_views() == []


def test_apply_view_filters_by_summary_and_service(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    pg = Profile.create(ws, "pg-box", Target(ip="10.0.0.1", platform="htb"))
    pg.set_services([DiscoveredService(5432, Proto.TCP, "postgresql")])
    pg.set_status("active")
    web = Profile.create(ws, "web-box", Target(ip="10.0.0.2", platform="htb"))
    web.set_services([DiscoveredService(80, Proto.TCP, "http")])
    web.set_archived(True)

    active = views.apply_view(views.SavedView("a", statuses=["active"], archived=False), ws)
    assert {s.name for s in active} == {"pg-box"}
    pg_view = views.apply_view(views.SavedView("p", service="postgresql"), ws)
    assert {s.name for s in pg_view} == {"pg-box"}
    archived = views.apply_view(views.SavedView("z", archived=True), ws)
    assert {s.name for s in archived} == {"web-box"}


def test_view_from_dict_tolerates_non_list_statuses() -> None:
    # regression: `statuses` as a non-list (hand-edited saved_views.json) raised TypeError out of
    # load_user_views, whose contract is a safe fallback.
    view = views._view_from_dict({"name": "x", "statuses": 5})
    assert view is not None and view.statuses == []  # coerced, not crashed
    ok = views._view_from_dict({"name": "y", "statuses": ["active"]})
    assert ok is not None and ok.statuses == ["active"]
