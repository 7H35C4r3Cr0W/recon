from __future__ import annotations

import json
import threading
from pathlib import Path

from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _service(port: int) -> DiscoveredService:
    return DiscoveredService(port=port, proto=Proto.TCP, service="http", discovered_at="")


def test_parallel_writers_do_not_lose_services_or_commands(tmp_path: Path) -> None:
    # scans now run in parallel, so save()/add_command()/merge_services() are reachable from several
    # threads. Without the profile lock this loses services and mints duplicate command ids.
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    threads = 8
    per_thread = 10
    barrier = threading.Barrier(threads)

    def worker(index: int) -> None:
        barrier.wait()
        for step in range(per_thread):
            port = 1000 + index * per_thread + step
            profile.merge_services([_service(port)])
            profile.add_command({"shell_line": f"cmd {port}"})  # id minted atomically
            profile.save()

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    expected = {1000 + i for i in range(threads * per_thread)}
    assert {s.port for s in profile.discovered_services} == expected
    assert len(profile.command_history) == threads * per_thread
    ids = [entry["id"] for entry in profile.command_history]
    assert len(set(ids)) == len(ids), "command ids must be unique across concurrent workers"

    payload = json.loads((tmp_path / "box" / "profile.json").read_text(encoding="utf-8"))
    assert isinstance(payload["discovered_services"], list)  # never a torn write


def test_merge_never_truncates_earlier_discovery(tmp_path: Path) -> None:
    # a narrow scan finishing after a broad one must ADD to discovery, not replace it with its
    # own view — the failure mode that makes parallel scanning lose ports.
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.merge_services([_service(80), _service(443), _service(8080)])
    profile.merge_services([_service(445)])
    assert {s.port for s in profile.discovered_services} == {80, 443, 445, 8080}


def test_merge_fills_blank_product_from_a_later_versioned_scan(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.merge_services([DiscoveredService(port=80, proto=Proto.TCP, service="http")])
    profile.merge_services(
        [
            DiscoveredService(
                port=80, proto=Proto.TCP, service="http", product="nginx", version="1.18"
            )
        ]
    )
    only = [s for s in profile.discovered_services if s.port == 80]
    assert len(only) == 1
    assert only[0].product == "nginx"
