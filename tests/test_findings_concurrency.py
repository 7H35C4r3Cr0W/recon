import threading
from pathlib import Path

from oscprecon import findings as findings_mod


def test_parallel_add_findings_loses_nothing(tmp_path: Path) -> None:
    # why: many recon workers write findings.json concurrently — the lock must make the
    # read-modify-write atomic so no thread's appends are clobbered by another's.
    threads = 8
    per_thread = 25
    barrier = threading.Barrier(threads)

    def writer(worker: int) -> None:
        barrier.wait()  # maximise overlap on the read-modify-write
        for i in range(per_thread):
            findings_mod.add_findings(
                tmp_path, [{"module": "smb", "kind": "user", "value": f"u{worker}-{i}"}]
            )

    workers = [threading.Thread(target=writer, args=(w,)) for w in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    stored = findings_mod.load_findings(tmp_path)
    values = {f["value"] for f in stored}
    assert len(values) == threads * per_thread  # every distinct finding survived
