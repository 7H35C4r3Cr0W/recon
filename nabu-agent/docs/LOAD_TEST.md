# Load Testing at /24 Scale

How the platform is load-tested, what the numbers actually prove, and where the
honest gap is. Scope: a class-C (/24, 256 hosts) recon run.

TL;DR: the **event pipeline** and the **per-service fan-out** are measured and
provably bounded. **Per-host fan-out does not exist yet** — the harness synthesizes
/24 event volume, it does not drive 256 real hosts. The RunLimits caps that *would*
bound a real /24 are defined but not yet wired. See [Does it hold up at /24?](#does-it-hold-up-at-24).

---

## 1. How to run the load tests

### The in-process harness (`pytest -m load`)

The `load` marker is registered in `pyproject.toml:81` and **excluded from unit CI**
— you run it explicitly:

```bash
uv run pytest -q -m load            # both /24 load cases
uv run pytest -q -m load -s         # -s to see the printed ev/s + concurrency lines
```

Backend: **sqlite + fakeredis, in-process** (`tests/load/test_cidr_load.py`).
Numbers are therefore *relative* — real Postgres/Redis are faster. The point of the
harness is not a wall-clock benchmark; it is to prove **no unbounded growth**, **strict
seq monotonicity + durability**, and that the **concurrency caps actually hold**.

Two cases:

- `test_cidr_event_pipeline_throughput` — streams a /24 worth of node/finding events
  (256 hosts x 4 svc) through the real `runs._emit` path (seq INCR -> DB persist ->
  Redis publish -> LogPump), then asserts every event persisted, seq strictly
  monotonic with no gaps/dupes, terminal event replayable. Prints ev/s.
- `test_wide_service_fanout_is_bounded` — one host with **300 services**, driven
  through the real API (`POST /runs`), asserts peak concurrent enum agents never
  exceeds `RunLimits.max_concurrent_service_agents` (8) and that every capped service
  got exactly one agent.

### Load-testing a REAL deployment

The harness never renders a frontend and never touches real Postgres/Redis. To
exercise the true stack:

```bash
make up                 # docker compose up -d --build: postgres, redis, migrate,
                        #   api (127.0.0.1:8000), worker (x2), frontend
                        # (see docker-compose.yml; worker capped at 2 cpus / 2g each)
```

Then drive a **wide scope** and **watch storage grow** while it runs:

```bash
# admin-only; row counts for the growth-prone tables
watch -n2 'curl -s -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:8000/api/admin/storage'
# -> {"runs":N,"run_events":N,"agent_tasks":N,"checkpoints":N}
```

`GET /api/admin/storage` (`nabu_agent/routers/admin.py:13`, via
`retention.storage_stats`) is the primary knob to confirm `run_events` growth stays
bounded. `POST /api/admin/retention` triggers the retention sweep on demand (it also
runs hourly on the worker — `worker.py:50`).

**Reality check when driving a real wide scope:** point the scope at a CIDR and the
platform still scans it as a **single host** today (see the gap below) — so a real
`docker compose` run will *not* reproduce the 256-host event volume the harness
synthesizes. To load-test genuine host-parallel behavior you must first close the
per-host fan-out gap. Open the frontend live map (the nginx `frontend` service, https://<host>:8443) during
a wide single-host run to observe the client-side scaling wall (Cytoscape relayout).

---

## 2. Measured results

Backend: sqlite + fakeredis, in-process (`tests/load/test_cidr_load.py`). Real
Postgres/Redis are faster.

| Test | Load | Result | What it proves |
|------|------|--------|----------------|
| Event pipeline throughput | 1537 events (256 hosts x 4 svc + terminals) | **3.05s ≈ 504 ev/s**; all durable; seq strictly monotonic, no gaps/dupes; terminal replayable | `_emit` persist+publish is durable, ordered, bounded under /24 volume |
| Wide service fan-out | 300 services on ONE host | ~2.3s; **300 enum agents, peak concurrency 4** (semaphore cap 8) | per-service fan-out is concurrency-bounded and completes |

Read **504 ev/s as a floor** for the `_emit` pipeline under synthetic stress, not a
real single-host run rate. On real Postgres each event adds a WAL fsync + Redis RTTs
on a serial per-run chain, so per-run event rate is bounded by ~1/commit_latency
regardless of fan-out width (see recs #4).

---

## Does it hold up at /24?

**Partially — and only the parts the harness can reach.**

### Proven

- **Event pipeline is durable, ordered, and bounded.** 1537 events persisted +
  published with strictly monotonic seq, no gaps or dupes, terminal event replayable
  (`test_cidr_event_pipeline_throughput`). Growth is bounded off the hot path:
  retention enforces a 30-day TTL on terminal runs' events + a per-project run cap
  on an hourly cron (`orchestration/retention.py`, `worker.py:50`).
- **Per-service fan-out is concurrency-bounded.** 300 services -> 300 agents, peak
  concurrency held at the semaphore cap (`test_wide_service_fanout_is_bounded`);
  `RunLimits.max_concurrent_service_agents` (default 8) is real and enforced in
  `services/runs.py`.

### The KNOWN GAP: no per-HOST fan-out

There is **no host-level fan-out**. Both real code paths (`services/runs._run_real`,
`_run_agent`) open ONE workspace for one Profile target, call `run_scan` on that
single target, and `asyncio.gather` only over **that one host's services**. There is
no loop over alive hosts, no per-host Profile, no per-host task subtree.
`executor.run_demo` is likewise single-host.

Consequences, all real today:

- The harness's "/24" is **synthetic** — it calls `_emit` 256x4 times directly; it
  never drives 256 hosts through orchestration. The host dimension is **untested**.
- A CIDR scope collapses all hosts into **one Profile folder / one findings.json**,
  and `findings._key()` carries **no host field**, so identical findings across
  different hosts dedupe into one row and lose host attribution
  (`engine/workspace.py`, `oscprecon/findings.py`). `ServiceDTO` and every map node id
  (`svc-{target}-{port}`) are likewise host-less, so two hosts with the same port
  collide on one node.
- The two-pool non-blocking supervisor + DECR fan-in barrier that DESIGN.md names as
  the thing bounding a /24 is **not implemented** — `orchestration/blackboard.py` and
  `orchestration/admission.py` are `NotImplementedError` stubs; the real worker is a
  single blocking supervisor on one 16-slot Arq pool (`worker.py:46,54`). A whole /24
  would live in one worker slot/process = single point of failure.

### The guardrails that WOULD bound a real /24 (and their status)

`orchestration/limits.py` defines the envelope, but most of it is **not yet wired**:

| Guardrail (`limits.py`) | Default | Status |
|-------------------------|---------|--------|
| `max_concurrent_service_agents` | 8 | **Enforced** (measured; inner semaphore) |
| `max_total_tasks` | 512 | **Partially wired** — applied as a flat slice of ONE host's services (`services/runs.py:260`), not a hosts x services global ceiling; fails silently, not as a "capped" event |
| `max_hosts` | 32 | **Dead constant** — read nowhere; `check_alive` returns the host list but `_run_real` discards it |
| `approval_required_above_hosts` | 16 | **Dead constant** — no host-count approval gate exists |
| `max_enum_per_host` | 4 | **Dead constant** — not enforced as a per-host semaphore |
| admission (1 active run/project, profile mutex) | — | **Stub** — `acquire/release_run_slot` raise `NotImplementedError`, called from nowhere; one-active-run index is Postgres-only |

**Verdict:** the event/persistence substrate and per-service fan-out are ready for
/24 volume. The orchestration layer above them is not — per-host fan-out must be
built and the RunLimits host guardrails wired before a real /24 run is safe or even
possible. Until then the caps that are supposed to bound the explosion are largely
inert.

---

## 3. Prioritized recommendations

Ordered by what unblocks a real /24 first, folding in the verified findings.

1. **Build the host tier (CRITICAL — the gap).** Alive-sweep the CIDR, take
   `parsed.hosts`, and for each live host resolve its own Profile and run the existing
   per-service fan-out. Host loop is the outer `gather`; the service semaphore stays
   the inner bound; add a second host-parallelism cap. Nothing else on this list
   matters at /24 until this exists. (`services/runs._run_real`/`_run_agent`)

2. **Give each host its own Profile + thread host through identity (HIGH).**
   `workspace_for(project_id, host_ip)` per live host -> separate findings.json (the
   `_slug`/directory shape already supports it). Add a `host` field to `ServiceDTO`
   and to every node id (`svc-{host}-{port}`, `agent-enum-{host}-{port}`,
   `finding-{host}-...`) and to `findings._key()`, then reconcile into `FindingIndex`
   keyed on host. Without this, /24 findings and the live map silently collapse hosts.
   (`engine/workspace.py`, `oscprecon/findings.py`, `engine/schemas.py`)

3. **Wire the RunLimits host guardrails (HIGH).** Route the alive-sweep result
   through `RunLimits`: clamp live hosts to `max_hosts` (32); when count >
   `approval_required_above_hosts` (16) create an explicit recon approval checkpoint
   before FAN_OUT; enforce `max_enum_per_host` (4) as a per-host inner semaphore; and
   make `max_total_tasks` (512) a run-global counter across the hosts x services
   product that emits a "capped" event instead of the current silent single-host slice
   (`services/runs.py:260`). (`orchestration/limits.py`, `engine/tools.py:80`)

4. **Lift the per-event commit floor (MEDIUM).** `_emit` opens a fresh session +
   COMMIT per event, all under the per-run asyncio lock — this serial commit latency
   is the hard ceiling on a run's event rate (the measured 504 ev/s floor); fan-out
   width cannot raise it. Batch node/finding events the way LogPump batches log lines
   (buffer per run, flush every ~50-100ms as one multi-row INSERT; seq is pre-assigned
   via Redis INCR so order is preserved), or set `synchronous_commit=off` on this
   replayable read-model write path. Publish must stay ordered (WS live-tail dedups on
   seq>last_seq). A real /24's several-thousand events otherwise serialize behind this
   and the live map lags the work. (`services/runs._emit`)

5. **Decide the worker model, then implement it (HIGH but gated on #1).** Either build
   the DESIGN.md two-pool split + DECR re-trigger barrier (so awaiting supervisors
   can't starve host children once they become Arq jobs) and implement
   `admission.acquire/release_run_slot` + `blackboard` single-writer, OR explicitly
   commit to the in-process model and document that a whole /24 lives in one worker
   slot = single point of failure. Do not ship host-children as Arq jobs on the
   current single blocking pool. (`worker.py`, `orchestration/blackboard.py`,
   `orchestration/admission.py`)

6. **Fix the client-side scaling wall (HIGH, and invisible to this harness).** The
   sqlite+fakeredis harness never renders, so it cannot see this: `RunGraph.tsx`
   re-runs a full `breadthfirst` Cytoscape layout **synchronously on every event**,
   with no node cap, virtualization, or debounce — O(V+E) hundreds of times/sec on the
   main thread; a ~1500-node /24 run will freeze the tab. Debounce layout to rAF/~250ms
   and run once per batch; switch to an incremental/preset layout so nodes don't
   reflow; cap rendered nodes (collapse per-host subtrees to a count badge).
   (`frontend/src/components/RunGraph.tsx`, `RunLive.tsx`)

7. **Make WS replay resumable and paged (HIGH).** `ws/routes.py` replays the ENTIRE
   history (`after=0`) as one frame per event on every (re)connect, and
   `replay_events` has no LIMIT — a flaky link re-pays the full cost each reconnect.
   The seq-cursor plumbing already exists (`replay_events(after=...)`,
   `GET /runs/{id}/events?after=`); have the client persist highest-seq and pass it on
   reconnect, page the replay by seq, and send replayed rows as batched arrays. Also
   implement (or delete the docstring for) the documented ~250ms hub coalescing of
   `task.updated`/`log.line` — `RunHub.replay_then_tail` is a `NotImplementedError`
   stub, so events forward 1:1 and drive the layout thrash in #6. (`ws/routes.py`,
   `ws/hub.py`, `ws/client.ts`)

8. **Bound the remaining unbounded buffers (MEDIUM).** Server: the replay spool in
   `ws/routes.py:49` is an unbounded `list` — make it a `maxlen` deque (drop-oldest +
   suppressed counter, mirroring LogPump). Client: `RunLive.tsx` keeps every log line
   in one array (O(n^2) copy) and renders every line to the DOM — keep only the last
   ~2000 lines and virtualize the list. Also evict `_EMIT_LOCKS` entries for
   terminal/reaped runs (the reaper `setdefault`s a lock that is never popped).

9. **Size the DB pool to worker concurrency (LOW).** `db/session.py` uses the
   SQLAlchemy default (5 + 10 overflow = 15) while `worker.py:54` sets `max_jobs=16`;
   16 runs each cycling per-event + heartbeat sessions can exceed the pool. Set
   `pool_size`/`max_overflow` explicitly (~`max_jobs` + headroom) aligned to Postgres
   `max_connections`. Batching events (#4) also cuts session churn, compounding this.

10. **Add a multi-host load case (LOW, do it alongside #1).** The current harness
    validates only the event and per-service dimensions. Once per-host fan-out exists,
    add a load case that actually drives hosts x services volume so the /24 numbers
    cover the host dimension the current tests skip.

---

*Files cited are under `nabu_agent/` unless prefixed `frontend/`. Line numbers are
indicative and may drift.*
