# Nabu Agent — deployment runbook

How to stand up Nabu Agent on an internal host. The stack is one Compose project: **api**, **worker**
(×N), **frontend** (nginx), **postgres**, **redis**, plus a one-shot **migrate** job. All recon tools
and the read-only `oscprecon` engine are baked into the api/worker image.

> Authorized use only. This platform runs recon against hosts **you own or are contracted to test**.
> Attacks (spray/exploit) never run automatically — they require a per-project gate **and** a
> human-approved checkpoint.

---

## 1. Prerequisites

- A Linux host on the internal network with **Docker** + the **Compose v2** plugin (`docker compose`)
  or the `docker-compose` binary. ~4 vCPU / 8 GB is comfortable for a worker or two.
- Outbound network from the host to your **engagement ranges** (the workers run the scans) and to your
  **internal LLM endpoint** (when you attach it).
- A **TLS cert + key** from your internal CA for the web edge (or terminate TLS at an org load balancer
  and point it at the frontend).
- The repo checked out (this project lives at `nabu-agent/` beside the read-only `src/oscprecon`).

## 2. Configure

```bash
cd nabu-agent
cp .env.example .env
```

Edit `.env` — the ones that matter for a real deploy:

| Key | Set to |
|---|---|
| `NABU_ENV` | `production` (enables strict checks: refuses empty session secret / default admin password) |
| `NABU_SESSION_SECRET` | `openssl rand -hex 32` |
| `NABU_ADMIN_EMAIL` / `NABU_ADMIN_PASSWORD` | your first admin login + a **strong** password (seeded once, on first boot) |
| `NABU_AGENT_BIND` | `0.0.0.0` to expose the edge on the host, or keep `127.0.0.1` behind an LB |
| `NABU_ALLOWED_EGRESS_CIDRS` | your authorized engagement ranges (defence in depth alongside per-project scope) |
| `NABU_USE_ARQ` | `true` (already set) — runs the distributed worker path |
| `DATABASE_URL` / `REDIS_URL` | leave the compose defaults unless you use external managed services |

Postgres password (referenced by the compose file):

```bash
mkdir -p secrets && openssl rand -hex 24 > secrets/postgres_password.txt
```

TLS for the edge — mount your cert/key where nginx expects them (`/etc/nginx/tls/server.crt` +
`server.key`); add a volume to the `frontend` service, e.g. `./secrets/tls:/etc/nginx/tls:ro`. (Skip
if an org LB terminates TLS and proxies to the frontend.)

Leave `NABU_LLM_*` and `NABU_OIDC_*` blank for now — wire them in §5–6 once the stack is up.

## 3. Bring it up

```bash
make up            # builds the images, starts db+redis, runs migrations, seeds the admin, starts api/worker/frontend
```

`make up` runs `docker compose up -d --build`. The **migrate** job runs `alembic upgrade head` (creates
the schema) then `python -m nabu_agent.bootstrap` (seeds the first admin if no users exist — idempotent).

Tail logs with `make logs`; stop with `make down`.

## 4. Verify

```bash
curl -sk https://<host>:8443/api/health/ready      # {"ready": true, "checks": {"database": true, "redis": true, ...}}
```

Then open `https://<host>:8443/`, sign in as `NABU_ADMIN_EMAIL`, and confirm the dashboard loads.
Smoke-test recon without the LLM: create a project → add an in-scope target → **Start run → scan** →
watch the live map recolour → open **Report & outputs**.

Or drive that whole path end to end (exercising the Redis + Arq worker fan-out) with the scripted
smoke test — point it at an **in-scope** target on your authorized network:

```bash
BASE=https://<host>:8443 TARGET=<in-scope-ip> ADMIN_PASSWORD=<pw> ./deploy/smoke.sh
# waits for readiness → logs in → project + scope → starts a scan → polls to done/partial
# exit 0 = the distributed scan path is healthy; non-zero = failed/timeout (then: docker compose logs worker)
```

## 5. Attach the LLM ("brain")

Sign in as an admin → **LLM setup** (sidebar, Admin). It shows the 3 env vars to set on the api +
worker:

```
NABU_LLM_BASE_URL=https://llm.internal.corp/v1     # OpenAI Chat Completions-compatible
NABU_LLM_API_KEY=sk-…                               # secret; never logged or returned
NABU_LLM_MODEL=gpt-5.1
```

Put them in `.env`, `make up` (recreates api + worker), then click **Test connection** — a green result
with latency + token counts means `agent`-type runs are ready. Until then, `scan` runs work and `agent`
runs fail cleanly with "no LLM configured".

## 6. Single sign-on (optional)

Set `NABU_OIDC_ISSUER` / `NABU_OIDC_CLIENT_ID` / `NABU_OIDC_CLIENT_SECRET` / `NABU_OIDC_REDIRECT_URL`
in `.env` and recreate. A "Sign in with SSO" button appears; users are provisioned on first login
(`NABU_OIDC_FIRST_USER_ADMIN=true` makes the first SSO user an admin). Back-channel logout is wired.

## 7. Add the team

Admin → **Users** to create local accounts and set global roles, or let OIDC provision them. Then, per
project, add members as **owner / operator / viewer** on the project page — a viewer can watch, an
operator can run and edit scope, only the owner manages the team and flips the attack gates.

## 8. Operate an engagement

Create a project → add authorized scope (an IP or a CIDR) → **Start run**. A CIDR sweeps for live hosts
and, above the approval threshold, **parks for your approval** before fanning out. Watch the live agent
map, read the combined report, and **⬇ Export** the bundle (report + findings; credentials are never
exported). Every action is in the project **Activity** log.

## 9. Upgrades, backups, scaling

- **Upgrade:** `git pull && make up` — the migrate job re-runs `alembic upgrade head` (idempotent) and
  images rebuild.
- **Back up:** the `nabu_pgdata` volume (Postgres — users/projects/runs/audit) and the `nabu_workspace`
  volume (engine Profiles — findings/reports). Back both up together.
- **Scale workers:** set `NABU_AGENT_WORKERS` (compose `replicas`); per-run fan-out stays bounded by the
  RunLimits guardrails regardless.

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| `/api/health/ready` → `database:false` | Postgres up? `docker compose logs postgres`; `DATABASE_URL` / `secrets/postgres_password.txt` correct. |
| Runs stay `queued` / never start | The **worker** service is running and `NABU_USE_ARQ=true`; `docker compose logs worker`. |
| A run shows `awaiting_approval` | Expected for a large CIDR fan-out — approve/reject it on the live run view. |
| `agent` runs fail immediately | LLM not attached — see §5 and the LLM setup page. |
| migrate job errors on boot | `docker compose logs migrate`; migrations are idempotent, safe to re-run. |
| A killed run stays "running" | The reaper marks it failed within ~2 min and frees its slot automatically. |

## Security posture (don't relax these)

- Keep the per-project **spray/exploit gates OFF** unless a specific engagement authorizes them — and
  even then, each attack still needs a human-approved checkpoint.
- Set a strong `NABU_ADMIN_PASSWORD` (prod refuses the default) and a random `NABU_SESSION_SECRET`.
- Constrain `NABU_ALLOWED_EGRESS_CIDRS` to authorized ranges.
- `src/oscprecon` is read-only; the api process runs no tools (only the worker does, through the single
  `shell.run` chokepoint).
