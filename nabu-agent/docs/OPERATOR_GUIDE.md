# Nabu Agent — operator guide

Day-to-day use of the platform, for analysts and their leads. (Deploying it is a separate doc:
[`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md).)

> **Authorized recon only.** Only run against hosts you own or are contracted to test. The platform
> enforces this — a run's target must be inside the project's authorized scope — but the
> responsibility is yours.

## 1. Sign in

Open `https://<your-host>:8443/` and sign in with the account your admin created (or **Sign in with
SSO** if OIDC is configured). You land on the **Dashboard** — a live feed of activity across your
projects, with counts of active runs, hosts discovered, and anything needing attention.

## 2. Create an engagement (project)

**Engagements → Create.** A project is a scoped container for one assessment. Then, on the project
page:

- **Authorized scope** — add the IPs / CIDRs you're cleared to test (e.g. `10.20.30.0/24`). A run's
  target must fall inside this. Remove targets with the ✕.
- **Team** — add colleagues by email as **owner / operator / viewer**:
  - *viewer* — watch runs and read reports, nothing else.
  - *operator* — run recon, edit scope, decide approvals.
  - *owner* — everything, plus manage the team and the attack gates.
- **Settings** — pick a scan profile (`quick` / `default` / `exam` / `full`) and, if an engagement
  authorizes it, the spray/exploit gates (owner only — and still only half the lock; see §6).

## 3. Run recon

**Run recon** on the project page: enter a target that's in scope and pick a kind:

- **scan** — deterministic recon (nmap + service enumeration). Works today, no model needed.
- **agent** — the LLM roster plans and enumerates per service. Needs the model attached (Admin → LLM
  setup); until then it fails cleanly.
- **demo** — a canned animation to show the live map without touching a target.

Starting a run opens the **live map**.

## 4. Read the live map

The map is a BloodHound-style tree that grows and recolours in real time:

| Colour | Meaning |
|---|---|
| 🟢 green (glowing) | active — where the run is working right now |
| 🔵 teal/blue | done |
| 🟡 yellow | stuck / awaiting a decision |
| 🔴 red | error |
| ⚪ grey | queued |

`run → host → service → agent → finding / report`. The log pane streams every action; the view
**auto-reconnects** if your network blips, without losing or duplicating anything.

**Approval gate.** If a range has more live hosts than the safety threshold, the run **pauses** and
the map shows a yellow *Approval required* banner. Review it and click **Approve fan-out** to proceed
or **Reject** to stop — nothing fans out until you decide.

## 5. Report & outputs

**Report & outputs** (from the project page or a finished run) gives you:

- a **findings table**, colour-coded by severity (vulnerable → relay-risk → exposure → access → info);
- the **combined report** — a per-host write-up with suggested next steps, aggregated across the whole
  range;
- **⬇ Export** — download the engagement as a JSON bundle (report + findings + services). Credentials
  are **never** exported.

Any credentials discovered live in the project's **credentials vault** (operator+); the secret values
are never shown in the UI or an export — only which account, where, and where it's been tested.

## 6. The safety model (how attacks work)

Recon is automated; **attacks are never**. A password spray or an exploit runs only when **both** are
true: the owner has turned the per-project gate on **and** a human has approved the specific action on
a server-minted checkpoint. An agent can *propose* an action with a rationale — it can never execute
one. Keep the gates off unless a specific engagement authorizes them.

## 7. Who did what

Every login, run, scope change, approval, and team change is on the project's **Activity** panel
(admins see the whole platform trail under Admin → the audit view). Failed logins and denied actions
are recorded too.

## 8. When something's off

- A run stuck at *awaiting approval* is waiting for **you** — approve or reject it on the run view.
- An `agent` run that fails immediately means the LLM isn't attached yet — ask an admin (Admin → LLM
  setup → Test connection).
- A run whose worker died is auto-failed within ~2 minutes and its slot freed; just start a new one.
