# Contributing to Nabu

Thanks for your interest. Nabu is a recon-first, OSCP-exam-legal desktop tool; the guardrails below
are non-negotiable because the tool has to stay exam-legal by default.

## Setup

```bash
git clone https://github.com/7H35C4r3Cr0W/recon.git && cd recon
uv sync
uv run python -m oscprecon    # launch the GUI
uv run nabu-cli doctor        # check host tools
```

## The four gates (must pass before every commit)

```bash
uv run mypy --strict src/
uv run pytest -q                       # set QT_QPA_PLATFORM=offscreen when headless
uv run ruff check
uv run ruff format --check
```

CI runs the same four on every push and PR.

Coverage is available as a **report, not a gate**:

```bash
uv run pytest --cov                       # terminal summary
uv run pytest --cov --cov-report=html     # browsable report under htmlcov/
```

## Ground rules

- **Stay exam-legal by default.** Do not wrap or ship as an action anything on the `CLAUDE.md` §2
  forbidden list — Metasploit exploitation modules, SQLMap, mass/commercial scanners, list-driven
  credential brute in the default mode, or any runtime LLM call. Credential spraying and manual
  exploitation stay **opt-in and off by default**.
- **All subprocess calls go through `shell.run()`** — never `subprocess` directly outside `shell.py`.
- **Secrets are shown in full** — the owner decision in `CLAUDE.md` §6: the loot IS the
  deliverable, and this is the operator's own tool against their own authorized targets. The
  masking helpers exist but ship OFF. Do not re-introduce redaction as a default. Do keep
  `creds.json` at mode 0600 and out of anything that leaves the project folder unasked.
- **Type hints everywhere; no narrating comments.** Only `# why:` comments for non-obvious decisions.
- **Tests:** parsers are tested against committed fixtures; GUI widgets get `pytest-qt` smoke tests.
- **Keep docs in sync.** A change also updates the README, the bundled guide
  (`src/oscprecon/guide/pages/*.md`, which powers Help → Documentation and `nabu-cli docs`), and
  `CLAUDE.md` where it documents a contract.

## Adding a service module

Read `CLAUDE.md` §7 (module contract) and §11/§12 (tier model). New modules must respect the
Tier 1 / 2 / 3 credential model and cite pattern-library provenance. Read `CLAUDE.md` in full before
proposing anything that touches the constraint surface.
