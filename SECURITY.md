# Security policy

## What Nabu is (and isn't)

Nabu is a **recon-first, OSCP-exam-legal** workspace. In its default mode it performs **read-only
enumeration only** — it never brute-forces credentials, auto-exploits, chains attacks, or calls any
LLM at runtime, and it runs offline (see `CLAUDE.md` §2). Credential spraying and the manual
Exploitation tab are **opt-in, off by default**, and only ever act against the single target you
assign. Use it only against systems you are authorized to test.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue:

- Preferred: open a private report via the repository's **Security → Report a vulnerability**
  (GitHub private vulnerability reporting).

Include the affected version/commit, a description, and reproduction steps. We aim to acknowledge
within a few days. Please give us reasonable time to fix before any public disclosure.

## Scope

In scope: issues in Nabu's own code — e.g. a path-traversal in project import, secret leakage in a
report/log, or a way to make the tool run an attack in the default recon mode. Out of scope: the
behaviour of the third-party tools Nabu wraps (`nmap`, `netexec`, …) and findings on target systems.
