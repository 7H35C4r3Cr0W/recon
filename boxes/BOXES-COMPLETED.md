# Boxes completed — running tally

**TOTAL: 50** ( Starting Point tier: 25 · Field reviews: 25 )

Single source of truth for every box worked in this project. **Update this file every time a box is
finished** — add a row, bump the total. Difficulty is the rating from the box's walkthrough / HTB page.

## Field reviews — harder retired HTB (25)
Live recon **and** attack reviews (most run against the live box, foothold→root where practical).

| # | Box | Difficulty | Platform / theme |
|---|-----|-----------|------------------|
| 1 | Ethereal | Insane | Windows — DNS exfil, OpenSSL LOLBIN, signed-MSI AppLocker |
| 2 | CTF | Insane | Linux — LDAP injection → stoken OTP → 7z privesc |
| 3 | Sizzle | Insane | Windows AD — SCF hash steal → ADCS → Kerberoast → DCSync |
| 4 | Smasher | Insane | Linux — path-traversal LFI + SUID TOCTOU race |
| 5 | Fighter | Insane | Windows — ffuf output-collision recon bug fixed here |
| 6 | Ariekei | Insane | WAF + containers — cert-SAN recon, ImageTragick |
| 7 | Fulcrum | Insane | multi-pivot — XXE→SSRF→RFI, Linux→Win→AD |
| 8 | RopeTwo | Insane | exploit-dev — generic classes only (V8/kernel excluded) |
| 9 | DarkCorp | Insane | Windows/AD — first live-hit box |
| 10 | Holiday | Insane | web — http hostname-fallback fix originated here |
| 11 | Conceal | Hard | Windows — IKE/IPsec firewall bypass, SNMP-leaked PSK |
| 12 | FluJab | Hard | cert-SAN / base64 cookie tamper / OOB SQLi |
| 13 | Falafel | Hard | Linux — type-juggle, upload truncation, video/disk groups |
| 14 | CrimeStoppers | Hard | Linux — zip:// LFI→RCE, firefox_decrypt loot |
| 15 | Tentacle | Hard | Linux — Squid pivot, MIT-Kerberos, OpenSMTPD RCE |
| 16 | Cereal | Hard | Linux — web injection/XSS/SSRF/deserialization |
| 17 | EarlyAccess | Hard | Linux — web injection, ssl-cert CN/SAN→hostname |
| 18 | Spider | Hard | Linux — Python-web (Werkzeug/Flask/Django) |
| 19 | Spooktrol | Hard | JSON-API (uvicorn/FastAPI) detection |
| 20 | Phoenix | Hard | WordPress / robots.txt |
| 21 | Carpediem | Hard | Linux — page-body vhost lead, docker escape |
| 22 | Snoopy | Hard | Linux — whatweb Email→vhost lead |
| 23 | Intense | Hard | Linux — SQLite blind SQLi, hash length-extension, ROP |
| 24 | BigBang | Hard | web |
| 25 | Race | (unrated in notes) | reviewed alongside BigBang |

## Starting Point tier (25)
From `STARTING-POINT-LOG.md` (rows 1–25). Tier I/II are Very-Easy/Easy; Dante is the Pro Lab.

| # | Box | Tier / rating |
|---|-----|--------------|
| 1 | Meow | Tier 0 · Very Easy |
| 2 | Fawn | Tier 0 · Very Easy |
| 3 | Dancing | Tier 0 · Very Easy |
| 4 | Redeemer | Tier 0 · Very Easy |
| 5 | Explosion | Tier 0 · Very Easy |
| 6 | Preignition | Tier 0 · Very Easy |
| 7 | Mongod | Tier 0 · Very Easy |
| 8 | Synced | Tier 0 · Very Easy |
| 9 | Appointment | Tier 1 · Very Easy |
| 10 | Sequel | Tier 1 · Very Easy |
| 11 | Crocodile | Tier 1 · Very Easy |
| 12 | Responder | Tier 1 · Very Easy |
| 13 | Three | Tier 1 · Very Easy |
| 14 | Funnel | Tier 1 · Very Easy |
| 15 | Bike | Tier 1 · Very Easy |
| 16 | Ignition | Tier 1 · Very Easy |
| 17 | Pennyworth | Tier 1 · Very Easy |
| 18 | Tactics | Tier 1 · Very Easy |
| 19 | Vaccine | Tier 1 · Very Easy |
| 20 | Dante | **HTB Pro Lab** (multi-machine) |
| 21 | Archetype | Tier 2 · Easy |
| 22 | Unified | Tier 2 · Easy |
| 23 | Included | Tier 2 · Easy |
| 24 | Markup | Tier 2 · Easy |
| 25 | Base | Tier 2 · Easy |

## Difficulty summary (field reviews)
Insane: 10 · Hard: 14 · unrated: 1
