#!/usr/bin/env python
"""Build the self-contained Nabu demo slideshow (docs/nabu-demo.html) from the screenshot set.

    uv run python docs/build-demo-deck.py   # regenerate after docs/screenshots/generate.py

Embeds every screenshot as a base64 data URI so the deck is offline + CDN-free (Artifact CSP-safe).
Screenshots come from generated demo data only (10.10.10.100 / demo.local; secrets masked).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

SHOTS = Path(__file__).parent / "screenshots"
OUT = Path(__file__).parent / "nabu-demo.html"


def data_uri(name: str) -> str:
    raw = (SHOTS / name).read_bytes()
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


# (kind, title, eyebrow, body, image, caption)  — kind: title | text | image | split
SLIDES: list[dict] = [
    {
        "kind": "title",
        "title": "Nabu",
        "eyebrow": "A guided tour",
        "body": "The local reconnaissance workspace for OSCP prep and exam day. "
        "This deck walks a real session — launch to report.",
        "bullets": ["Recon-only by default", "Runs offline", "Exam-legal, no exploitation"],
    },
    {
        "kind": "text",
        "eyebrow": "Overview",
        "title": "What Nabu is",
        "body": "Nabu wraps the standard enumeration tools you already use (nmap, feroxbuster, "
        "smbclient, netexec, enum4linux-ng…) behind one calm desktop workspace. It runs them "
        "safely, structures what they find, links each service to HackTricks and Exploit-DB, "
        "draws an attack-surface graph, and writes an Obsidian-ready report.",
        "bullets": [
            "One self-contained project folder per box",
            "Every command passes a compliance safety-gate",
            "Credentials stay masked and local — never exposed",
            "No exploitation, no brute-force, no AI at runtime (all opt-in / off)",
        ],
    },
    {
        "kind": "text",
        "eyebrow": "The pipeline",
        "title": "How a session flows",
        "body": "The same shape every time — you stay in control at every step; nothing runs itself.",
        "bullets": [
            "1 · Launch → workspace",
            "2 · New project → enter the target IP",
            "3 · nmap discovers ports & services",
            "4 · Each service routes to its module",
            "5 · Safe per-service recon (Auto / Shown / opt-in Spray)",
            "6 · Findings parsed & conservatively classified",
            "7 · References, graph, and a full report",
        ],
    },
    {
        "kind": "image",
        "eyebrow": "Step 1 — Launch",
        "title": "Your workspace",
        "body": "Nabu opens offline to the workspace dashboard — every project you've worked, "
        "searchable and filterable. First run, it's an invitation to start.",
        "image": "dashboard-empty.png",
        "caption": "Workspace dashboard — empty state",
    },
    {
        "kind": "image",
        "eyebrow": "Step 2 — New project",
        "title": "Enter the target",
        "body": "Type the target IP (and an optional hostname / box name). Nabu creates a "
        "self-contained project folder that will hold everything for this box — reopen it "
        "later and the whole state comes back.",
        "image": "new-project.png",
        "caption": "New Project dialog",
    },
    {
        "kind": "image",
        "eyebrow": "The shell",
        "title": "One workspace, three panes",
        "body": "A primary nav rail on the left (Workspace · Recon · Graph · Findings · Credentials · "
        "Notes · Report · Activity), a compact header showing the project and target, and the "
        "three-pane recon view: services, tools, and references.",
        "image": "shell-dark.png",
        "caption": "The main application shell",
    },
    {
        "kind": "image",
        "eyebrow": "Step 3 — Discovery",
        "title": "Ports & services (nmap)",
        "body": "One click runs nmap in stages — fast top-1000 TCP, full sweep, versioned scan on what's "
        "open, and a UDP pass. Discovered services fill the tree; TCP reads blue, UDP green.",
        "image": "shell-dark.png",
        "caption": "Discovered services in the tree (left pane)",
    },
    {
        "kind": "image",
        "eyebrow": "Step 4-5 — Enumerate",
        "title": "Per-service recon, in tiers",
        "body": "Each module runs safe read-only checks automatically (Tier-1: null session, shares, "
        "banners), shows single default-credential checks for you to click (Tier-2), and keeps "
        "list-based spraying opt-in and off by default (Tier-3). The flagship action is ranked.",
        "image": "smb-tool-panel.png",
        "caption": "SMB recon — Tier-1 auto, Tier-2 manual follow-ups",
    },
    {
        "kind": "image",
        "eyebrow": "Coverage",
        "title": "49 service modules, TCP & UDP",
        "body": "Every service the scanner maps has a dedicated read-only module — the AD/web core "
        "(HTTP, SMB, LDAP, Kerberos, RDP, WinRM, MSRPC), databases (MSSQL/MySQL/Postgres/Oracle/"
        "Redis/Mongo), HTTP-API stores (Elasticsearch, CouchDB, Docker, Kubernetes, etcd), and the "
        "long tail (VNC, IPMI, SIP, rsync, SVN, iSCSI, mDNS, UPnP, RMI, Finger, X11, and more). Each "
        "ships Tier-1 auto recon, Tier-2 follow-ups, a parser, and pattern-based next steps.",
        "image": "services-breadth.png",
        "caption": "One click per service — the tree groups TCP (blue) and UDP (green)",
    },
    {
        "kind": "image",
        "eyebrow": "Web",
        "title": "Content discovery, by dropdown",
        "body": "The HTTP builder reproduces a full feroxbuster/ffuf/gobuster command from controls — "
        "wordlist, extension presets, threads, depth, status codes — and switches tools without "
        "retyping. Password wordlists are filtered out unless Spray mode is on.",
        "image": "http-panel.png",
        "caption": "HTTP content-discovery builder",
    },
    {
        "kind": "image",
        "eyebrow": "Step 6 — Analyze",
        "title": "Findings, framed conservatively",
        "body": "Everything parsed lands in one searchable, filterable view. Crucially, an open port, a "
        "version, or an Exploit-DB match is never called a vulnerability — only real weak "
        "postures (anonymous access, null session, SMB signing disabled) are flagged notable.",
        "image": "findings.png",
        "caption": "Findings — colour-coded conservative categories",
    },
    {
        "kind": "image",
        "eyebrow": "References",
        "title": "HackTricks + Exploit-DB, in-pane",
        "body": "Select a service and the matching HackTricks page loads — bundled offline so it always "
        "works, with an optional live copy — and Exploit-DB is looked up by product/version. "
        "The pane even jumps to the section your findings point at. Reference only; never run.",
        "image": "reference-offline.png",
        "caption": "Reference pane — offline HackTricks + the source badge",
    },
    {
        "kind": "image",
        "eyebrow": "Visualize",
        "title": "The attack-surface graph",
        "body": "Press Ctrl+G for a BloodHound-style map: target → services → findings → credentials. "
        "Notable/weak items are ringed, Exploit-DB references are coloured apart from danger, and "
        "credential secrets are never searchable. Search, drill in, annotate, and export to PNG/SVG.",
        "image": "graph.png",
        "caption": "Attack-surface graph — illustrative (the live view is interactive Cytoscape)",
    },
    {
        "kind": "image",
        "eyebrow": "Credentials",
        "title": "A durable, masked vault",
        "body": "Collected credentials live in the project (file-permission-locked). The table shows the "
        "username, source, and a masked length — never the secret. The plaintext only ever leaves "
        "via an explicit Copy, and even that logs the username only.",
        "image": "credential-vault.png",
        "caption": "Credential Vault — secrets masked, primary/destructive ranking",
    },
    {
        "kind": "image",
        "eyebrow": "Opt-in",
        "title": "Credential spray — gated",
        "body": "Password spraying against your own authorized target is OSCP-legal, so it's supported — "
        "but off by default. You enable Spray mode, pick the credentials, preview the exact "
        "commands, and confirm. Secrets are redacted in the streamed output and on disk.",
        "image": "spray-dialog.png",
        "caption": "Credential Spray — explicit, target-scoped, preview-then-run",
    },
    {
        "kind": "text",
        "eyebrow": "Safety",
        "title": "One gate, every command",
        "body": "Every subprocess — automatic or typed by hand — runs through a single chokepoint that "
        "enforces the exam rules. Blocked actions surface as a clear feedback banner while the "
        "full stream still lands in the output log.",
        "bullets": [
            "No Metasploit / meterpreter, no SQLMap, no commercial scanners",
            "No brute-force / spraying unless you explicitly turn Spray mode on",
            "Blocked → “[blocked] credential brute is Spray-mode only (§2a)”",
            "The default posture is provably recon-only",
        ],
    },
    {
        "kind": "image",
        "eyebrow": "Trail",
        "title": "A complete audit trail",
        "body": "Every action is recorded to an append-only log — commands, setting changes, reference "
        "visits, credential edits (secret redacted). The Activity view reads it back, newest "
        "first: a full, exam-ready record of exactly what you did and when.",
        "image": "activity.png",
        "caption": "Activity — the append-only audit trail",
    },
    {
        "kind": "image",
        "eyebrow": "Step 7 — Present",
        "title": "An Obsidian-ready report",
        "body": "Everything becomes a single markdown report — front-matter, an open-ports summary, "
        "per-service findings with HackTricks links, suggested next steps with sources, and the full "
        "command log with timings. Drop it into your vault and the write-up is half done.",
        "image": "report.png",
        "caption": "The generated report.md, rendered — nothing about what ran is hidden",
    },
    {
        "kind": "split",
        "eyebrow": "Comfort",
        "title": "Light & dark, your call",
        "body": "The whole workspace is theme-aware — pick what's easy on the eyes at 2 a.m. Colour is "
        "always paired with text, so state never depends on colour alone.",
        "image": "shell-light.png",
        "image2": "shell-dark.png",
        "caption": "The same shell, both themes",
    },
    {
        "kind": "text",
        "eyebrow": "Why it's safe to demo",
        "title": "Recon-first, by design",
        "body": "Nabu is built to be run during the exam, not just prep — so the guardrails are the "
        "product, not an afterthought.",
        "bullets": [
            "Recon-only default · exploitation is out of scope entirely",
            "Runs offline · no telemetry, no login, no AI at runtime",
            "Credentials durable + masked; spraying opt-in and target-scoped",
            "Every screenshot here is synthetic demo data — no real host or secret",
        ],
    },
    {
        "kind": "title",
        "title": "A complete recon workspace",
        "eyebrow": "That's the tour",
        "body": "From the moment you enter an IP to the finished report — discovery, enumeration, "
        "findings, references, graph, and write-up, in one calm, exam-legal desktop tool.",
        "bullets": [
            "See the interactive flow + system map — the companion “How Nabu works” page",
            "Every stage is user-driven — nothing runs itself",
        ],
    },
]

USED = {s[k] for s in SLIDES for k in ("image", "image2") if s.get(k)}
IMAGES = {name: data_uri(name) for name in sorted(USED)}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nabu — a guided tour</title>
<style>
:root{
 /* why: dark is the default so the deck and the dark GUI screenshots present easy on the eyes,
    not scalding white in a dim room; the theme button flips to light. Not OS-driven -> deterministic. */
 --ink:#0f1420;--surface:#161d2b;--surface-2:#1b2434;--border:#2a3446;--text:#e6e9ef;
 --muted:#8a94a6;--gold:#c9a227;--gold-soft:rgba(201,162,39,.14);--teal:#5b8a8f;
 --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
 --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
 --mono:"JetBrains Mono","SF Mono","DejaVu Sans Mono",Consolas,monospace;}
:root[data-theme="dark"]{--ink:#0f1420;--surface:#161d2b;--surface-2:#1b2434;--border:#2a3446;
 --text:#e6e9ef;--muted:#8a94a6;--gold:#c9a227;--gold-soft:rgba(201,162,39,.14);--teal:#5b8a8f;}
:root[data-theme="light"]{--ink:#f2ede1;--surface:#fbf8f0;--surface-2:#f4efe2;--border:#ddd3bf;
 --text:#1f2633;--muted:#6b6656;--gold:#9a7415;--gold-soft:rgba(154,116,21,.12);--teal:#3f6f74;}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{font-family:var(--sans);background:var(--ink);color:var(--text);overflow:hidden}
.deck{height:100vh;display:flex;flex-direction:column;
 background-image:radial-gradient(1100px 560px at 88% -10%,var(--gold-soft),transparent 60%)}
.bar{display:flex;align-items:center;gap:12px;padding:10px 22px;border-bottom:1px solid var(--border)}
.bar svg{width:30px;height:30px}.bar .nm{font-family:var(--serif);font-weight:600;font-size:18px}
.bar .tag{color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase}
.bar .sp{flex:1}
.count{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
.tbtn{font-family:var(--sans);font-size:12.5px;color:var(--text);background:var(--surface);
 border:1px solid var(--border);border-radius:8px;padding:6px 11px;cursor:pointer;margin-left:10px}
.tbtn:hover{border-color:var(--gold)}.tbtn:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.stage{flex:1;display:flex;padding:8px 14px;overflow:hidden}
.slide{width:100%;max-width:1840px;margin:auto;height:100%;min-height:0;display:flex;flex-direction:column;justify-content:center;animation:fade .35s ease}
.slide.wide{max-width:none}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.slide{animation:none}}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin:0 0 10px}
h1{font-family:var(--serif);font-weight:600;line-height:1.05;text-wrap:balance;margin:0 0 14px}
.slide h1{font-size:clamp(26px,4vw,44px)}
.lead{font-size:clamp(15px,1.6vw,19px);color:var(--text);max-width:64ch;margin:0 0 16px;line-height:1.5}
ul{margin:10px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px;max-width:70ch}
li{position:relative;padding-left:22px;color:var(--text);font-size:15px}
li::before{content:"";position:absolute;left:2px;top:8px;width:8px;height:8px;border-radius:2px;background:var(--gold)}
.title-slide{text-align:center;max-width:40ch;margin:0 auto}
.title-slide h1{font-size:clamp(40px,7vw,74px)}.title-slide .lead{margin:0 auto 18px}
.title-slide ul{align-items:center}.title-slide li{padding-left:0}.title-slide li::before{display:none}
.title-slide li{color:var(--muted);font-family:var(--mono);font-size:13px}
.imgslide{display:flex;flex-direction:column;height:100%;min-height:0;gap:6px}
.imgslide .cap{flex:0 0 auto}
.imgslide .eyebrow{margin:0 0 2px}
.imgslide h1{font-size:clamp(17px,2vw,25px);margin:0}
.imgslide .lead{font-size:clamp(12.5px,1.15vw,14.5px);line-height:1.4;margin:3px 0 0;max-width:120ch}
.hero{flex:1 1 auto;min-height:0;margin:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px}
.hero .imgwrap{flex:1 1 auto;min-height:0;width:100%;display:flex;align-items:center;justify-content:center;gap:14px}
.hero .imgwrap img{max-width:100%;max-height:100%;width:auto;object-fit:contain;border-radius:8px;border:1px solid var(--border);box-shadow:0 14px 44px rgba(0,0,0,.34);cursor:zoom-in}
.hero figcaption{color:var(--muted);font-size:13.5px;line-height:1.4;flex:0 0 auto;text-align:center;max-width:120ch;margin:0 auto}
.hero figcaption b{color:var(--gold)}.hero figcaption i{color:var(--text);font-style:normal}
#lb{position:fixed;inset:0;background:rgba(6,9,14,.93);display:none;align-items:center;justify-content:center;z-index:99;cursor:zoom-out;padding:22px}
#lb.on{display:flex}
#lb img{max-width:97vw;max-height:93vh;border-radius:8px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.foot{display:flex;align-items:center;gap:14px;padding:9px 22px;border-top:1px solid var(--border)}
.dots{display:flex;gap:6px;flex:1;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--border);border:none;padding:0;cursor:pointer}
.dot[aria-current="true"]{background:var(--gold)}
.dot:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.nav{font-family:var(--sans);font-size:14px;color:var(--text);background:var(--surface);
 border:1px solid var(--border);border-radius:8px;padding:8px 16px;cursor:pointer}
.nav:hover{border-color:var(--gold)}.nav:disabled{opacity:.4;cursor:default}
.nav:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.nav.primary{background:var(--gold);color:var(--ink);border-color:var(--gold);font-weight:600}
.nav.on{border-color:var(--gold);color:var(--gold);font-weight:600}
.brand .m-tile{fill:var(--surface);stroke:var(--gold);stroke-opacity:.4;stroke-width:2}
.brand .m-gold{fill:var(--gold)}.brand .m-teal-f{fill:var(--teal)}.brand .m-teal-s{stroke:var(--teal);fill:none}
</style>
</head>
<body>
<div class="deck">
 <div class="bar">
  <svg class="brand" viewBox="0 0 256 256" aria-hidden="true">
   <rect class="m-tile" x="8" y="8" width="240" height="240" rx="52"/>
   <path class="m-gold" d="M128 40 L142 66 L128 60 L114 66 Z"/><rect class="m-gold" x="125" y="60" width="6" height="20" rx="3"/>
   <g class="m-teal-s" stroke-width="7" stroke-linecap="round"><line x1="128" y1="140" x2="76" y2="100"/>
   <line x1="128" y1="140" x2="188" y2="108"/><line x1="128" y1="140" x2="112" y2="200"/><line x1="188" y1="108" x2="112" y2="200"/></g>
   <circle class="m-gold" cx="128" cy="140" r="17"/><circle class="m-teal-f" cx="76" cy="100" r="11"/>
   <circle class="m-teal-f" cx="188" cy="108" r="11"/><circle class="m-teal-f" cx="112" cy="200" r="11"/>
  </svg>
  <div><div class="nm">Nabu</div><div class="tag">Guided tour</div></div>
  <div class="sp"></div>
  <span class="count" id="count"></span>
  <button class="tbtn" id="theme" type="button">◐ Theme</button>
 </div>
 <div class="stage"><div class="slide" id="slide"></div></div>
 <div class="foot">
  <div class="dots" id="dots"></div>
  <button class="nav" id="play" type="button" aria-pressed="false" aria-label="Play the tour automatically">▶ Play</button>
  <button class="nav" id="prev" type="button">← Back</button>
  <button class="nav primary" id="next" type="button">Next →</button>
 </div>
</div>
<div id="lb" role="dialog" aria-label="Enlarged screenshot"></div>
<script>
const IMAGES=__IMAGES__;
const SLIDES=__SLIDES__;
const slide=document.getElementById('slide');
const dots=document.getElementById('dots');
const count=document.getElementById('count');
let i=0, timer=null;
const AUTOPLAY_MS=6000;
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function bullets(b){return b&&b.length?('<ul>'+b.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>'):'';}
function render(){
 const s=SLIDES[i];
 slide.className='slide'+((s.kind==='image'||s.kind==='split')?' wide':'');
 let html='';
 const head=(s.eyebrow?'<p class="eyebrow">'+esc(s.eyebrow)+'</p>':'')+(s.title?'<h1>'+esc(s.title)+'</h1>':'')
   +(s.body?'<p class="lead">'+esc(s.body)+'</p>':'');
 // image slides: only the eyebrow+title on top (image gets the room); the explanation is the caption
 const htop=(s.eyebrow?'<p class="eyebrow">'+esc(s.eyebrow)+'</p>':'')+(s.title?'<h1>'+esc(s.title)+'</h1>':'');
 const cap=(s.body?esc(s.body):'')+(s.caption?(s.body?'  ·  ':'')+'<i>'+esc(s.caption)+'</i>':'')
   +'  ·  <b>click to enlarge</b>';
 if(s.kind==='title'){slide.innerHTML='<div class="title-slide">'+head+bullets(s.bullets)+'</div>';}
 else if(s.kind==='text'){slide.innerHTML='<div>'+head+bullets(s.bullets)+'</div>';}
 else if(s.kind==='split'){
  slide.innerHTML='<div class="imgslide"><div class="cap">'+htop+'</div>'
   +'<figure class="hero"><div class="imgwrap"><img src="'+IMAGES[s.image]+'" alt=""><img src="'+IMAGES[s.image2]+'" alt=""></div>'
   +'<figcaption>'+cap+'</figcaption></figure></div>';
 } else {
  slide.innerHTML='<div class="imgslide"><div class="cap">'+htop+'</div>'
   +'<figure class="hero"><div class="imgwrap"><img src="'+IMAGES[s.image]+'" alt="'+esc(s.title||'')+'"></div><figcaption>'+cap+'</figcaption></figure></div>';
 }
 slide.querySelectorAll('.hero img').forEach(im=>{im.onclick=()=>openLB(im.src);});
 count.textContent=(i+1)+' / '+SLIDES.length;
 [...dots.children].forEach((d,n)=>d.setAttribute('aria-current',n===i));
 document.getElementById('prev').disabled=i===0;
 document.getElementById('next').disabled=i===SLIDES.length-1;
}
function show(n){i=Math.max(0,Math.min(SLIDES.length-1,n));render();}
function go(n){stopPlay();show(n);}                       // any manual nav halts autoplay
function tick(){show(i>=SLIDES.length-1?0:i+1);}          // autoplay: advance, wrap at the end
const playBtn=document.getElementById('play');
function syncPlay(){const on=timer!==null;playBtn.textContent=on?'⏸ Pause':'▶ Play';
 playBtn.setAttribute('aria-pressed',on);playBtn.setAttribute('aria-label',on?'Pause the automatic tour':'Play the tour automatically');playBtn.classList.toggle('on',on);}
function startPlay(){if(timer!==null)return;timer=setInterval(tick,AUTOPLAY_MS);syncPlay();}
function stopPlay(){if(timer!==null){clearInterval(timer);timer=null;syncPlay();}}
function togglePlay(){timer!==null?stopPlay():startPlay();}
playBtn.onclick=togglePlay;
SLIDES.forEach((_,n)=>{const b=document.createElement('button');b.className='dot';b.type='button';
 b.setAttribute('aria-label','Slide '+(n+1));b.onclick=()=>go(n);dots.appendChild(b);});
document.getElementById('prev').onclick=()=>go(i-1);
document.getElementById('next').onclick=()=>go(i+1);
const lb=document.getElementById('lb');
function openLB(src){stopPlay();lb.innerHTML='<img src="'+src+'" alt="Enlarged screenshot">';lb.classList.add('on');}
lb.onclick=()=>lb.classList.remove('on');
addEventListener('keydown',e=>{
 if(lb.classList.contains('on')){if(e.key==='Escape'||e.key===' '){e.preventDefault();lb.classList.remove('on');}return;}
 if(e.ctrlKey||e.metaKey||e.altKey)return;                          // leave browser shortcuts (Ctrl+P etc.) alone
 const onBtn=e.target&&e.target.closest&&e.target.closest('button');// don't hijack Space activating a focused control
 if(e.key==='ArrowRight'||e.key==='PageDown'||(e.key===' '&&!onBtn)){e.preventDefault();go(i+1);}
 else if(e.key==='ArrowLeft'||e.key==='PageUp'){e.preventDefault();go(i-1);}
 else if(e.key==='Home'){e.preventDefault();go(0);}else if(e.key==='End'){e.preventDefault();go(SLIDES.length-1);}
 else if(e.key==='p'||e.key==='P'){e.preventDefault();togglePlay();}
});
const root=document.documentElement;
root.setAttribute('data-theme','dark');   // present dark by default (easy on the eyes); the button flips to light
document.getElementById('theme').onclick=()=>{
 const cur=root.getAttribute('data-theme')==='dark'?'dark':'light';
 root.setAttribute('data-theme',cur==='dark'?'light':'dark');
};
render();
</script>
</body></html>
"""

html = TEMPLATE.replace("__IMAGES__", json.dumps(IMAGES)).replace(
    "__SLIDES__", json.dumps(SLIDES, ensure_ascii=False)
)
OUT.write_text(html, encoding="utf-8")
kb = len(html.encode()) // 1024
print(f"wrote {OUT}  ({len(SLIDES)} slides, {len(IMAGES)} images, {kb} KB)")
