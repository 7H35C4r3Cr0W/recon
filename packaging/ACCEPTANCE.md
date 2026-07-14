# AppImage acceptance

Record of the actual acceptance pass for the single-click contained app. The build script
(`build-appimage.sh`) is **not** proof of acceptance — this file records a real build + run.

## Artifact

| | |
|---|---|
| Name | `dist/oscp-recon-0.0.1-x86_64.AppImage` |
| Size | 253,213,176 bytes (~242 MiB; AppDir 773 MiB uncompressed) |
| SHA-256 | `b27e2552e51f7f00f5bd7712b6d3cbac81b93f6b4b81fa7ff370ef2439cf27cc` |
| Built on | Kali GNU/Linux Rolling, `Linux 7.0.12+kali-amd64 x86_64` |
| Toolchain | `uv` standalone CPython 3.11.15 + PySide6 6.11.1 (Qt/QtWebEngine bundled in the wheel), packed with `appimagetool` (continuous, build 295) |

> The SHA-256 is specific to one build; a rebuild differs. Regenerate with
> `sha256sum dist/*.AppImage` after building.

## Build-script fixes this pass required

The first two build attempts failed on real defects, both now fixed in `build-appimage.sh`:

1. **`uv pip install` refused the uv-managed interpreter** ("externally-managed-environment").
   Fixed: install with the bundled copy's own `pip` and `--break-system-packages` (it is *our*
   private copy, not a system Python).
2. **Non-relocatable copy** — `uv python find` returns a path through a uv *version symlink*, so
   `cp -a` bundled a dangling link and pip wrote PySide6 into the shared uv store; the first
   "successful" AppImage was 961 KB (empty). Fixed: `readlink -f` the Python root before copying, so
   the bundle holds real files (the artifact is now ~242 MiB with Qt inside).

## Tests run (extracted to `/tmp`, OUTSIDE the source checkout and dev venv)

| Check | Result |
|---|---|
| `appimagetool` runs, artifact packs | ✅ pass |
| Bundled interpreter version | ✅ CPython 3.11.15 |
| `import PySide6` from the bundle | ✅ 6.11.1 |
| `import oscprecon` from the bundle | ✅ 0.0.1 |
| Splash constructs (offscreen) | ✅ pass |
| Bundled data resources (21 HackTricks pages, 108 services.yaml rules, offline SMB page) | ✅ pass |
| QtWebEngine `QWebEngineView` constructs from the bundle | ✅ pass |
| `MainWindow` constructs from the bundle (offscreen) | ✅ pass |
| Clean teardown via `closeEvent` — no "QThread destroyed while running" | ✅ pass (0 warnings) |
| No `ImportError` / `ModuleNotFound` / missing-resource errors | ✅ pass |

## Blocked / not verified in this environment

These need an interactive desktop session and/or another machine; they are **not** marked accepted:

- **Interactive double-click launch** and the visibly-rendered splash (only offscreen construction
  was verified here).
- **Live HackTricks fetch through the AppImage** end-to-end (needs the setting enabled + network at
  run time; the engine + fallback are unit-tested, but not exercised via the packed binary).
- **Graph view / report render / doctor dialog** as pixels on screen (their widgets construct; visual
  rendering not asserted).
- **Icons + `.desktop` integration** in a real desktop menu.
- **Portability to a stripped target.** QtWebEngine's Chromium *system* libs (`libnss3`,
  `libxcomposite1`, `libxdamage1`, `libxrandr2`, `libasound2`) are NOT bundled (linuxdeploy was not
  used). They are present on this Kali box, so QtWebEngine worked; a minimal target must `apt install`
  those or the build must be re-run with `linuxdeploy`.
- **Second clean VM.** Only one host was available.

## Nabu identity (rebrand) — verify on the packed build

The product is **Nabu**; the AppImage carries that identity. Verified here at the input level
(`test_packaging`): `packaging/nabu.desktop` has `Name=Nabu`, `Exec=nabu`, `Icon=nabu`;
`packaging/nabu.png` is the Nabu mark rendered from `icon.svg`; `build-appimage.sh` emits
`dist/Nabu-<version>-<arch>.AppImage`. **Not yet accepted** (need a real build on Kali):

- The produced artifact is actually named `Nabu-<version>-<arch>.AppImage`.
- The desktop entry shows **Nabu** with the Nabu icon in a real application menu.
- The window title, splash, and About dialog read **Nabu** in the packed binary.
- `nabu` / `nabu-cli` console scripts resolve when installed from the wheel (verified out-of-checkout
  in the dev venv; re-check inside the AppImage's bundled interpreter).

## Verdict

The AppImage **builds and runs on this Kali host**: it is self-contained for Python + PySide6 +
QtWebEngine + all app data, and the app object constructs and tears down cleanly from outside the
checkout. Full interactive + cross-machine acceptance — and the Nabu identity on the packed binary —
remain open (see above).
