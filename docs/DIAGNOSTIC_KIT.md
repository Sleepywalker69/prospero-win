# Software-GDI PS5 diagnostic kit

This is a diagnostic build, not a verified Battle.net installer or game release.
It contains the full matching Wine PE/NLS distribution, the checked PS5 Wine/TLS
modules and fonts, both CPU backends, and the native title/helper. The first
launch target is Wine's own Notepad. Console loading, working entropy, HTTPS
certificate verification and Battle.net installation/login are unverified.

The kit does not include a Vulkan driver, accelerated OpenGL/Zink, DXVK DLLs,
Microsoft runtimes, game files or a vendor installer. Wine patch 0550 still
rejects Windows child-process creation on the console. Packaging cannot make
multi-process installers work. On-console prefix initialization is unsupported;
use the existing PC preparation and push path below.

## Which artifact to use

Use `software-gdi-diagnostic-<commit>-<attempt>`, containing
`prospero-software-gdi-diagnostic.tar.gz`. Preserve the entire archive and its
source/provenance files. Do not treat `host-wine-checkpoint` as a PS5 package:
that earlier artifact retains a completed PC prerequisite if a later build fails.

After extraction the final kit contains:

- `PPSA99995/`: the complete title folder to upload to `/data/homebrew/`
- `PPSA99995/win/wine/lib/wine/{i386-windows,x86_64-windows}/`: Wine PE modules
- `PPSA99995/win/wine/lib/wine/x86_64-unix/`: PS5 PRXs, including TLS and both CPU backends
- `PPSA99995/win/wine/share/wine/{nls,fonts}/` and `ca-certificates.crt`
- `pc/host-wine/usr/`: the matching Linux Wine used to initialize a prefix
- `pc/tools/{pw_install.py,pw_prefix.py}`, `pc/wowprospero.dll`, and the Notepad recipe
- `sources/`, `LICENSES/`, `provenance/`, `KIT-MANIFEST.json`, `FILES.json`, and `SHA256SUMS`

A Wine prefix is intentionally not included. A prefix contains registry/user
state and symbolic links; copying an arbitrary PC prefix directly over FTP is
not a supported substitute for the conversion performed by `pw_prefix.py`.

## 1. Prepare the PC

Use x86_64 Ubuntu 24.04 (native Linux or WSL2). The PC runtime is built on that
system; other operating systems and older C libraries have not been validated.
Have Python 3, its venv support, and the host libraries listed in
[Development](DEVELOPMENT.md#host-setup) available. The build's actual configure
log is included in `provenance/host-configure.log` for missing-library diagnosis.

Extract the tar archive into a new folder. In that folder:

```sh
sha256sum --check SHA256SUMS
python3 -m venv "$HOME/.venvs/prospero-diagnostic"
. "$HOME/.venvs/prospero-diagnostic/bin/activate"
python3 -m pip install pyyaml==6.0.1
./pc/host-wine/usr/bin/wine --version
```

Keep all the kit's files together. No account credentials, game licence keys or
vendor installer are needed for this diagnostic.

## 2. Create a clean Notepad prefix on the PC

From the kit folder, using a new library directory:

```sh
python3 pc/tools/pw_install.py pc/recipes/diagnostic-notepad.yml \
  --library "$HOME/prospero-diagnostic-library" \
  --wine "$PWD/pc/host-wine/usr/bin/wine" --resolution 800x600
```

This runs Wine's prefix initializer only. The recipe disables optional Gecko,
Mono and DXVK downloads and does not run a vendor program. It produces a
`prefixes/diagnostic-notepad/` directory and a matching profile under `profiles/`.
If no desktop display is available, run the same command with `xvfb-run -a`.
Do not reuse an existing game prefix or delete one to satisfy this step.

## 3. Copy the kit and prefix to the PS5

Use your compatible jailbreak, homebrew app loader, FTP server and ELF loader.
The bundled helper expects the ELF loader on the console's local port 9021.
The assistant does not deploy the kit or operate the console.

1. Upload the whole `PPSA99995` folder to `/data/homebrew/` using your FTP client.
2. Preserve executable permissions, or set mode 755 on `eboot.bin`,
   `sce_module/libc.prx`, and every `.prx` in `win/wine/lib/wine/x86_64-unix/`.
3. Register the title with your existing homebrew app loader.
4. Push the new prefix and profile using the supported conversion path:

```sh
python3 pc/tools/pw_prefix.py push diagnostic-notepad \
  --library "$HOME/prospero-diagnostic-library" --host <PS5-IP> \
  --cpu-dll "$PWD/pc/wowprospero.dll"
```

The push converts Wine's CPU registry selection and writes `.pw-symlinks`
tables, transfers `wowprospero.dll`, and updates the launcher's profile list.
Do not pass `--force` over an existing console prefix without first preserving
its state. No `dev.conf` or private network address is bundled.

## 4. First console test

Launch prospero-win and select `Wine Notepad diagnostic`. A software-GDI window
and working text/input are the intended first observation, not an established
hardware result. A USB keyboard/mouse provides a simple input test.
Hold Options + Create to close the app normally and return to the launcher.

If the title returns to Home, shows a black screen, or exits before the window,
stop and retain the log before changing multiple settings. A title failing to
start before any splash also needs its execute permissions and loader checked.

Logs are saved under `/data/prospero-win/logs/`: `session-0.log` through
`session-7.log`, with `next.txt` identifying the next slot. Preserve the newest
session and its `.previous.log` if present, the kit's manifest, and the exact
firmware/jailbreak/loader versions. Review paths and personal information before
posting logs publicly. No live network log receiver is required.

## Vendor-installer experiments

The kit ships no Battle.net installer and performs no vendor/account operation.
Use a separate new prefix and your own lawful installer only after the basic
Wine/GDI launch is established. A first installer window would not prove that
child processes, TLS, login, installation or games work. The console's current
process-creation limitation remains a blocker; do not reinterpret its refusal
as a packaging success.

## Build and provenance

The opt-in workflow builds the full matching host Wine first and checkpoints its
runtime, source and notices. It then uses the existing native-title, TLS,
Wine-PRX and CPU builders in one producer workspace, checks the real PRX build,
and calls `package_release.sh` on its original input directories. A real
disposable host Notepad prefix must initialize before the final kit is emitted;
that prefix is not shipped. All prerequisites must pass. No checksum guard,
module requirement or sanitizer check is bypassed.

The ordinary `ubuntu-24.04` job has a 330-minute limit. This is a resource bound,
not a completion guarantee. It uses read-only repository permissions, no secrets,
no paid larger runner, no console deployment and no release publishing. The
completed artifact, not a timeout or a title-only artifact, is the deliverable.
