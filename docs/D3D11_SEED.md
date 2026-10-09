# Derived D3D11 diagnostic prefix

This separate package provides an already initialized, converted Wine prefix
for the original D3D11 clear/readback fixture. Preparing it does not require
Wine, WSL, a vendor installer or an account on the operator's PC. A successful
package check establishes file provenance and a generated launch profile. It
does not establish console loading, GPU presentation, D3D12 or Retail support.

The producer copies the exact accepted Notepad seed into a **new**
`diagnostic-d3d11` prefix. Every existing prefix byte, permission and directory
is preserved, including all registries, six portable fonts, console CPU DLL
and the ordinary `.pw-symlinks` file. The only prefix additions are one directory
and the three exact accepted graphics-overlay files:

- `drive_c/graphics-smoke/d3d11.dll`
- `drive_c/graphics-smoke/dxgi.dll`
- `drive_c/graphics-smoke/d3d11-clear.exe`

The original Notepad seed and software-GDI kit remain separate inputs. The
producer does not initialize Wine again, change a registry, run an installer,
download a DXVK release, execute the fixture or contact a console. It invokes
only the bound original `pw_install.py` parser/constructor and pure `profile()`
method. The actual AMD64 executable header and final complete profile are
checked. Native `d3d11,dxgi=n` overrides belong to that one profile. The preserved seed
contains host Wine builtin PE copies; several differ from the patched runtime
PEs supplied by the matching kit. Pinned Wine source searches its runtime first
for their builtin markers, with a fallback. Actual selection of the patched
runtime remains a console binding check, not a property proved by copying the
seed.

## Input and output contract

The Notepad input is run 37878126672, artifact 11593440576, ZIP SHA256
`f93e8cf113c0954560f56c5d8fb7862d8d9193ce98c43f025965ad74f04eb71d`.
It binds the software-GDI kit from run 37861508535/artifact 11588549010,
project tree `93a62a15aff0376316b7504aba4e3dd35779750b`, and Wine
`490f6d5dcbb2a5047345b8af88d114bbcaad69a8`.

The independently accepted corrected graphics input is run37887109548,
artifact11596543191, ZIP SHA256
`df75b14375b070311c96d82f1463365b4ff9904aeb4161fdb30b57574dee7b7e`.
Its manifest SHA256 is
`e5770735b7f8c9001de867900f02dda9c49aaa35a5f7f289f515c2a3c462fb29`.
[The producer](../tools/build_d3d11_seed.py) binds those exact identities;
there is no fallback to an older artifact, latest run or locally installed Wine.
Successful run/head/artifact metadata, outer and inner hashes, complete file
coverage, modes and directory topology are checked before any output copy.

`DERIVED-MANIFEST.json` records both artifact lineages, the unchanged original
prefix inventory digest, every addition, exact profile hash, and this producer's
commit/tree and source archive. `FILES.json` covers file hashes/modes and all
directories before the inventory and final checksum list themselves are written;
`SHA256SUMS` covers every final regular file except that checksum list itself.
Corresponding source, licences and unchanged input manifests remain in
`provenance/`. Original manifests retained there describe their original input
artifacts; they are not manifests of the derived output directory.

The package intentionally contains no `profiles.lst`. Its only console payload
is a fresh prefix and one profile under `console/data/prospero-win`. The
`provenance/graphics-overlay` directory retains the original overlay for evidence,
including its driver; it is not another console data payload.

## Operator steps

Use this seed only with the exact matching complete kit plus independently
accepted graphics overlay. Preserve the software-GDI/Notepad baseline and pass
that first session before trying a separate graphics session.

1. Verify all package checksums and keep its manifests with the session log.
   On Windows, the same PowerShell `Get-FileHash` method documented for the
   original Notepad seed works without WSL. On Linux, run
   `sha256sum --check SHA256SUMS` in the extracted directory.
2. Close the title. Confirm both
   `/data/prospero-win/prefixes/diagnostic-d3d11` and
   `/data/prospero-win/profiles/diagnostic-d3d11.profile` are absent. Stop if either
   exists; preserve the earlier state rather than overwriting it.
3. Copy only the new prefix and profile to those exact paths with the already
   working transfer method. Preserve hidden `.pw-symlinks` as ordinary files;
   do not turn it into native symbolic links or copy provenance into a prefix.
4. Preserve an existing profile catalog. If an index exists, append
   `diagnostic-d3d11.profile` only when absent and below the 16-entry limit.
   At capacity, stop. If the index is absent, the existing launcher scans profiles.
5. Select Original x64 D3D11 diagnostic only when ready for the separately
   bounded graphics session. It selects `C:\graphics-smoke\d3d11-clear.exe`,
   working directory `C:\graphics-smoke`, `pe64`, `wine-wow64`, `graphics=auto`
   and a 1920x1080 desktop with fit scaling. Collect a fresh complete saved log.

The fixture requests hardware feature level11.0, clears and reads back two
colours, and requires successful Present calls. Its observed25-second deadline
may request termination of the hosting Wine title; it cannot guarantee
interruption of platform/GPU hangs. Stop after a crash, hang, failed map/present,
missing runtime or incomplete close. A passing readback/Present result still
does not prove a visible TV frame, arbitrary shader/draw workloads or game
compatibility. No vendor program or account is part of this seed.

## Reproduction

The tool's `prepare` mode accepts already downloaded exact ZIPs and their
GitHub run/artifact JSON records in a local input directory. It verifies and
extracts them into a fresh owned work directory. `package` rechecks the inputs
and creates a separate fresh output from a clean committed source checkout:

```sh
python3 tools/build_d3d11_seed.py prepare --inputs INPUTS --work WORK
python3 tools/build_d3d11_seed.py package --work WORK --out OUTPUT \
  --repository https://github.com/Sleepywalker69/prospero-win
```

The input files are named `kit`, `seed` and `graphics`, each with `.zip`,
`-run.json` and `-artifact.json`. Python3.12 and PyYAML are the only host software
requirements; no native or Windows executable is invoked. These operations
assume stable owned directories with no concurrent writers. Original Wine
initialization contains timestamps/identifiers, so this is an exactly bound
artifact and deterministic copy validation, not a claim of reproducible Wine
initialization or console runtime success.
