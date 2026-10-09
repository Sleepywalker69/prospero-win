# Clean Wine Notepad seed

This optional artifact contains a fresh Wine prefix generated on the hosted
builder, then converted by the matching original `pw_prefix.py`. You do not
need to run Wine or WSL locally to prepare this prefix. It is not on-console
Wine initialization, a Battle.net installation or proof of Windows child support.

Use it only with the matching software-GDI diagnostic kit from producer run
37861508535. The seed manifest binds that kit, its host-Wine checkpoint, source
revision, conversion code and CPU DLL. It contains only original Wine software
and generated clean configuration, without games, vendor installers or accounts.

## Files and first test

1. Extract the artifact into a new folder and verify its `SHA256SUMS`. Keep
   `SEED-MANIFEST.json` and the matching kit's manifest with the test log.
2. Close prospero-win before copying any prefix/runtime files. Use your existing
   working console file-transfer method and the matching complete kit's app
   installation instructions. This seed supplies only data below
   `console/data/prospero-win`.
3. Confirm `/data/prospero-win/prefixes/diagnostic-notepad` and
   `/data/prospero-win/profiles/diagnostic-notepad.profile` do not already exist.
   If either exists, stop and preserve it. This package is for a fresh test and
   must not replace game state, saves or an earlier diagnostic prefix.
4. Copy the new prefix directory and the one new profile from the seed to those
   exact locations. Preserve hidden `.pw-symlinks` files: these are the
   console's drive mappings and must remain ordinary files. Do not recreate
   native symbolic links or copy the unconverted host prefix.
5. This artifact deliberately contains no `profiles.lst`. When that index is
   absent, the existing launcher scans the profile directory. If an index
   already exists, preserve its current contents and append the single line
   `diagnostic-notepad.profile` only if it is missing and there are fewer than
   16 profile entries. Blank lines and lines beginning with `#` or `;` do not
   count. At 16 entries, stop: appending another makes the entire catalog
   invalid. Preserve existing entries; a separate test-library catalog requires
   an explicit operator decision. Never automatically remove entries or replace
   the index with a file containing just this diagnostic.
6. Start prospero-win and select Wine Notepad diagnostic. Record whether the
   window appears and input/normal close work. Collect its saved session log
   before later sessions rotate it away. Stop after a crash, hang, missing
   runtime error or incomplete close; preserve the exact stage and manifests.

On Windows, open PowerShell in the extracted seed folder and verify without
Linux or WSL:

```powershell
Get-Content .\SHA256SUMS | ForEach-Object {
    $expected, $relative = $_ -split '  ', 2
    $actual = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw "Hash mismatch: $relative" }
}
```

On Linux, the equivalent command in that folder is
`sha256sum --check SHA256SUMS`. Any mismatch is a stop condition.

A successful hosted initialization is not a PS5 pass. The first meaningful
console observation is the original Notepad window running with the matching
runtime and prefix. This package does not add Vulkan/DXVK, Battle.net services,
game installation, Windows child processes or Retail WoW compatibility.

## Producer and audit contract

The optional job downloads only the fixed checkpoint and kit artifacts, checks
their outer SHA256, successful producer identity, complete file manifests,
source archive hashes and original tool/recipe hashes before executing Wine.
It runs the fixed Wine-only recipe under a fresh HOME/XDG/TMP environment,
without inherited CI tokens or host-user configuration. Optional Gecko, Mono,
DXVK and menu integration are disabled by the original recipe/tool behavior.
It performs no vendor/client/account operation or network probe.

After initialization and a successful matching wineserver wait, export audits
every resolved source. External file symlinks may resolve only to the exact
bound host runtime; external directories become empty directories using the
existing converter. Copied PE/font/data bytes must match the bound runtime
or its bounded Wine data/WinSxS resources. Only narrowly named generated
registry/INI/timestamp files are allowed. Host paths in generated text, special files, traversal, case collisions and runtime
virtual-link limits are checked. An unknown file fails the job for review;
the producer must not silently widen the allowlist or ship a raw prefix.

Failure diagnostics contain only metadata and at most 128 KiB of the fixed
sterile initializer's filtered log. Secret, registry-dump or binary patterns
withhold the log entirely; its size/hash remain available. The raw prefix,
registries, failed export and unfiltered log are never uploaded.

The output contains original notices, matching project/Wine source archives,
the exporter source, a source-content audit, a separate seed manifest and file
hashes. Registry timestamps and generated identifiers may vary, so this is an
exact hashed build artifact rather than a byte-reproducibility claim.

The source artifacts expire under their original retention policy. Expiration
or an identity mismatch requires a new explicitly reviewed input binding;
there is no fallback to latest artifacts or a different Wine installation.
