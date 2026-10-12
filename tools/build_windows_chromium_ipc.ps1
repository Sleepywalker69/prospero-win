# SPDX-License-Identifier: LGPL-2.1-or-later
param([ValidateSet('x64', 'x86')][string]$Arch = 'x64', [string]$Out = '')
$ErrorActionPreference = 'Stop'
if (!$Out) { $Out = Join-Path $PSScriptRoot ("..\build\windows-chromium-ipc-{0}" -f $Arch) }
$Out = [IO.Path]::GetFullPath($Out)
if (Test-Path $Out) { throw 'Use a fresh output directory; this diagnostic never overwrites reference evidence.' }
New-Item -ItemType Directory $Out | Out-Null
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\tests\fixtures\windows_chromium_ipc.c')).Path
$contract = (Resolve-Path (Join-Path $PSScriptRoot '..\tests\fixtures\windows_chromium_ipc_contract.h')).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'Preinstalled Visual Studio C++ tools are required; nothing is installed.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'No installed x86/x64 MSVC toolchain found.' }
$vcvarsName = if ($Arch -eq 'x64') { 'vcvars64.bat' } else { 'vcvars32.bat' }
$vcvars = Join-Path $installation ("VC\Auxiliary\Build\{0}" -f $vcvarsName)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$commit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Exact source commit is required.' }
$tree = (& git -C $repo rev-parse 'HEAD^{tree}').Trim()
if ($LASTEXITCODE -ne 0 -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Exact source tree is required.' }
& git -C $repo diff --exit-code HEAD -- .gitattributes tests/fixtures/windows_chromium_ipc.c tests/fixtures/windows_chromium_ipc_contract.h tools/build_windows_chromium_ipc.ps1 tools/check_windows_chromium_ipc.py .github/workflows/windows-chromium-ipc-reference.yml
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic producer/reference inputs differ from the committed source.' }
$exe = Join-Path $Out 'chromium-ipc.exe'
$object = Join-Path $Out 'chromium-ipc.obj'
$command = 'call "{0}" > nul && where cl.exe && cl.exe /Bv /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS "{1}" /Fe:"{2}" /Fo:"{3}" /link advapi32.lib /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO' -f $vcvars, $source, $exe, $object
& $env:ComSpec /d /s /c $command 2>&1 | Tee-Object -FilePath (Join-Path $Out 'build.log')
if ($LASTEXITCODE -ne 0) { throw "MSVC diagnostic build failed: $LASTEXITCODE" }
$image = [IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($image, 60)
$expectedMachine = if ($Arch -eq 'x64') { 0x8664 } else { 0x014c }
$expectedMagic = if ($Arch -eq 'x64') { 0x20b } else { 0x10b }
if ($image[0] -ne 0x4d -or $image[1] -ne 0x5a -or [BitConverter]::ToUInt32($image, $pe) -ne 0x4550 -or
    [BitConverter]::ToUInt16($image, $pe + 4) -ne $expectedMachine -or
    [BitConverter]::ToUInt16($image, $pe + 24) -ne $expectedMagic) { throw 'PE architecture verification failed.' }
Copy-Item $source (Join-Path $Out 'windows_chromium_ipc.c')
Copy-Item $contract (Join-Path $Out 'windows_chromium_ipc_contract.h')
$aliases = [ordered]@{
    'pw-ipc-self-memory.exe' = 'self-memory'
    'pw-ipc-live-memory.exe' = 'live-memory'
    'pw-ipc-suspended-memory.exe' = 'suspended-memory'
    'pw-ipc-section-readonly.exe' = 'section-readonly'
    'pw-ipc-section-duplicate.exe' = 'section-duplicate'
    'pw-ipc-section-close-source.exe' = 'section-close-source'
    'pw-ipc-mojo-pipe.exe' = 'mojo-pipe'
    'pw-ipc-page-regression.exe' = 'page-regression'
}
$executableHash = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
$entries = @()
foreach ($alias in $aliases.Keys) {
    $destination = Join-Path $Out $alias
    if (Test-Path $destination) { throw 'Alias target must be fresh.' }
    Copy-Item $exe $destination
    $hash = (Get-FileHash -Algorithm SHA256 $destination).Hash.ToLowerInvariant()
    if ($hash -ne $executableHash) { throw 'Profile alias is not byte-identical to the diagnostic.' }
    $case = $aliases[$alias]
    $entries += [ordered]@{file=$alias; case=$case; sha256=$hash; arguments=@();
        proposed_profile_id="windows-chromium-ipc-$case-v1"; native_admission='not_implemented'}
}
$copies = [ordered]@{
    'build_windows_chromium_ipc.ps1' = (Join-Path $repo 'tools/build_windows_chromium_ipc.ps1')
    'check_windows_chromium_ipc.py' = (Join-Path $repo 'tools/check_windows_chromium_ipc.py')
    'windows-chromium-ipc-reference.yml' = (Join-Path $repo '.github/workflows/windows-chromium-ipc-reference.yml')
}
foreach ($name in $copies.Keys) { Copy-Item $copies[$name] (Join-Path $Out $name) }
$manifest = [ordered]@{
    schema = 'pw-chromium-ipc-build/2'; arch = $Arch; pe_machine = $expectedMachine
    project = @{commit=$commit; tree=$tree}
    ci = @{repository=$env:GITHUB_REPOSITORY; run_id=$env:GITHUB_RUN_ID; run_attempt=$env:GITHUB_RUN_ATTEMPT}
    recipe_sha256 = (Get-FileHash -Algorithm SHA256 $copies['build_windows_chromium_ipc.ps1']).Hash.ToLowerInvariant()
    checker_sha256 = (Get-FileHash -Algorithm SHA256 $copies['check_windows_chromium_ipc.py']).Hash.ToLowerInvariant()
    reference_workflow_sha256 = (Get-FileHash -Algorithm SHA256 $copies['windows-chromium-ipc-reference.yml']).Hash.ToLowerInvariant()
    empty_argument_entries = $entries
    source_sha256 = (Get-FileHash -Algorithm SHA256 $source).Hash.ToLowerInvariant()
    contract_sha256 = (Get-FileHash -Algorithm SHA256 $contract).Hash.ToLowerInvariant()
    executable_sha256 = $executableHash
    compiler_selection = 'Exact where cl.exe and /Bv output retained in build.log'
    windows_execution = 'not_run'; ps5_execution = 'not_run'; native_admission = 'not_implemented'
}
# Hash the exact executable resolved by vcvars, rather than an assumed version.
$resolve = 'call "{0}" > nul && where cl.exe' -f $vcvars
$resolved = @(& $env:ComSpec /d /s /c $resolve) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($LASTEXITCODE -ne 0 -or !$resolved) { throw 'Cannot identify the selected MSVC compiler.' }
$manifest.compiler_sha256 = (Get-FileHash -Algorithm SHA256 $resolved).Hash.ToLowerInvariant()
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.json')
@('chromium-ipc.exe', 'windows_chromium_ipc.c', 'windows_chromium_ipc_contract.h', 'build.log', 'BUILD-INFO.json') + @($aliases.Keys) + @($copies.Keys) |
    ForEach-Object { $h = Get-FileHash -Algorithm SHA256 (Join-Path $Out $_); '{0}  {1}' -f $h.Hash.ToLowerInvariant(), $_ } |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
