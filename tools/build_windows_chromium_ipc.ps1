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
$manifest = [ordered]@{
    schema = 'pw-chromium-ipc-build/1'; arch = $Arch; pe_machine = $expectedMachine
    source_sha256 = (Get-FileHash -Algorithm SHA256 $source).Hash.ToLowerInvariant()
    contract_sha256 = (Get-FileHash -Algorithm SHA256 $contract).Hash.ToLowerInvariant()
    executable_sha256 = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
    compiler_selection = 'Exact where cl.exe and /Bv output retained in build.log'
    windows_execution = 'not_run'; ps5_execution = 'not_run'; native_admission = 'not_implemented'
}
# Hash the exact executable resolved by vcvars, rather than an assumed version.
$resolve = 'call "{0}" > nul && where cl.exe' -f $vcvars
$resolved = @(& $env:ComSpec /d /s /c $resolve) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($LASTEXITCODE -ne 0 -or !$resolved) { throw 'Cannot identify the selected MSVC compiler.' }
$manifest.compiler_sha256 = (Get-FileHash -Algorithm SHA256 $resolved).Hash.ToLowerInvariant()
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.json')
'chromium-ipc.exe', 'windows_chromium_ipc.c', 'windows_chromium_ipc_contract.h', 'build.log', 'BUILD-INFO.json' |
    ForEach-Object { $h = Get-FileHash -Algorithm SHA256 (Join-Path $Out $_); '{0}  {1}' -f $h.Hash.ToLowerInvariant(), $_ } |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
