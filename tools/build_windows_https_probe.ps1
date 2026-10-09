# SPDX-License-Identifier: LGPL-2.1-or-later
param([string]$Out = '')
$ErrorActionPreference = 'Stop'
if (!$Out) { $Out = Join-Path $PSScriptRoot '..\build\windows-https-probe-x64' }
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\tests\fixtures\windows_https_probe.c')).Path
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force $Out | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'Preinstalled Visual Studio C++ tools required; this script installs nothing.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'No installed x64 MSVC toolchain found.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
$exe = Join-Path $Out 'windows-https-probe.exe'
$object = Join-Path $Out 'probe.obj'
$command = 'call "{0}" > nul && cl.exe /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS "{1}" /Fe:"{2}" /Fo:"{3}" /link winhttp.lib crypt32.lib /FIXED:NO /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /INCREMENTAL:NO' -f $vcvars, $source, $exe, $object
& $env:ComSpec /d /s /c $command 2>&1 | Tee-Object -FilePath (Join-Path $Out 'build.log')
if ($LASTEXITCODE -ne 0) { throw "MSVC build failed: $LASTEXITCODE" }
# Inspect the actual linked image as bytes. A COFF compile or header flags
# alone cannot establish usable base relocations or the DLL import closure.
& python (Join-Path $PSScriptRoot 'inspect_windows_https_probe.py') $exe --source $source --output (Join-Path $Out 'PE-VALIDATION.json')
if ($LASTEXITCODE -ne 0) { throw 'Linked HTTPS diagnostic failed static PE/import validation.' }
'{0}  windows-https-probe.exe' -f (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant() |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
@(
    'Original single-process AMD64 WinHTTP DNS/TLS diagnostic; build only.'
    'No executable run, endpoint contact, account use or certificate-store change performed by this script.'
    'TLS1.2 only; one caller-selected HEAD /; no proxy, credentials, redirects or certificate-ignore flags.'
    '25-second process watchdog may terminate the Wine-hosting diagnostic title on timeout.'
    'Pinned Wine collapses certificate reasons: generic TLS failures remain INCONCLUSIVE.'
    'PE-VALIDATION.json records actual linked imports, DIR64 relocations, security flags and source/image hashes.'
    'No claim of PS5 execution, Battle.net compatibility or child-process support.'
) | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.txt')
