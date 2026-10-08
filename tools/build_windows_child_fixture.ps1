# SPDX-License-Identifier: LGPL-2.1-or-later
param([ValidateSet('x64', 'x86')][string]$Arch = 'x64', [string]$Out = '')
$ErrorActionPreference = 'Stop'
if (!$Out) { $Out = Join-Path $PSScriptRoot ("..\build\windows-child-fixture-{0}" -f $Arch) }
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\tests\fixtures\windows_child_process.c')).Path
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force $Out | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'Preinstalled Visual Studio C++ tools are required; nothing is installed by this script.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'No installed x86/x64 MSVC toolchain found.' }
$vcvarsName = if ($Arch -eq 'x64') { 'vcvars64.bat' } else { 'vcvars32.bat' }
$vcvars = Join-Path $installation ("VC\Auxiliary\Build\{0}" -f $vcvarsName)
$parent = Join-Path $Out 'parent.exe'
$object = Join-Path $Out 'fixture.obj'
# Only this original test image opts out of ASLR, making equal virtual
# addresses observable. No operating-system security setting is changed.
# Relocations remain available: differing load addresses are inconclusive.
$command = 'call "{0}" > nul && cl.exe /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS "{1}" /Fe:"{2}" /Fo:"{3}" /link /DYNAMICBASE:NO /NXCOMPAT /INCREMENTAL:NO' -f $vcvars, $source, $parent, $object
& $env:ComSpec /d /s /c $command 2>&1 | Tee-Object -FilePath (Join-Path $Out 'build.log')
$code = $LASTEXITCODE
if ($code -ne 0) { throw "MSVC fixture build failed: $code" }
$image = [IO.File]::ReadAllBytes($parent)
$pe = [BitConverter]::ToInt32($image, 60)
$machine = [BitConverter]::ToUInt16($image, $pe + 4)
$expectedMachine = if ($Arch -eq 'x64') { 0x8664 } else { 0x014c }
if ($image[0] -ne 0x4d -or $image[1] -ne 0x5a -or [BitConverter]::ToUInt32($image, $pe) -ne 0x4550 -or $machine -ne $expectedMachine) { throw "Incorrect PE machine for $Arch" }
Copy-Item $parent (Join-Path $Out 'child.exe') -Force
$hashes = 'parent.exe', 'child.exe' | ForEach-Object { Get-FileHash -Algorithm SHA256 (Join-Path $Out $_) }
if ($hashes[0].Hash -ne $hashes[1].Hash) { throw 'Parent and child must be exact copies of the same original image.' }
$hashes | ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) } |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
@(
    "Original Windows child-process diagnostic; $Arch MSVC build; PE machine $machine."
    'parent.exe and child.exe are byte-identical; --child selects the worker role.'
    'Test-image ASLR disabled; no custom mapping operations or machine changes.'
    'No proof of PS5 execution, native loader integration, Battle.net, or launcher Stop cleanup.'
) | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.txt')
