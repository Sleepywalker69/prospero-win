# SPDX-License-Identifier: LGPL-2.1-or-later
param([ValidateSet('x64', 'x86')][string]$Arch = 'x64', [string]$Out = '')
$ErrorActionPreference = 'Stop'
if (!$Out) { $Out = Join-Path $PSScriptRoot ("..\build\windows-memory-reference-{0}" -f $Arch) }
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\tests\fixtures\windows_process_memory.c')).Path
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force $Out | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'Preinstalled Visual Studio C++ tools are required.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'No installed x86/x64 MSVC toolchain found.' }
$vcvarsName = if ($Arch -eq 'x64') { 'vcvars64.bat' } else { 'vcvars32.bat' }
$vcvars = Join-Path $installation ("VC\Auxiliary\Build\{0}" -f $vcvarsName)
$imagePath = Join-Path $Out 'memory-reference.exe'
$object = Join-Path $Out 'memory-reference.obj'
$command = 'call "{0}" > nul && cl.exe /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS "{1}" /Fe:"{2}" /Fo:"{3}" /link /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO' -f $vcvars, $source, $imagePath, $object
& $env:ComSpec /d /s /c $command 2>&1 | Tee-Object -FilePath (Join-Path $Out 'build.log')
if ($LASTEXITCODE -ne 0) { throw "MSVC fixture build failed: $LASTEXITCODE" }
$image = [IO.File]::ReadAllBytes($imagePath)
if ($image.Length -lt 64) { throw 'Truncated DOS header.' }
$pe = [BitConverter]::ToInt32($image, 60)
if ($pe -lt 64 -or $pe -gt ($image.Length - 96)) { throw 'Invalid PE header offset.' }
$machine = [BitConverter]::ToUInt16($image, $pe + 4)
$magic = [BitConverter]::ToUInt16($image, $pe + 24)
$expectedMachine = if ($Arch -eq 'x64') { 0x8664 } else { 0x014c }
$expectedMagic = if ($Arch -eq 'x64') { 0x20b } else { 0x10b }
if ($image[0] -ne 0x4d -or $image[1] -ne 0x5a -or [BitConverter]::ToUInt32($image, $pe) -ne 0x4550 -or $machine -ne $expectedMachine -or $magic -ne $expectedMagic) { throw 'Incorrect PE architecture.' }
$dllCharacteristics = [BitConverter]::ToUInt16($image, $pe + 24 + 70)
if (($dllCharacteristics -band 0x140) -ne 0x140) { throw 'ASLR and NX compatibility must remain enabled.' }
Get-FileHash -Algorithm SHA256 $source, $imagePath |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) } |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
@(
    "Original owned child data-memory reference; architecture=$Arch; PE machine=$machine."
    'Only PAGE_READWRITE child data is modified. ASLR/NX remain enabled.'
    'No Wine/PS5 runtime modification, vendor process, executable-memory write or injection.'
    'Windows reference only; no PS5 or Battle.net compatibility claim.'
) | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.txt')
