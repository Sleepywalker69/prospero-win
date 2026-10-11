# SPDX-License-Identifier: LGPL-2.1-or-later
# Separate proposed recipe. -RunReference also executes the original parent/child.
param([Parameter(Mandatory=$true)][string]$ProjectRoot,
      [Parameter(Mandatory=$true)][string]$Out,
      [string]$Source = (Join-Path $PSScriptRoot '..\tests\fixtures\windows_child_user.c'),
      [switch]$RunReference)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$Source = (Resolve-Path $Source).Path
$recipe = $PSCommandPath
$validator = Join-Path $ProjectRoot 'tools\windows_child_user_contract.py'
$Out = [IO.Path]::GetFullPath($Out)
if (Test-Path -LiteralPath $Out) { throw 'Use a fresh output directory; no existing build is reused.' }
function Hash-File([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Git-Text([string[]]$Arguments) {
    $value = & git -C $ProjectRoot @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Git source identity check failed.' }
    return ($value -join "`n").Trim()
}
$commit = Git-Text @('rev-parse','HEAD')
$tree = Git-Text @('rev-parse','HEAD^{tree}')
if ($commit -notmatch '^[0-9a-f]{40}$' -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Invalid project identity.' }
if (Git-Text @('status','--porcelain','--untracked-files=no')) { throw 'Tracked project files must be clean.' }
# The eventual source/recipe must actually belong to this checkout. An isolated
# proposal cannot claim the identity of an unrelated clean repository.
foreach ($file in @($Source,$recipe,$validator)) {
    $prefix = $ProjectRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if (!$file.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Source and recipe must be inside the bound checkout.' }
    $relative = $file.Substring($prefix.Length).Replace('\','/')
    $null = Git-Text @('ls-files','--error-unmatch','--',$relative)
}
$sourceHash = Hash-File $Source
$recipeHash = Hash-File $recipe
$validatorHash = Hash-File $validator
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Preinstalled Visual Studio C++ tools are required; nothing is installed.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'No installed MSVC x64 toolchain found.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
New-Item -ItemType Directory $Out | Out-Null
$identityCommand = 'call "{0}" > nul && where cl.exe && where dumpbin.exe' -f $vcvars
$providers = @(& $env:ComSpec /d /s /c $identityCommand)
if ($LASTEXITCODE -ne 0) { throw 'Could not identify the selected compiler and inspector.' }
$compiler = @($providers | Where-Object { $_ -match '\\cl\.exe$' })[0]
$inspector = @($providers | Where-Object { $_ -match '\\dumpbin\.exe$' })[0]
if (!(Test-Path -LiteralPath $compiler) -or !(Test-Path -LiteralPath $inspector)) { throw 'Selected tool paths are absent.' }
$compilerHash = Hash-File $compiler
$inspectorHash = Hash-File $inspector
$files = @{}
$headers = @{}
$compileCommands = @{}
foreach ($role in @('parent','child')) {
    $selector = if ($role -eq 'child') { 1 } else { 0 }
    $leaf = "user-$role.exe"
    $exe = Join-Path $Out $leaf
    $object = Join-Path $Out "user-$role.obj"
    $dependencies = Join-Path $Out "dependencies-$role.json"
    $command = 'call "{0}" > nul && "{1}" /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DPW_USER_CHILD={2} /sourceDependencies "{6}" "{3}" user32.lib gdi32.lib /Fe:"{4}" /Fo:"{5}" /link /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO' -f $vcvars,$compiler,$selector,$Source,$exe,$object,$dependencies
    $compileCommands[$role] = $command
    & $env:ComSpec /d /s /c $command 2>&1 | Tee-Object -FilePath (Join-Path $Out "build-$role.log")
    if ($LASTEXITCODE -ne 0) { throw "MSVC $role build failed." }
    $image = [IO.File]::ReadAllBytes($exe)
    if ($image.Length -lt 256 -or $image.Length -gt 16MB -or $image[0] -ne 0x4d -or $image[1] -ne 0x5a) { throw 'Invalid bounded DOS image.' }
    $pe = [BitConverter]::ToInt32($image,60)
    if ($pe -lt 64 -or $pe -gt $image.Length-264 -or [BitConverter]::ToUInt32($image,$pe) -ne 0x4550 -or [BitConverter]::ToUInt16($image,$pe+4) -ne 0x8664) { throw 'Expected AMD64 PE.' }
    $optional = $pe+24
    if ([BitConverter]::ToUInt16($image,$pe+20) -lt 240 -or [BitConverter]::ToUInt16($image,$optional) -ne 0x20b) { throw 'Expected complete PE32+ optional header.' }
    $flags = [BitConverter]::ToUInt16($image,$optional+70)
    $characteristics = [BitConverter]::ToUInt16($image,$pe+22)
    if (($flags -band 0x140) -ne 0x140 -or ($characteristics -band 1) -ne 0 -or ($characteristics -band 0x2000) -ne 0) { throw 'ASLR/NX/executable/relocation flags differ.' }
    if ([BitConverter]::ToUInt32($image,$optional+108) -lt 6 -or [BitConverter]::ToUInt32($image,$optional+152) -eq 0 -or [BitConverter]::ToUInt32($image,$optional+156) -eq 0) { throw 'Base relocation directory is missing.' }
    & $inspector /headers /imports /relocations $exe 2>&1 | Tee-Object -FilePath (Join-Path $Out "inspect-$role.log")
    if ($LASTEXITCODE -ne 0) { throw "dumpbin $role inspection failed." }
    $dependencyData = Get-Content -LiteralPath $dependencies -Raw | ConvertFrom-Json
    if ([IO.Path]::GetFullPath($dependencyData.Data.Source) -ne $Source) { throw 'Compiler dependency source differs.' }
    $includes = @($dependencyData.Data.Includes)
    if (!$includes.Count -or $includes.Count -gt 512) { throw 'Missing or excessive compiler header dependencies.' }
    foreach ($include in $includes) {
        $header = Get-Item -LiteralPath $include
        if ($header.PSIsContainer -or ($header.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $header.Length -gt 16MB) { throw 'Invalid bounded compiler header input.' }
        $headerHash = Hash-File $header.FullName
        if ($headers.ContainsKey($header.FullName) -and $headers[$header.FullName].sha256 -ne $headerHash) { throw 'Consumed header changed between role builds.' }
        $headers[$header.FullName] = @{ bytes=$header.Length; sha256=$headerHash }
    }
    $files[$leaf] = @{ bytes=$image.Length; sha256=(Hash-File $exe); machine='AMD64'; selector=$selector }
}
if ((Hash-File $Source) -ne $sourceHash -or (Hash-File $recipe) -ne $recipeHash -or
    (Hash-File $validator) -ne $validatorHash -or
    (Git-Text @('rev-parse','HEAD')) -ne $commit -or (Git-Text @('rev-parse','HEAD^{tree}')) -ne $tree -or
    (Git-Text @('status','--porcelain','--untracked-files=no'))) { throw 'Project or fixture inputs changed during build.' }
$report = @{
    schema='pw-original-windows-child-user-msvc/1'; architecture='x64'; project=@{commit=$commit;tree=$tree};
    run_id=$env:GITHUB_RUN_ID; run_attempt=$env:GITHUB_RUN_ATTEMPT;
    source_sha256=$sourceHash; recipe_sha256=$recipeHash; validator_sha256=$validatorHash; headers=$headers; compile_commands=$compileCommands;
    compiler=@{name='MSVC cl.exe';sha256=$compilerHash;file_version=(Get-Item -LiteralPath $compiler).VersionInfo.FileVersion};
    inspector=@{name='MSVC dumpbin.exe';sha256=$inspectorHash}; files=$files;
    reference=@{executed=$false;exit=$null;deadline_seconds=105;stdout=$null;stderr=$null;role_logs=@{}}; import_policy_verified=$false; relocation_entries_verified=$false;
    runtime_validated=$false; child_presentation=$false; child_input=$false
}
if ($RunReference) {
    if ($env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]*$') { throw 'Per-run reference identity is required.' }
    $stdout = Join-Path $Out 'reference.stdout.log'
    $stderr = Join-Path $Out 'reference.stderr.log'
    $process = Start-Process -FilePath (Join-Path $Out 'user-parent.exe') -WorkingDirectory $Out -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (!$process.WaitForExit(105000)) {
        # Hosted original-reference failure only; never native console ownership.
        $process.Kill($true)
        $process.WaitForExit()
        throw 'Original USER reference exceeded105 seconds; no passing receipt is emitted.'
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Original USER reference exit $($process.ExitCode)" }
    $roleLogs = @{}
    foreach ($role in @('parent','child')) {
        $logs = @(Get-ChildItem -LiteralPath $Out -Filter "user-$role-*.log" -File)
        if ($logs.Count -ne 1 -or $logs[0].Length -gt 65536) { throw 'Missing, excessive or ambiguous role log.' }
        $roleLogs[$logs[0].Name] = @{ bytes=$logs[0].Length;sha256=(Hash-File $logs[0].FullName) }
    }
    foreach ($leaf in @('user-parent.exe','user-child.exe')) {
        if ((Hash-File (Join-Path $Out $leaf)) -ne $files[$leaf].sha256) { throw 'Reference image changed.' }
    }
    $report.reference = @{executed=$true;exit=0;deadline_seconds=105;
        stdout=@{bytes=(Get-Item $stdout).Length;sha256=(Hash-File $stdout)};
        stderr=@{bytes=(Get-Item $stderr).Length;sha256=(Hash-File $stderr)};role_logs=$roleLogs}
}
if ((Hash-File $compiler) -ne $compilerHash -or (Hash-File $inspector) -ne $inspectorHash -or
    (Hash-File $Source) -ne $sourceHash -or (Hash-File $recipe) -ne $recipeHash -or
    (Hash-File $validator) -ne $validatorHash -or
    (Git-Text @('rev-parse','HEAD')) -ne $commit -or (Git-Text @('rev-parse','HEAD^{tree}')) -ne $tree -or
    (Git-Text @('status','--porcelain','--untracked-files=no'))) { throw 'Bound inputs changed before final receipt.' }
foreach ($header in $headers.GetEnumerator()) {
    if ((Get-Item -LiteralPath $header.Key).Length -ne $header.Value.bytes -or (Hash-File $header.Key) -ne $header.Value.sha256) { throw 'Consumed compiler header changed.' }
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding ascii (Join-Path $Out 'user-source.json')
Copy-Item -LiteralPath $Source -Destination (Join-Path $Out 'windows_child_user.c')
Copy-Item -LiteralPath $recipe -Destination (Join-Path $Out 'build_windows_child_user.ps1')
if ($RunReference) {
    & python $validator --directory $Out --repo $ProjectRoot --report (Join-Path $Out 'user-inspection.json')
    if ($LASTEXITCODE -ne 0) { throw 'Independent USER PE/reference inspection failed.' }
    if ((Hash-File $validator) -ne $validatorHash) { throw 'Independent validator changed.' }
}
Get-ChildItem -LiteralPath $Out -File | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Hash-File $_.FullName),$_.Name
} | Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS')
Write-Host 'Original USER images built; see user-source.json for the actual reference outcome. Import/relocation-entry review, native admission and console validation remain separate.'
