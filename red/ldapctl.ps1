<#
  Convenience launcher for the red tool. Runs `python -m ldapctl <args>` using the scanner venv
  Python (which has ldap3 + pycryptodome) and UTF-8 output, so you don't have to type either.

  Examples:
    .\ldapctl.ps1 recon   --dc dc01.cloud.lab --user 'CLOUD\svc-research' --dn 'CN=Administrator,CN=Users,DC=cloud,DC=lab'
    .\ldapctl.ps1 collect --dc dc01.cloud.lab --user 'CLOUD\svc-research' --filter '(objectClass=user)' --output users.json

  Set the password once per session so it stays off screen:  $env:LDAPCTL_PASSWORD = '...'
#>
$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'

# red/ is two levels below the repo root that holds scanner/.venv: repo\ldap-controls-toolkit\red
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$venvPy = Join-Path $repoRoot 'scanner\.venv\Scripts\python.exe'
$py = if (Test-Path $venvPy) { $venvPy } else { 'python' }

Push-Location $PSScriptRoot
try   { & $py -m ldapctl @args }
finally { Pop-Location }
exit $LASTEXITCODE
