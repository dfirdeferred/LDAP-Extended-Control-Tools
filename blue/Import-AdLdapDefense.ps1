<#
  Convenience loader for the blue-team module. Imports AdLdapDefense into your session (suppressing
  the harmless "unapproved verb" warning) and lists what you can call.

  Usage (from the blue\ folder, in an ELEVATED PowerShell):
    .\Import-AdLdapDefense.ps1

  Then just call the functions, e.g.:
    Invoke-LdapLoggingAudit -Dc dc01.cloud.lab
#>
Import-Module (Join-Path $PSScriptRoot 'AdLdapDefense.psd1') -Force -DisableNameChecking -Global
Write-Host 'Loaded module AdLdapDefense. Available functions:' -ForegroundColor Green
Get-Command -Module AdLdapDefense | ForEach-Object { Write-Host "  $($_.Name)" }
