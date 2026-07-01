# AdLdapDefense — defensive tooling for AD LDAP extended-control abuse.
# Dot-sources every function file, then exports the public functions.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-ChildItem -Path (Join-Path $here 'functions') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

Export-ModuleMember -Function `
    Invoke-LdapLoggingAudit, `
    Invoke-ReplMetadataHunt, `
    Deploy-SaclCanary, `
    Test-SaclCanary, `
    Get-ReplicationAbuse
