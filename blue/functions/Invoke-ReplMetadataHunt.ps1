function Invoke-ReplMetadataHunt {
    <#
    .SYNOPSIS
      Hunt FORCE_UPDATE-style tampering: a per-attribute replication VERSION that increases while
      the value is UNCHANGED (also catches DCShadow-class version manipulation).

    .DESCRIPTION
      Snapshots per-attribute Version + a SHA256 value hash (via Get-ADReplicationAttributeMetadata)
      for sensitive attributes across a search base. First run seeds the baseline JSON; later runs
      diff against it and emit anomalies where VersionNow > VersionWas AND the value hash is
      unchanged. FORCE_UPDATE leaves no Event 1644 (it rides a modify), so this metadata hunt is the
      reliable detection.

    .PARAMETER Server        DC to read from.
    .PARAMETER SearchBase    Base DN to scan (default: domain root).
    .PARAMETER Attributes    Sensitive attributes to watch.
    .PARAMETER BaselinePath  JSON baseline (seed on first run, diff after).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [string]$SearchBase,
        [string[]]$Attributes = @('description','scriptPath','servicePrincipalName','gPLink','msDS-AllowedToActOnBehalfOfOtherIdentity'),
        [Parameter(Mandatory)][string]$BaselinePath
    )
    if (-not $SearchBase) { $SearchBase = (Get-ADDomain -Server $Server).DistinguishedName }

    function Hash([string]$s) {
        if ([string]::IsNullOrEmpty($s)) { return '<empty>' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        ([System.BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)))) -replace '-'
    }

    $snap = @{}
    $objs = Get-ADObject -Server $Server -SearchBase $SearchBase `
        -LDAPFilter '(|(objectClass=user)(objectClass=group)(objectClass=computer))' -Properties $Attributes
    foreach ($o in $objs) {
        $md = Get-ADReplicationAttributeMetadata -Server $Server -Object $o.DistinguishedName `
            -Properties $Attributes -ErrorAction SilentlyContinue
        foreach ($m in $md) {
            if ($Attributes -notcontains $m.AttributeName) { continue }
            $snap["$($o.DistinguishedName)|$($m.AttributeName)"] = [pscustomobject]@{
                Version    = [int]$m.Version
                ValueHash  = Hash("$($o.$($m.AttributeName))")
                LastChange = "$($m.LastOriginatingChangeTime)"
                LastDsa    = "$($m.LastOriginatingChangeDirectoryServerIdentity)"
            }
        }
    }

    if (-not (Test-Path $BaselinePath)) {
        $snap | ConvertTo-Json -Depth 4 | Set-Content $BaselinePath
        Write-Verbose "Baseline seeded ($($snap.Count) attribute-instances) -> $BaselinePath. Re-run later to detect anomalies."
        return
    }

    $base = @{}
    (Get-Content $BaselinePath -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $base[$_.Name] = $_.Value }
    $alerts = foreach ($key in $snap.Keys) {
        if (-not $base.ContainsKey($key)) { continue }
        $now = $snap[$key]; $was = $base[$key]
        if ($now.Version -gt $was.Version -and $now.ValueHash -eq $was.ValueHash) {
            $dn, $attr = $key -split '\|', 2
            [pscustomobject]@{
                Object = $dn; Attribute = $attr
                VersionWas = $was.Version; VersionNow = $now.Version; Delta = $now.Version - $was.Version
                ValueChanged = $false; LastOriginatingDsa = $now.LastDsa; LastChange = $now.LastChange
                Signal = "FORCE_UPDATE: version +$($now.Version - $was.Version) with NO value change"
            }
        }
    }
    $snap | ConvertTo-Json -Depth 4 | Set-Content $BaselinePath   # refresh baseline
    $alerts
}
