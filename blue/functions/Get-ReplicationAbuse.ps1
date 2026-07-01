function Get-ReplicationAbuse {
    <#
    .SYNOPSIS
      Hunt AD replication (DirSync/DCSync) abuse: Event 4662 with a Get-Changes GUID from a
      non-DC, non-approved-sync account, with the source IP recovered from the matching 4624 logon.

    .DESCRIPTION
      DirSync (F-8, confidential reads via flags=0) and DCSync both exercise the DS-Replication
      Get-Changes rights, which raise Event 4662. This catches Get-Changes (DirSync, 1131f6aa),
      Get-Changes-All (DCSync, 1131f6ad), and Get-Changes-In-Filtered-Set. 4662 carries the account
      but not the source IP, so it joins to the 4624 logon by LogonId. DCSync-only rules that watch
      just Get-Changes-All MISS the lower-privileged DirSync path.

    .PARAMETER Dc                    DC whose Security log to read.
    .PARAMETER Since                 Look-back start (default: 24h ago).
    .PARAMETER ApprovedSyncAccounts  Allowlisted sync accounts (wildcards ok; default MSOL_*).
    .PARAMETER IncludeDCSyncOnly     Only flag Get-Changes-All (classic DCSync).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dc,
        [datetime]$Since = (Get-Date).AddHours(-24),
        [string[]]$ApprovedSyncAccounts = @('MSOL_*'),
        [switch]$IncludeDCSyncOnly
    )
    $guids = if ($IncludeDCSyncOnly) { @($Script:ReplGuids['Get-Changes-All']) } else { @($Script:ReplGuids.Values) }

    function ParseFields($e) { $h=@{}; ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $h[$_.Name]=$_.'#text' }; $h }

    # LogonId -> source IP from 4624 logons in the window.
    $logons = @{}
    Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Security';Id=4624;StartTime=$Since} -ErrorAction SilentlyContinue |
        ForEach-Object { $d = ParseFields $_; if ($d.TargetLogonId) { $logons[$d.TargetLogonId] = $d.IpAddress } }

    Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Security';Id=4662;StartTime=$Since} -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = ParseFields $_
            $props = "$($d.Properties)"
            $hit = @($guids | Where-Object { $props -match [regex]::Escape($_) })
            if (-not $hit) { return }
            $acct = "$($d.SubjectUserName)"
            if ($acct.EndsWith('$')) { return }                                   # exclude DC machine accounts
            if ($ApprovedSyncAccounts | Where-Object { $acct -like $_ }) { return } # allowlisted sync accounts
            $kind = if ($hit -contains $Script:ReplGuids['Get-Changes-All']) { 'DCSync' } else { 'DirSync' }
            [pscustomobject]@{
                Time     = $_.TimeCreated
                Account  = $acct
                SourceIp = $logons["$($d.SubjectLogonId)"]
                Kind     = $kind
                Guids    = ($hit -join ',')
                Object   = "$($d.ObjectName)"
            }
        }
}
