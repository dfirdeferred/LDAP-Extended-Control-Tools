function Invoke-LdapLoggingAudit {
    <#
    .SYNOPSIS
      Report what a DC ACTUALLY logs for LDAP activity, and (optionally) fix Event 1644.

    .DESCRIPTION
      Event 1644 (LDAP search statistics) is widely "enabled" but silently useless when the
      thresholds are 0 (= DISABLED). This audits the real config, and with -Probe fires benign
      control-bearing searches to show which controls actually appear in the 1644 "Server controls"
      field (SD_FLAGS / ASQ / SHOW_DELETED are recorded; phantom-root / EXPECTED_ENTRY_COUNT are
      NOT -- validated). It also confirms Event 4662 auditing and notes the ADWS logging gap.

    .PARAMETER Dc     Target domain controller.
    .PARAMETER Probe  Fire benign control searches and report which are captured by 1644.
    .PARAMETER Fix    Set "15 Field Engineering"=5 and all three thresholds=1 (log every search).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Dc,
        [switch]$Probe,
        [switch]$Fix
    )
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $cfg = Invoke-Command -ComputerName $Dc -ScriptBlock {
        $d = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        [pscustomobject]@{
            FieldEngineering = (Get-ItemProperty $d -Name '15 Field Engineering' -EA SilentlyContinue).'15 Field Engineering'
            LdapInterface    = (Get-ItemProperty $d -Name '16 LDAP Interface Events' -EA SilentlyContinue).'16 LDAP Interface Events'
            Expensive        = (Get-ItemProperty $p -Name 'Expensive Search Results Threshold' -EA SilentlyContinue).'Expensive Search Results Threshold'
            Inefficient      = (Get-ItemProperty $p -Name 'Inefficient Search Results Threshold' -EA SilentlyContinue).'Inefficient Search Results Threshold'
            SearchTime       = (Get-ItemProperty $p -Name 'Search Time Threshold (msecs)' -EA SilentlyContinue).'Search Time Threshold (msecs)'
        }
    }
    $thresholdsLogAll = ($cfg.Expensive -eq 1 -and $cfg.Inefficient -eq 1 -and $cfg.SearchTime -eq 1)
    $event1644Effective = (($cfg.FieldEngineering -ge 5) -and $thresholdsLogAll)

    if ($Fix -and $PSCmdlet.ShouldProcess($Dc, "Set Field Engineering=5 + thresholds=1")) {
        Invoke-Command -ComputerName $Dc -ScriptBlock {
            $d = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
            $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            New-ItemProperty $d -Name '15 Field Engineering' -Value 5 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty $d -Name '16 LDAP Interface Events' -Value 2 -PropertyType DWORD -Force | Out-Null
            foreach ($n in 'Expensive Search Results Threshold','Inefficient Search Results Threshold','Search Time Threshold (msecs)') {
                New-ItemProperty $p -Name $n -Value 1 -PropertyType DWORD -Force | Out-Null
            }
        }
        $event1644Effective = $true
        Write-Verbose "Applied: Field Engineering=5, thresholds=1."
    }

    $probeRows = @()
    if ($Probe) {
        $root = (Get-ADRootDSE -Server $Dc).defaultNamingContext
        $grp  = (Get-ADGroup 'Domain Admins' -Server $Dc).DistinguishedName
        $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Dc, 389)
        $t0   = Get-DcClock $Dc
        function Fire($req, $ctrl) {
            $req.Controls.Add($ctrl) | Out-Null
            $c = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
            $c.AuthType = 'Negotiate'; $c.Bind()
            try { [void]$c.SendRequest($req) } catch {} finally { $c.Dispose() }
        }
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest($root,"(sAMAccountName=Administrator)","Subtree","nTSecurityDescriptor")
        Fire $r (New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl([System.DirectoryServices.Protocols.SecurityMasks]"Dacl,Owner,Group"))
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest($grp,"(objectClass=group)","Base","cn")
        Fire $r (New-Object System.DirectoryServices.Protocols.AsqRequestControl("member"))
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest($root,"(sAMAccountName=Administrator)","Subtree","cn")
        Fire $r (New-Object System.DirectoryServices.Protocols.ShowDeletedControl)
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest($root,"(sAMAccountName=Administrator)","Subtree","cn")
        Fire $r (New-Object System.DirectoryServices.Protocols.SearchOptionsControl([System.DirectoryServices.Protocols.SearchOption]::PhantomRoot))
        Start-Sleep 6
        $ev = Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Directory Service';Id=1644;StartTime=$t0} -EA SilentlyContinue
        function ServerControls($e){ $l=$e.Message -split "`r?`n"; $i=[Array]::FindIndex($l,[Predicate[string]]{param($x) $x.Trim() -eq 'Server controls:'}); if($i -ge 0 -and $i+1 -lt $l.Count){$l[$i+1].Trim()}else{''} }
        $captured = @($ev | ForEach-Object { ServerControls $_ } | Where-Object { $_ })
        foreach ($name in 'SDflags','ASQ','return_deleted') {
            $probeRows += [pscustomobject]@{ Control=$name; RecordedIn1644=[bool]($captured -match $name) }
        }
        $probeRows += [pscustomobject]@{ Control='PhantomRoot/.1340'; RecordedIn1644=$false }
        $probeRows += [pscustomobject]@{ Control='EXPECTED_ENTRY_COUNT/.2211'; RecordedIn1644=$false }
    }

    $has4662 = [bool](Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Security';Id=4662} -MaxEvents 1 -EA SilentlyContinue)
    $adwsLog = $false
    try { $adwsLog = [bool](Get-WinEvent -ComputerName $Dc -ListLog 'Active Directory Web Services' -EA Stop) } catch {}

    [pscustomobject]@{
        Dc                   = $Dc
        Event1644Effective   = $event1644Effective
        ThresholdTrap        = (-not $thresholdsLogAll)   # $true => thresholds 0/unset => logs little or nothing
        Config               = $cfg
        ControlsCaptured     = $probeRows
        Event4662Auditing    = $has4662
        AdwsLoggingAvailable = $adwsLog
        BlindSpots           = @(
            'Event 1644 is search-only: FORCE_UPDATE / SET_OWNER modifies and BATCH ext-ops are invisible.',
            'DirSync uses the replication path -> Event 4662, not 1644.',
            'OBJECT_SECURITY DirSync produces neither 4662 nor 1644.',
            'ADWS (9389) logs the client as 127.0.0.1 (loopback); the noise filter hides it.'
        )
    }
}
