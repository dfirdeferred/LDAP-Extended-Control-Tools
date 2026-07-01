function Deploy-SaclCanary {
    <#
    .SYNOPSIS
      Deploy a SACL audit-ACE "canary" on a high-value AD object so access raises Event 4662.

    .DESCRIPTION
      A SACL audit ACE fires Event 4662 on the audited access regardless of which LDAP control or
      transport was used -- for WRITES (e.g. the FORCE_UPDATE modify) AND for READS, including the
      otherwise-invisible OBJECT_SECURITY DirSync collection (validated: reads fire 4662 when the
      event is matched by objectGUID, not CN). This is the reliable catch for the stealthy DirSync
      read, which produces no Event 1644 and no Get-Changes 4662 on its own. Requires
      SeSecurityPrivilege (admin) and 'Audit Directory Service Access' (Success) enabled.

    .PARAMETER Target     Object DN to canary.
    .PARAMETER Audit      Read, Write, or All (default Write).
    .PARAMETER Principal  Audited principal (SID or name; default Everyone).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('Read','Write','All')][string]$Audit = 'Write',
        [string]$Principal = 'S-1-1-0'   # Everyone
    )
    $rights = switch ($Audit) {
        'Read'  { [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty' }
        'Write' { [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty' }
        'All'   { [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty,WriteProperty' }
    }
    $sid = try { (New-Object System.Security.Principal.SecurityIdentifier($Principal)) }
           catch { (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier]) }
    if ($PSCmdlet.ShouldProcess($Target, "add $Audit audit canary for $Principal")) {
        $path = "AD:\$Target"
        $acl = Get-Acl -Path $path -Audit
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($sid, $rights, [System.Security.AccessControl.AuditFlags]::Success)
        $acl.AddAuditRule($rule)
        Set-Acl -Path $path -AclObject $acl
        [pscustomobject]@{ Target=$Target; Audit=$Audit; Principal="$sid"; Deployed=$true }
    }
}

function Test-SaclCanary {
    <#
    .SYNOPSIS
      Verify a SACL canary actually raises Event 4662 (or remove it).

    .DESCRIPTION
      Triggers a matching access on the target and checks whether Event 4662 was raised on the DC
      (matched by objectGUID). Both Write and Read canaries fire (validated), and a Read canary also
      catches OBJECT_SECURITY DirSync collection. -Remove revokes the canary.

    .PARAMETER Target   Object DN.
    .PARAMETER Dc       DC whose Security log to check (default: the target's server / current DC).
    .PARAMETER Audit    Read or Write (which access to trigger).
    .PARAMETER Remove   Revoke the audit ACE(s) for -Principal instead of testing.
    .PARAMETER Principal  Principal whose audit ACE to remove (default Everyone).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Dc = (Get-ADDomainController -Discover -NextClosestSite).HostName[0],
        [ValidateSet('Read','Write')][string]$Audit = 'Write',
        [switch]$Remove,
        [string]$Principal = 'S-1-1-0'
    )
    $path = "AD:\$Target"
    if ($Remove) {
        $sid = try { New-Object System.Security.Principal.SecurityIdentifier($Principal) }
               catch { (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier]) }
        if ($PSCmdlet.ShouldProcess($Target, "remove audit canary for $Principal")) {
            $acl = Get-Acl -Path $path -Audit
            [void]$acl.PurgeAuditRules($sid)
            Set-Acl -Path $path -AclObject $acl
            return [pscustomobject]@{ Target=$Target; Removed=$true }
        }
        return
    }

    $t0 = Get-DcClock $Dc
    # Event 4662 identifies the object by its objectGUID (Object Name: %{guid}), not its CN.
    $guid = (Get-ADObject $Target -Server $Dc -Properties objectGUID).objectGUID.Guid
    if ($Audit -eq 'Write') {
        $cur = (Get-ADObject $Target -Server $Dc -Properties comment).comment
        Set-ADObject $Target -Server $Dc -Replace @{comment = "canary-probe-$(Get-Random)"}
        if ($null -eq $cur) { Set-ADObject $Target -Server $Dc -Clear comment -EA SilentlyContinue }
        else { Set-ADObject $Target -Server $Dc -Replace @{comment = $cur} -EA SilentlyContinue }
    } else {
        [void](Get-ADObject $Target -Server $Dc -Properties description, comment, servicePrincipalName)
    }
    Start-Sleep 5
    $fired = @(Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Security';Id=4662;StartTime=$t0} -EA SilentlyContinue |
               Where-Object { $_.Message -match $guid }).Count -gt 0
    [pscustomobject]@{
        Target = $Target; Audit = $Audit; Fired4662 = $fired
        Note = if ($fired) { 'Canary works (a read canary also catches OBJECT_SECURITY DirSync).' }
               else { 'Did not fire -- check Audit Directory Service Access (Success) + the SACL ACE.' }
    }
}
