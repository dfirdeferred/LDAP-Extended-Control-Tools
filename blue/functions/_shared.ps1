# Shared helpers for AdLdapDefense.

# AD replication extended-right GUIDs (the DirSync/DCSync signal on Event 4662).
$Script:ReplGuids = @{
    'Get-Changes'                 = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DirSync
    'Get-Changes-All'             = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DCSync
    'Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
}

function Get-DcClock {
    param([Parameter(Mandatory)][string]$Dc)
    (Get-CimInstance Win32_OperatingSystem -ComputerName $Dc).LocalDateTime
}

function Get-4662Since {
    param([Parameter(Mandatory)][string]$Dc, [Parameter(Mandatory)][datetime]$Since)
    Get-WinEvent -ComputerName $Dc -FilterHashtable @{LogName='Security'; Id=4662; StartTime=$Since} `
        -ErrorAction SilentlyContinue
}
