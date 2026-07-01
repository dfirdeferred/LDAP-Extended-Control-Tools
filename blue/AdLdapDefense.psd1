@{
    RootModule        = 'AdLdapDefense.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b3e7c1a2-5d84-4f0e-9a61-7c2d8b40e913'
    Author            = 'DFIRdeferred'
    Description       = 'Defensive tooling for Active Directory LDAP extended-control abuse: LDAP logging coverage audit, replication-metadata anomaly hunting, SACL-canary deploy/self-test, and Get-Changes (DirSync/DCSync) abuse detection.'
    PowerShellVersion = '5.1'
    RequiredModules   = @('ActiveDirectory')
    FunctionsToExport = @(
        'Invoke-LdapLoggingAudit',
        'Invoke-ReplMetadataHunt',
        'Deploy-SaclCanary',
        'Test-SaclCanary',
        'Get-ReplicationAbuse'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('ActiveDirectory','LDAP','DFIR','Detection','BlueTeam') } }
}
