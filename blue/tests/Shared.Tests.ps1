Describe "AdLdapDefense module" {
    It "exports the five public functions" {
        Import-Module "$PSScriptRoot/../AdLdapDefense.psd1" -Force
        $exp = (Get-Module AdLdapDefense).ExportedFunctions.Keys
        $exp | Should -Contain 'Invoke-LdapLoggingAudit'
        $exp | Should -Contain 'Invoke-ReplMetadataHunt'
        $exp | Should -Contain 'Deploy-SaclCanary'
        $exp | Should -Contain 'Test-SaclCanary'
        $exp | Should -Contain 'Get-ReplicationAbuse'
    }
}
