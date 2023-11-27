Configuration 'DoD_Google_Chrome_v2r8'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Google_Chrome_v2r8' -ModuleVersion '0.0.1'

    DoD_Google_Chrome_v2r8 'Example'
    {
    }
}
DoD_Google_Chrome_v2r8 -OutputPath 'C:\DoD_Google_Chrome_v2r8'
