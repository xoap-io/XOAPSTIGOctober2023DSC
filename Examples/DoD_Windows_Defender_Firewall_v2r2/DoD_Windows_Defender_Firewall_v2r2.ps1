Configuration 'DoD_Windows_Firewall_v2r2'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Windows_Firewall_v2r2' -ModuleVersion '0.0.1'

    DoD_Windows_Firewall_v2r2 'Example'
    {
    }
}
DoD_Windows_Firewall_v2r2 -OutputPath 'C:\DoD_Windows_Firewall_v2r2'
