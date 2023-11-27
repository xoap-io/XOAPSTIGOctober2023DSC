Configuration 'DoD_Windows_10_v2r8'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Windows_10_v2r8' -ModuleVersion '0.0.1'

    DoD_Windows_10_v2r8 'Example'
    {
    }
}
DoD_Windows_10_v2r8 -OutputPath 'C:\DoD_Windows_10_v2r8'
