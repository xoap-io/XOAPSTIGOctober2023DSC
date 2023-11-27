Configuration 'DoD_Windows_11_v1r5'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Windows_11_v1r5' -ModuleVersion '0.0.1'

    DoD_Windows_11_v1r5 'Example'
    {
    }
}
DoD_Windows_11_v1r5 -OutputPath 'C:\DoD_Windows_11_v1r5'
