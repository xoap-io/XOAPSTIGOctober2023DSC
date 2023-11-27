Configuration 'DoD_WinSvr_2012R2_MS_and_DC_v3r7'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_WinSvr_2012R2_MS_and_DC_v3r7' -ModuleVersion '0.0.1'

    DoD_WinSvr_2012R2_MS_and_DC_v3r7 'Example'
    {
    }
}
DoD_WinSvr_2012R2_MS_and_DC_v3r7 -OutputPath 'C:\DoD_WinSvr_2012R2_MS_and_DC_v3r7'
