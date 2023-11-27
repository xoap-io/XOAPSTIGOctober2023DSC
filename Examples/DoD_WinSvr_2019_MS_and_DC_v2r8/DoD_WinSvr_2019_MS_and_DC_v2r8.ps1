Configuration 'DoD_WinSvr_2019_MS_and_DC_v2r8'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_WinSvr_2019_MS_and_DC_v2r8' -ModuleVersion '0.0.1'

    DoD_WinSvr_2019_MS_and_DC_v2r8 'Example'
    {
    }
}
DoD_WinSvr_2019_MS_and_DC_v2r8 -OutputPath 'C:\DoD_WinSvr_2019_MS_and_DC_v2r8'
