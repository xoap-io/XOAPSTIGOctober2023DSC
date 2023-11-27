Configuration 'DoD_WinSvr_2022_MS_and_DC_v1r4'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_WinSvr_2022_MS_and_DC_v1r4' -ModuleVersion '0.0.1'

    DoD_WinSvr_2022_MS_and_DC_v1r4 'Example'
    {
    }
}
DoD_WinSvr_2022_MS_and_DC_v1r4 -OutputPath 'C:\DoD_WinSvr_2022_MS_and_DC_v1r4'
