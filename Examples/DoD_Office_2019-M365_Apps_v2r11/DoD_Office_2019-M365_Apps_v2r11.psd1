Configuration 'DoD_Office_2019-M365_Apps_v2r11'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Office_2019-M365_Apps_v2r11' -ModuleVersion '0.0.1'

    DoD_Office_2019-M365_Apps_v2r11 'Example'
    {
    }
}
DoD_Office_2019-M365_Apps_v2r11 -OutputPath 'C:\DoD_Office_2019-M365_Apps_v2r11'
