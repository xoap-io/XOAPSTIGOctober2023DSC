Configuration 'XOAPSTIGOctober2023DSC'
{
    Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Adobe_Acrobat_Pro_DC_Continuous_V2R1' -ModuleVersion '0.0.1'

    param
        (
        )

    Node 'XOAPSTIGOctober2023DSC'
    {
        DoD_Adobe_Acrobat_Pro_DC_Continuous_SV2R1 'Example'
        {
        }

    }
}
XOAPSTIGOctober2023DSC -OutputPath 'C:\XOAPSTIGOctober2023DSC'
