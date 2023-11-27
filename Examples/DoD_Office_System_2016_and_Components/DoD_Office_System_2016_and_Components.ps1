Configuration 'DoD_Office_System_2016_and_Components'
{
	Import-DSCResource -Module 'XOAPSTIGOctober2023DSC' -Name 'DoD_Office_System_2016_and_Components' -ModuleVersion '0.0.1'

    DoD_Office_System_2016_and_Components 'Example'
    {
    }
}
DoD_Office_System_2016_and_Components -OutputPath 'C:\DoD_Office_System_2016_and_Components'
