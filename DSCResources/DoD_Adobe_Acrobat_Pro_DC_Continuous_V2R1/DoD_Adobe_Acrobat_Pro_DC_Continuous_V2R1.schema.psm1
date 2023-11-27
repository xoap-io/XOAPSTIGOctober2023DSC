configuration 'DoD_Adobe_Acrobat_Pro_DC_Continuous_V2R1'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
        {
            ValueData = 1
            Key = 'Software\Adobe\Adobe Acrobat\DC\Installer'
            ValueName = 'DisableMaintenance'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityStandalone'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bEnhancedSecurityStandalone'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bEnhancedSecurityInBrowser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iFileAttachmentPerms'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'iFileAttachmentPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnableFlash'
        {
            ValueData = 0
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bEnableFlash'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedFolders'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bDisableTrustedFolders'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bProtectedMode'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bProtectedMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iProtectedView'
        {
            ValueData = 2
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'iProtectedView'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bDisablePDFHandlerSwitching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedSites'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
            ValueName = 'bDisableTrustedSites'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
            ValueName = 'bAdobeSendPluginToggle'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bDisableADCFileStore'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
            ValueName = 'bDisableADCFileStore'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
        {
            ValueData = 3
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueName = 'iUnknownURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueName = 'iURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bTogglePrefsSync'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
            ValueName = 'bTogglePrefsSync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bToggleWebConnectors'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
            ValueName = 'bToggleWebConnectors'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint'
            ValueName = 'bDisableSharePointFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles'
            ValueName = 'bDisableWebmail'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
        {
            ValueData = 0
            Key = 'Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen'
            ValueName = 'bShowWelcomeScreen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
        {
            ValueData = 1
            Key = 'Software\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
            ValueName = 'DisableMaintenance'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral\bFIPSMode'
        {
            ValueData = 1
            Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral'
            ValueName = 'bFIPSMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
        {
            ValueData = 0
            Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload'
            ValueName = 'bLoadSettingsFromURL'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
        {
            ValueData = 0
            Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload'
            ValueName = 'bLoadSettingsFromURL'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
