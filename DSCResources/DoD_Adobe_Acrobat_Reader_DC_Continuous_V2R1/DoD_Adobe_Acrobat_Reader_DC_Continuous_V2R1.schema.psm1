configuration 'DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            ValueData = 1
            Key = 'Software\Adobe\Acrobat Reader\DC\Installer'
            ValueName = 'DisableMaintenance'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bEnhancedSecurityStandalone'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bProtectedMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
        {
            ValueData = 2
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'iProtectedView'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'iFileAttachmentPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnableFlash'
        {
            ValueData = 0
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bEnableFlash'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bDisablePDFHandlerSwitching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bAcroSuppressUpsell'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bAcroSuppressUpsell'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bEnhancedSecurityInBrowser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedFolders'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bDisableTrustedFolders'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedSites'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueName = 'bDisableTrustedSites'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud'
            ValueName = 'bAdobeSendPluginToggle'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueName = 'iURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
        {
            ValueData = 3
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueName = 'iUnknownURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeDocumentServices'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueName = 'bToggleAdobeDocumentServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bTogglePrefsSync'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueName = 'bTogglePrefsSync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleWebConnectors'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueName = 'bToggleWebConnectors'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeSign'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueName = 'bToggleAdobeSign'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bUpdater'
        {
            ValueData = 0
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueName = 'bUpdater'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint'
            ValueName = 'bDisableSharePointFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
        {
            ValueData = 1
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles'
            ValueName = 'bDisableWebmail'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
        {
            ValueData = 0
            Key = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen'
            ValueName = 'bShowWelcomeScreen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            ValueData = 1
            Key = 'Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
            ValueName = 'DisableMaintenance'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\AVGeneral\bFIPSMode'
        {
            ValueData = 1
            Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\AVGeneral'
            ValueName = 'bFIPSMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
        {
            ValueData = 0
            Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload'
            ValueName = 'bLoadSettingsFromURL'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
        {
            ValueData = 0
            Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload'
            ValueName = 'bLoadSettingsFromURL'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
