configuration 'DoD_Internet_Explorer_11_v2r4'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
        {
            ValueData = 0
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueName = 'RunThisTimeEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueName = 'VersionCheckEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel\History'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Control Panel'
            ValueName = 'History'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
            ValueName = 'RunInvalidSignatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
        {
            ValueData = 'yes'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
            ValueName = 'CheckExeSignatures'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools\Disabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\IEDevTools'
            ValueName = 'Disabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'DisableEPMCompat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Isolation64Bit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
        {
            ValueData = 'PMEM'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Isolation'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'NotifyDisableIEOptions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = '(Reserved)'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = 'explorer.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
        {
            ValueData = '1'
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = 'iexplore.exe'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'PreventOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'EnabledV9'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\ClearBrowsingHistoryOnExit'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'ClearBrowsingHistoryOnExit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\CleanHistory'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'CleanHistory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\EnableInPrivateBrowsing'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'EnableInPrivateBrowsing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Restrictions'
            ValueName = 'NoCrashDetection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Internet Explorer\Security'
            ValueName = 'DisableSecuritySettingsCheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
            ValueName = 'BlockNonAdminActiveXInstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_zones_map_edit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_options_edit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_HKLM_only'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'PreventIgnoreCertErrors'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'CertificateRevocation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'WarnOnBadCertRecving'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'EnableSSL3Fallback'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
        {
            ValueData = 2048
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History\DaysToKeep'
        {
            ValueData = 40
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
            ValueName = 'DaysToKeep'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
            ValueName = 'UNCAsIntranet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueName = '270C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '270C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '1201'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
        {
            ValueData = 65536
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '270C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '1201'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
        {
            ValueData = 65536
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1406'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1407'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1802'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2402'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '120b'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '120c'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1206'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2102'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1209'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2103'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2200'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '270C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1001'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1004'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2709'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2708'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '160A'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1201'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1804'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
        {
            ValueData = 65536
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1A00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1607'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2004'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2001'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1806'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1409'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2500'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2301'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1809'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1606'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2101'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '140C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1406'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1400'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2000'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1407'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1802'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1803'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2402'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1608'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '120b'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '120c'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1206'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2102'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1209'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2103'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2200'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '270C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1001'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1004'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2709'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2708'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '160A'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1201'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1C00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1804'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
        {
            ValueData = 196608
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1A00'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1607'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2004'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1200'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1405'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1402'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1806'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1409'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2500'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2301'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1809'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1606'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2101'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2001'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '140C'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
