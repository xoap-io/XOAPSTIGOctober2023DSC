configuration 'DoD_WinSvr_2019_MS_and_DC_v2r8'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
        {
            ValueData = 1
            Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoPreviewPane'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
        {
            ValueData = 1
            Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoReadingPane'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            ValueData = 0
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            ValueData = 255
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'DCSettingIndex'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'ACSettingIndex'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableInventory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'AllowProtectedCreds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueName = 'DODownloadMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HVCIMATRequired'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'LsaCfgFlags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'ConfigureSystemGuardLaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            ValueData = 32768
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            ValueData = 196608
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            ValueData = 32768
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoBackgroundPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoGPOListChanges'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\NETLOGON'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\SYSVOL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Ensure = 'Absent'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'EnableTranscripting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            ValueData = 'C:\ProgramData\PS_Transcript'
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'OutputDirectory'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            Ensure = 'Absent'
            ValueName = 'EnableInvocationHeader'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowBasic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableHTTPPrinting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueName = 'UseLogonCredential'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'SMB1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            ValueData = 4
            Key = 'HKLM:\System\CurrentControlSet\Services\MrxSmb10'
            ValueName = 'Start'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            ValueData = 1
            Key = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
            ValueName = 'NoNameReleaseOnDemand'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            ValueData = 2
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableICMPRedirect'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            ValueData = 2
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
        {
            ValueData = 1
            Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoReadingPane'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
        {
            ValueData = 1
            Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoPreviewPane'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            ValueData = 0
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            ValueData = 255
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            ValueData = 4
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueName = 'PasswordComplexity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            ValueData = 14
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueName = 'PasswordLength'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            ValueData = 60
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueName = 'PasswordAgeDays'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            ValueData = 0
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            ValueData = 1
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'DCSettingIndex'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'ACSettingIndex'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableInventory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'AllowProtectedCreds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueName = 'DODownloadMode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HVCIMATRequired'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'LsaCfgFlags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'ConfigureSystemGuardLaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            ValueData = 32768
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            ValueData = 196608
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            ValueData = 32768
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoBackgroundPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoGPOListChanges'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\NETLOGON'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\SYSVOL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Ensure = 'Absent'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'EnableTranscripting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            ValueData = 'C:\ProgramData\PS_Transcript'
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'OutputDirectory'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            Ensure = 'Absent'
            ValueName = 'EnableInvocationHeader'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnumerateLocalUsers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowBasic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableHTTPPrinting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'RestrictRemoteClients'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            ValueData = 3
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueName = 'UseLogonCredential'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'SMB1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            ValueData = 4
            Key = 'HKLM:\System\CurrentControlSet\Services\MrxSmb10'
            ValueName = 'Start'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            ValueData = 1
            Key = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
            ValueName = 'NoNameReleaseOnDemand'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            ValueData = 2
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            ValueData = 0
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableICMPRedirect'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            ValueData = 2
            Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Name = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Name = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Name = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Name = 'User Account Management'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Name = 'Process Creation'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
        {
            Name = 'Directory Service Access'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
        {
            Name = 'Directory Service Access'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
        {
            Name = 'Directory Service Changes'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Name = 'Directory Service Changes'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Name = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Name = 'Group Membership'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Name = 'Logoff'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Name = 'Logon'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Name = 'Special Logon'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Name = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Name = 'Other System Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Name = 'Security State Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Name = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Name = 'System Integrity'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }

        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }

        <#AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Name = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Name = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Name = 'User Account Management'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Name = 'Process Creation'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Name = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }#>

        <#AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Name = 'Group Membership'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Name = 'Logoff'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Name = 'Logon'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Name = 'Special Logon'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Name = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Name = 'Other System Events'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Name = 'Security State Change'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Name = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Name = 'System Integrity'
            AuditFlag = 'Success'
            Ensure = 'Present'
        }#>

        <#AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }#>

        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }

        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Name = 'Account_lockout_threshold'
            Account_lockout_threshold = 3
        }

        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Enforce_password_history = 24
            Name = 'Enforce_password_history'
        }

        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }

        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }

        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Name = 'Maximum_Password_Age'
            Maximum_Password_Age = 60
        }

        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Name = 'Account_lockout_duration'
            Account_lockout_duration = 15
        }

        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }

        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
        }

        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Name = 'Accounts_Rename_guest_account'
            Accounts_Rename_guest_account = 'Visitor'
        }

        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }

        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }

<#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        } #>

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Name = 'Domain_controller_LDAP_server_signing_requirements'
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
        }

        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }

        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Domain_member_Maximum_machine_account_password_age = '30'
            Name = 'Domain_member_Maximum_machine_account_password_age'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }

        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }

        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }

<#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
        } #>

        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }

        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }

        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Create_global_objects'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_as_a_batch_job'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @('')
            Policy = 'Deny_log_on_as_a_service'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-19', '*S-1-5-20')
            Policy = 'Generate_security_audits'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }

        <#SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }#>

        <#AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Name = 'Account_lockout_threshold'
            Account_lockout_threshold = 3
        }#>

        <#AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Enforce_password_history = 24
            Name = 'Enforce_password_history'
        }#>

        <#AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }#>

        <#SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }#>

        <#AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }#>

        <#AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Name = 'Maximum_Password_Age'
            Maximum_Password_Age = 60
        }#>

        <#AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Name = 'Account_lockout_duration'
            Account_lockout_duration = 15
        }#>

        <#AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }#>

        <#SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
        }#>

        <#SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Name = 'Accounts_Rename_guest_account'
            Accounts_Rename_guest_account = 'Visitor'
        }#>

        <#AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }#>

        <#AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Domain_member_Maximum_machine_account_password_age = '30'
            Name = 'Domain_member_Maximum_machine_account_password_age'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }#>

        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM =  @(
            MSFT_RestrictedRemoteSamSecurityDescriptor{
                Permission = 'Allow'
                Identity   = 'Administrators'
            }
            )
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        }

        <#SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }#>

        <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        }#>

        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
        }

        <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
            Policy = 'Deny_log_on_locally'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Create_global_objects'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
            Policy = 'Deny_log_on_as_a_batch_job'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @('ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
            Policy = 'Deny_log_on_as_a_service'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-19', '*S-1-5-20')
            Policy = 'Generate_security_audits'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }#>

        <#UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }#>

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
