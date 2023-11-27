configuration 'DoD_Microsoft_Defender_Antivirus_v2r4'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            ValueData = 1
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueName = 'PUAProtection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
            ValueName = 'DisableAutoExclusions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueName = 'DisableEmailScanning'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueName = 'ScheduleDay'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
        {
            ValueData = 7
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueName = 'ASSignatureDue'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
        {
            ValueData = 7
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueName = 'AVSignatureDue'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueName = 'ScheduleDay'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
        {
            ValueData = 0
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'DisableBlockAtFirstSeen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
        {
            ValueData = 2
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SpynetReporting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
        {
            ValueData = 1
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
        {
            ValueData = 1
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats'
            ValueName = 'Threats_ThreatSeverityDefaultAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5'
        {
            ValueData = '2'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueName = '5'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4'
        {
            ValueData = '2'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueName = '4'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2'
        {
            ValueData = '2'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueName = '2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1'
        {
            ValueData = '2'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            ValueData = 1
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            ValueName = 'ExploitGuard_ASR_Rules'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3B576869-A4EC-4529-8536-B80A7769E899'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = '3B576869-A4EC-4529-8536-B80A7769E899'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D3E037E1-3EB8-44C8-A917-57927947596D'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = 'D3E037E1-3EB8-44C8-A917-57927947596D'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
        {
            ValueData = '1'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            ValueData = 1
            Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            ValueName = 'EnableNetworkProtection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
