configuration 'DoD_Windows_Defender_Firewall_v2r2'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            ValueData = 539
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
            ValueName = 'PolicyVersion'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
        {
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
        {
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName = 'LogFileSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName = 'LogDroppedPackets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName = 'LogSuccessfulConnections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
        {
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName = 'LogFileSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName = 'LogDroppedPackets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName = 'LogSuccessfulConnections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DefaultInboundAction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'AllowLocalPolicyMerge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
        {
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName = 'LogFileSize'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName = 'LogDroppedPackets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
        {
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName = 'LogSuccessfulConnections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
