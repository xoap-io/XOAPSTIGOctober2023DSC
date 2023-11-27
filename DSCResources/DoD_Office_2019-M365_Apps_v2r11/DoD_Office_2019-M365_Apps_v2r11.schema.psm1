configuration 'DoD_Office_2019-M365_Apps_v2r11'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
        {
            ValueData = 'Block all Flash activation'
            Key = 'Software\microsoft\Office\Common\COM Compatibility'
            ValueName = 'Comment'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
        {
            ValueData = 1
            Key = 'Software\policies\microsoft\office\16.0\lync'
            ValueName = 'enablesiphighsecuritymode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
        {
            ValueData = 1
            Key = 'Software\policies\microsoft\office\16.0\lync'
            ValueName = 'disablehttpconnect'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            ValueData = 0
            Key = 'Software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'ActivationFilterOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            ValueData = 1024
            Key = 'Software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueName = 'Compatibility Flags'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'blockcontentexecutionfrominternet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\portal\linkpublishingdisabled'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\portal'
            ValueName = 'linkpublishingdisabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\macroruntimescanscope'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'macroruntimescanscope'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'drmencryptproperty'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
        {
            ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'defaultencryption12'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
        {
            ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'openxmlencryption'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
            ValueName = 'allow user locations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word\noextensibilitycustomizationfromdocument'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word'
            ValueName = 'noextensibilitycustomizationfromdocument'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
            ValueName = 'trustbar'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\internet\donotloadpictures'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\internet'
            ValueName = 'donotloadpictures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
            ValueName = 'extractdatadisableui'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublish'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
            ValueName = 'disableautorepublish'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublishwarning'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
            ValueName = 'disableautorepublishwarning'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fupdateext_78_1'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
            ValueName = 'fupdateext_78_1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\extensionhardening'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'extensionhardening'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'excelbypassencryptedmacroscan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'webservicefunctionwarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'blockcontentexecutionfrominternet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlaunch'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
            ValueName = 'disableddeserverlaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlookup'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
            ValueName = 'disableddeserverlookup'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\enableblockunsecurequeryfiles'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
            ValueName = 'enableblockunsecurequeryfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'dbasefiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'difandsylkfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl2macros'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl2worksheets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl3macros'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl3worksheets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl4macros'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl4workbooks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl4worksheets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl95workbooks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl9597workbooksandtemplates'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'htmlandxmlssfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueName = 'enableonload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueName = 'disableeditfrompv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\enabledatabasefileprotectedview'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
            ValueName = 'enabledatabasefileprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
            ValueName = 'disableinternetfilesinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
            ValueName = 'disableunsafelocationsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
            ValueName = 'disableattachmentsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
            ValueName = 'disallowattachmentcustomization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\general\msgformat'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\general'
            ValueName = 'msgformat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'internet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'junkmailenablelinks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
            ValueName = 'enablerpcencryption'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
        {
            ValueData = 16
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'authenticationservice'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'publicfolderscript'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'sharedfolderscript'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'allowactivexoneoffforms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publishtogaldisabled'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'publishtogaldisabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
        {
            ValueData = 168
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'minenckey'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\warnaboutinvalid'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'warnaboutinvalid'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'usecrlchasing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'adminsecuritymode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowuserstolowerattachments'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'allowuserstolowerattachments'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'showlevel1attach'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            Ensure = 'Absent'
            ValueName = 'fileextensionsremovelevel1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            Ensure = 'Absent'
            ValueName = 'fileextensionsremovelevel2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'enableoneoffformscripts'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomcustomaction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomaddressbookaccess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomformulaaccess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomsaveas'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomaddressinformationaccess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoommeetingtaskrequestresponse'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomsend'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'level'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'runprograms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'powerpointbypassencryptedmacroscan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'blockcontentexecutionfrominternet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\binaryfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
            ValueName = 'binaryfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            ValueName = 'enableonload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            ValueName = 'disableeditfrompv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
            ValueName = 'disableinternetfilesinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
            ValueName = 'disableattachmentsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
            ValueName = 'disableunsafelocationsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
            ValueName = 'blockcontentexecutionfrominternet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2000files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
            ValueName = 'visio2000files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2003files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
            ValueName = 'visio2003files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio50andearlierfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
            ValueName = 'visio50andearlierfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'notbpromptunsignedaddin'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'wordbypassencryptedmacroscan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'blockcontentexecutionfrominternet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word2files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word2000files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2003files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word2003files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2007files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word2007files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word60files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word95files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word97files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'wordxpfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            ValueName = 'openinprotectedview'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            ValueName = 'disableeditfrompv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            ValueName = 'enableonload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableinternetfilesinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
            ValueName = 'disableinternetfilesinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableunsafelocationsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
            ValueName = 'disableunsafelocationsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
            ValueName = 'disableattachmentsinpv'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
            ValueName = 'allownetworklocations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\uficontrols'
        {
            ValueData = 6
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueName = 'uficontrols'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueName = 'automationsecurity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueName = 'automationsecuritypublisher'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
            ValueName = 'neverloadmanifests'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\vba\security\loadcontrolsinforms'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\vba\security'
            ValueName = 'loadcontrolsinforms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
