configuration 'DoD_Mozilla_Firefox_v6r5'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SSLVersionMin'
        {
            ValueData = 'tls1.2'
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'SSLVersionMin'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\ExtensionUpdate'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'ExtensionUpdate'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFormHistory'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableFormHistory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PasswordManagerEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableTelemetry'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableTelemetry'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableDeveloperTools'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableDeveloperTools'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableForgetButton'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableForgetButton'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePrivateBrowsing'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisablePrivateBrowsing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SearchSuggestEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'SearchSuggestEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\NetworkPrediction'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'NetworkPrediction'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxAccounts'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableFirefoxAccounts'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFeedbackCommands'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableFeedbackCommands'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Preferences'
        {
            ValueData = '{"security.default_personal_cert": {"Value": "Ask Every Time","Status": "locked"},"browser.search.update": { "Value": false,    "Status": "locked"  },  "dom.disable_window_move_resize": {    "Value": true,    "Status": "locked"  },  "dom.disable_window_flip": {    "Value": true,    "Status": "locked"  },   "browser.contentblocking.category": {    "Value": "strict",    "Status": "locked"  },  "extensions.htmlaboutaddons.recommendations.enabled": {    "Value": false,    "Status": "locked"  }}'
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'Preferences'
            ValueType = 'MultiString'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePocket'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisablePocket'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxStudies'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableFirefoxStudies'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\Certificates'
            ValueName = 'ImportEnterpriseRoots'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisabledCiphers\TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\DisabledCiphers'
            ValueName = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Fingerprinting'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            ValueName = 'Fingerprinting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Cryptomining'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            ValueName = 'Cryptomining'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Enabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Locked'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            ValueName = 'Locked'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Search'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'Search'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\TopSites'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'TopSites'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredTopSites'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'SponsoredTopSites'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Highlights'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'Highlights'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Pocket'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'Pocket'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredPocket'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'SponsoredPocket'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Snippets'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'Snippets'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Locked'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueName = 'Locked'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission\Default'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\InstallAddonsPermission'
            ValueName = 'Default'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Permissions\Autoplay\Default'
        {
            ValueData = 'block-audio-video'
            Key = 'Software\Policies\Mozilla\Firefox\Permissions\Autoplay'
            ValueName = 'Default'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Default'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
            ValueName = 'Default'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Locked'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
            ValueName = 'Locked'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
        {
            ValueData = ''
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\1'
        {
            ValueData = '.mil'
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\2'
        {
            ValueData = '.gov'
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
            ValueName = '2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cache'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'Cache'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cookies'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'Cookies'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Downloads'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'Downloads'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\FormData'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'FormData'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\History'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'History'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Sessions'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'Sessions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\SiteSettings'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'SiteSettings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\OfflineApps'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'OfflineApps'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Locked'
        {
            ValueData = 1
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueName = 'Locked'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging\ExtensionRecommendations'
        {
            ValueData = 0
            Key = 'Software\Policies\Mozilla\Firefox\UserMessaging'
            ValueName = 'ExtensionRecommendations'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
