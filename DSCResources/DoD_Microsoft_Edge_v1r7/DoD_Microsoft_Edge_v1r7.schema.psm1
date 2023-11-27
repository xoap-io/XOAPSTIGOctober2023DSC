configuration 'DoD_Microsoft_Edge_v1r7'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SSLVersionMin'
        {
            ValueData = 'tls1.2'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SSLVersionMin'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SyncDisabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SyncDisabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportBrowserSettings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DeveloperToolsAvailability'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DeveloperToolsAvailability'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PromptForDownloadLocation'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PromptForDownloadLocation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PreventSmartScreenPromptOverride'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PreventSmartScreenPromptOverrideForFiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'InPrivateModeAvailability'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowDeletingBrowserHistory'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AllowDeletingBrowserHistory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BackgroundModeEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'BackgroundModeEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultPopupsSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DefaultPopupsSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NetworkPredictionOptions'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'NetworkPredictionOptions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SearchSuggestEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportAutofillFormData'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportAutofillFormData'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportCookies'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportCookies'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportExtensions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHistory'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportHistory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHomepage'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportHomepage'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportOpenTabs'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportOpenTabs'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportPaymentInfo'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportPaymentInfo'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSavedPasswords'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportSavedPasswords'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSearchEngine'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportSearchEngine'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportShortcuts'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ImportShortcuts'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AutoplayAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableMediaRouter'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'EnableMediaRouter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AutofillCreditCardEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AutofillAddressEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PersonalizationReportingEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PersonalizationReportingEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultGeolocationSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DefaultGeolocationSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PasswordManagerEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#
        This MultiString Value has a value of $null,
        Some Security Policies require Registry Values to be $null
        If you believe ' ' is the correct value for this string, you may change it here.
        #>
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\IsolateOrigins'
        {
            ValueData = $null
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'IsolateOrigins'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenPuaEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'PaymentMethodQueryEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AlternateErrorPagesEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AlternateErrorPagesEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'UserFeedbackAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeCollectionsEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'EdgeCollectionsEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureShare'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ConfigureShare'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'BrowserGuestModeEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'BuiltInDnsClientEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'SitePerProcess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ManagedSearchEngines'
        {
            ValueData = '[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ManagedSearchEngines'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AuthSchemes'
        {
            ValueData = 'ntlm,negotiate'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'AuthSchemes'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebUsbGuardSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DefaultWebUsbGuardSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebBluetoothGuardSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DefaultWebBluetoothGuardSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'TrackingPrevention'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RelaunchNotification'
        {
            ValueData = 2
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'RelaunchNotification'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ProxySettings'
        {
            ValueData = 'ADD YOUR PROXY CONFIGURATIONS HERE'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'ProxySettings'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableOnlineRevocationChecks'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'EnableOnlineRevocationChecks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\QuicAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'QuicAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DownloadRestrictions'
        {
            ValueData = 1
            Key = 'Software\Policies\Microsoft\Edge'
            ValueName = 'DownloadRestrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\1'
        {
            ValueData = '[*.]gov'
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\2'
        {
            ValueData = '[*.]mil'
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueName = '2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\1'
        {
            ValueData = '*'
            Key = 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
        {
            ValueData = ''
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\1'
        {
            ValueData = '[*.]mil'
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\2'
        {
            ValueData = '[*.]gov'
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueName = '2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
