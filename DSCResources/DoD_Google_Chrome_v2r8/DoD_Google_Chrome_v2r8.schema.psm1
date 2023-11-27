configuration 'DoD_Google_Chrome_v2r8'
{
     Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'RemoteAccessHostFirewallTraversal'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultPopupsSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultGeolocationSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
        {
            ValueData = 'Google Encrypted'
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultSearchProviderName'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultSearchProviderEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'BackgroundModeEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SyncDisabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'CloudPrintProxyEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'MetricsReportingEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SearchSuggestEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'ImportSavedPasswords'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'IncognitoModeAvailability'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SavingBrowserHistoryDisabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'AllowDeletingBrowserHistory'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'PromptForDownloadLocation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'AutoplayAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SafeBrowsingExtendedReportingEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultWebUsbGuardSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'ChromeCleanupEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupReportingEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'ChromeCleanupReportingEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'EnableMediaRouter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'WebRtcEventLogCollectionAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'NetworkPredictionOptions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DeveloperToolsAvailability'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BrowserGuestModeEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'BrowserGuestModeEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillCreditCardEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'AutofillCreditCardEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillAddressEnabled'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'AutofillAddressEnabled'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportAutofillFormData'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'ImportAutofillFormData'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SafeBrowsingProtectionLevel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
        {
            ValueData = 'https://www.google.com/search?q={searchTerms}'
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultSearchProviderSearchURL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DownloadRestrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebBluetoothGuardSetting'
        {
            ValueData = 2
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'DefaultWebBluetoothGuardSetting'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\QuicAllowed'
        {
            ValueData = 0
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'QuicAllowed'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
        {
            ValueData = 1
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'EnableOnlineRevocationChecks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SSLVersionMin'
        {
            ValueData = 'tls1.2'
            Key = 'Software\Policies\Google\Chrome'
            ValueName = 'SSLVersionMin'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\AutoplayAllowlist'
        {
            ValueData = ''
            Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\1'
        {
            ValueData = '[*.]mil'
            Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\2'
        {
            ValueData = '[*.]gov'
            Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
            ValueName = '2'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
        {
            ValueData = ''
            Key = 'Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
        {
            ValueData = ''
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\1'
        {
            ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
        {
            ValueData = ''
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist\1'
        {
            ValueData = '*'
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\URLBlocklist'
        {
            ValueData = ''
            Key = 'Software\Policies\Google\Chrome\URLBlocklist'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlocklist\1'
        {
            ValueData = 'javascript://*'
            Key = 'Software\Policies\Google\Chrome\URLBlocklist'
            ValueName = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
