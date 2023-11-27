configuration 'DoD_Office_System_2016_and_Components'
{
    Import-DSCResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion '1.1'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defaultformat'
        {
            ValueData = 51
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
            ValueName = 'defaultformat'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fglobalsheet_37_1'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
            ValueName = 'fglobalsheet_37_1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'requireaddinsig'
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

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            Ensure = 'Absent'
            ValueName = 'excelbypassencryptedmacroscan'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\accessvbom'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'accessvbom'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            Ensure = 'Absent'
            ValueName = 'webservicefunctionwarnings'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueName = 'blockcontentexecutionfrominternet'
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
            ValueData = 5
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'xl95workbooks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
        {
            ValueData = 5
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
            ValueName = 'htmlandxmlssfiles'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueName = 'enableonload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            Ensure = 'Absent'
            ValueName = 'openinprotectedview'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueName = 'disableeditfrompv'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableintranetcheck'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
            ValueName = 'disableintranetcheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\alllocationsdisabled'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
            ValueName = 'alllocationsdisabled'
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

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
        {
            ValueData = '1111-2222-3333-4444'
            Key = 'Software\Policies\Microsoft\OneDrive\AllowTenantList'
            ValueName = '1111-2222-3333-4444'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\meetings\profile\serverui'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\meetings\profile'
            ValueName = 'serverui'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat\pgrfafo_25_1'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat'
            ValueName = 'pgrfafo_25_1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\blockextcontent'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'blockextcontent'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblockspecificsenders'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'unblockspecificsenders'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblocksafezone'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'unblocksafezone'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\trustedzone'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'trustedzone'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\intranet'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'intranet'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readasplain'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'readasplain'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readsignedasplain'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'readsignedasplain'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\editorpreference'
        {
            ValueData = 65536
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'editorpreference'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\message rtf format'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
            ValueName = 'message rtf format'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disableofficeonline'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
            ValueName = 'disableofficeonline'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disabledav'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
            ValueName = 'disabledav'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\publishcalendardetailspolicy'
        {
            ValueData = 16384
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
            ValueName = 'publishcalendardetailspolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\restrictedaccessonly'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
            ValueName = 'restrictedaccessonly'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enablefulltexthtml'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
            ValueName = 'enablefulltexthtml'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enableattachments'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
            ValueName = 'enableattachments'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\enableattachments'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
            ValueName = 'enableattachments'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\disable'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
            ValueName = 'disable'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'sharedfolderscript'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'allowactivexoneoffforms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\addintrust'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'addintrust'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enablerememberpwd'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'enablerememberpwd'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomsend'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoommeetingtaskrequestresponse'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'promptoomformulaaccess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\externalsmime'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'externalsmime'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\msgformats'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'msgformats'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\fipsmode'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'fipsmode'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\clearsign'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'clearsign'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\respondtoreceiptrequests'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'respondtoreceiptrequests'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'level'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\forcedefaultprofile'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'forcedefaultprofile'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\nocheckonsessionsecurity'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'nocheckonsessionsecurity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\supressnamechecks'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueName = 'supressnamechecks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'DELVALS_CU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
            Ensure = 'Present'
            ValueName = ''
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Exclusive = $True
        }#>

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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
        {
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            ValueData = 0
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
            ValueData = 0
            Key = 'Software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'groove.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'excel.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'mspub.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'powerpnt.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'pptview.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'visio.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'winproj.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'winword.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'outlook.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            ValueData = 0
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'spdesign.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            ValueData = 0
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'exprwd.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'msaccess.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            ValueData = 1
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'onenote.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            ValueData = 0
            Key = 'Software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueName = 'mse7.exe'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
        {
            ValueData = 1
            Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
            ValueName = 'DisablePersonalSync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
            ValueName = 'requireaddinsig'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trustwss'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
            ValueName = 'trustwss'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
        {
            ValueData = '1111-2222-3333-4444'
            Key = 'Software\Policies\Microsoft\OneDrive\AllowTenantList'
            ValueName = '1111-2222-3333-4444'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
            ValueName = 'requireaddinsig'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
        {
            ValueData = ''
            Key = 'HKCU:\keycupoliciesmsvbasecurity'
            Ensure = 'Absent'
            ValueName = 'loadcontrolsinforms'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\sendcustomerdata'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
            ValueName = 'sendcustomerdata'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disabledefaultservice'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
            ValueName = 'disabledefaultservice'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disableprogrammaticaccess'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
            ValueName = 'disableprogrammaticaccess'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\drm\requireconnection'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\drm'
            ValueName = 'requireconnection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\includescreenshot'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
            ValueName = 'includescreenshot'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\fixedformat\disablefixedformatdocproperties'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\fixedformat'
            ValueName = 'disablefixedformatdocproperties'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\ptwatson\ptwoptin'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\ptwatson'
            ValueName = 'ptwoptin'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryptproperty'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'openxmlencryptproperty'
            ValueType = 'Dword'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
        {
            ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'defaultencryption12'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\encryptdocprops'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
            ValueName = 'encryptdocprops'
            ValueType = 'Dword'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
            ValueName = 'trustbar'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablefileobfuscation'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
            ValueName = 'enablefileobfuscation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\requireserververification'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
            ValueName = 'requireserververification'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            Ensure = 'Absent'
            ValueName = 'uficontrols'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueName = 'automationsecurity'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
        {
            ValueData = 1
            Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
            ValueName = 'DisablePersonalSync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\promptforbadfiles'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher'
            ValueName = 'promptforbadfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
            ValueName = 'requireaddinsig'
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
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
        {
            ValueData = 3
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueName = 'automationsecuritypublisher'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\internet\donotunderlinehyperlinks'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\internet'
            ValueName = 'donotunderlinehyperlinks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'requireaddinsig'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\modaltrustdecisiononly'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'modaltrustdecisiononly'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
            ValueName = 'vbawarnings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\settings\default file format'
        {
            ValueData = 12
            Key = 'HKCU:\software\policies\microsoft\office\16.0\access\settings'
            ValueName = 'default file format'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
        {
            ValueData = 0
            Key = 'Software\policies\microsoft\office\16.0\lync'
            ValueName = 'savepassword'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\useonline'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
            ValueName = 'useonline'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\defaultformat'
        {
            ValueData = '
'
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
            ValueName = 'defaultformat'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\dontupdatelinks'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
            ValueName = 'dontupdatelinks'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'requireaddinsig'
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

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            Ensure = 'Absent'
            ValueName = 'wordbypassencryptedmacroscan'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\accessvbom'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'accessvbom'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueName = 'vbawarnings'
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
            ValueData = 5
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word2000files'
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
            ValueData = 5
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word95files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
        {
            ValueData = 5
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'word97files'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
        {
            ValueData = 5
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
            ValueName = 'wordxpfiles'
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

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            Ensure = 'Absent'
            ValueName = 'openinprotectedview'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            ValueName = 'disableeditfrompv'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableintranetcheck'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
            ValueName = 'disableintranetcheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\alllocationsdisabled'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
            ValueName = 'alllocationsdisabled'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\options\defaultformat'
        {
            ValueData = 27
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\options'
            ValueName = 'defaultformat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\requireaddinsig'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'requireaddinsig'
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

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            Ensure = 'Absent'
            ValueName = 'powerpointbypassencryptedmacroscan'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\accessvbom'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'accessvbom'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            Ensure = 'Absent'
            ValueName = 'runprograms'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
        {
            ValueData = 2
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueName = 'vbawarnings'
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

        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
        {
            ValueData = ''
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            Ensure = 'Absent'
            ValueName = 'openinprotectedview'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
        }

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            ValueName = 'disableeditfrompv'
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

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableintranetcheck'
        {
            ValueData = 0
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
            ValueName = 'disableintranetcheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
        }#>

        <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\alllocationsdisabled'
        {
            ValueData = 1
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
            ValueName = 'alllocationsdisabled'
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

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
}
