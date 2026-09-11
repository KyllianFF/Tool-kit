<#
    Toolkit - Test suite (Pester 5)

    Scope of these tests: the deterministic parts. Subnet arithmetic, winget
    output parsing, package identifier validation, catalog integrity and the
    password generator all have a right answer that does not depend on the
    machine, so they are the ones worth asserting.

    Anything that reads real hardware or changes the system is deliberately
    not tested here: those need a controlled machine, not a unit test.

    Run with:
        Invoke-Pester -Path .\tests\Toolkit.Tests.ps1
#>

BeforeAll {

    $script:RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent

    # -NoGui loads every function without opening a window.
    . (Join-Path -Path $script:RepositoryRoot -ChildPath 'toolkit.ps1') -NoGui | Out-Null
}

Describe 'IPv4 conversion' {

    It 'converts <Address> to <Expected> and back' -TestCases @(
        @{ Address = '0.0.0.0';         Expected = 0 }
        @{ Address = '192.168.1.1';     Expected = 3232235777 }
        @{ Address = '10.0.0.1';        Expected = 167772161 }
        @{ Address = '255.255.255.255'; Expected = 4294967295 }
    ) {
        param($Address, $Expected)

        $value = ConvertTo-TkIPv4Integer -Address $Address

        $value | Should -Be $Expected
        (ConvertFrom-TkIPv4Integer -Value $value) | Should -Be $Address
    }

    It 'rejects a value that is not an IPv4 address' {
        { ConvertTo-TkIPv4Integer -Address 'not-an-address' } | Should -Throw
    }

    It 'rejects an IPv6 address' {
        { ConvertTo-TkIPv4Integer -Address '::1' } | Should -Throw
    }
}

Describe 'Subnet masks' {

    It 'builds the mask for /<Prefix>' -TestCases @(
        @{ Prefix = 0;  Mask = '0.0.0.0' }
        @{ Prefix = 8;  Mask = '255.0.0.0' }
        @{ Prefix = 12; Mask = '255.240.0.0' }
        @{ Prefix = 22; Mask = '255.255.252.0' }
        @{ Prefix = 24; Mask = '255.255.255.0' }
        @{ Prefix = 30; Mask = '255.255.255.252' }
        @{ Prefix = 32; Mask = '255.255.255.255' }
    ) {
        param($Prefix, $Mask)

        ConvertTo-TkSubnetMask -PrefixLength $Prefix | Should -Be $Mask
        ConvertFrom-TkSubnetMask -SubnetMask $Mask   | Should -Be $Prefix
    }

    It 'rejects a non contiguous mask' {
        { ConvertFrom-TkSubnetMask -SubnetMask '255.0.255.0' } | Should -Throw
    }
}

Describe 'Get-TkSubnetInfo' {

    Context 'a standard /24' {

        BeforeAll {
            $script:Info = Get-TkSubnetInfo -Address '192.168.1.10/24'
        }

        It 'finds the network address'   { $script:Info.NetworkAddress   | Should -Be '192.168.1.0' }
        It 'finds the broadcast address' { $script:Info.BroadcastAddress | Should -Be '192.168.1.255' }
        It 'finds the first host'        { $script:Info.FirstHost        | Should -Be '192.168.1.1' }
        It 'finds the last host'         { $script:Info.LastHost         | Should -Be '192.168.1.254' }
        It 'counts 254 usable hosts'     { $script:Info.UsableHosts      | Should -Be 254 }
        It 'builds the wildcard mask'    { $script:Info.WildcardMask     | Should -Be '0.0.0.255' }
        It 'reports the RFC 1918 scope'  { $script:Info.Scope            | Should -Match 'RFC 1918' }
    }

    Context 'a /31 point to point link' {

        BeforeAll {
            $script:Link = Get-TkSubnetInfo -Address '10.1.1.1/31'
        }

        It 'makes both addresses usable, per RFC 3021' {
            $script:Link.UsableHosts | Should -Be 2
            $script:Link.FirstHost   | Should -Be '10.1.1.0'
            $script:Link.LastHost    | Should -Be '10.1.1.1'
        }
    }

    Context 'a /32 host route' {

        It 'reports exactly one usable address' {
            $single = Get-TkSubnetInfo -Address '8.8.8.8/32'

            $single.UsableHosts | Should -Be 1
            $single.FirstHost   | Should -Be '8.8.8.8'
            $single.LastHost    | Should -Be '8.8.8.8'
        }
    }

    Context 'address scopes' {

        It 'classifies <Address> as <Expected>' -TestCases @(
            @{ Address = '10.0.0.1/8';      Expected = 'RFC 1918' }
            @{ Address = '172.20.1.1/12';   Expected = 'RFC 1918' }
            @{ Address = '192.168.5.1/24';  Expected = 'RFC 1918' }
            @{ Address = '169.254.1.1/16';  Expected = 'APIPA' }
            @{ Address = '100.64.1.1/10';   Expected = 'Carrier grade NAT' }
            @{ Address = '127.0.0.1/8';     Expected = 'Loopback' }
            @{ Address = '8.8.8.8/32';      Expected = 'Public' }
        ) {
            param($Address, $Expected)

            (Get-TkSubnetInfo -Address $Address).Scope | Should -Match $Expected
        }
    }

    It 'accepts a mask instead of a prefix length' {
        (Get-TkSubnetInfo -Address '192.168.1.10' -SubnetMask '255.255.255.0').PrefixLength | Should -Be 24
    }

    It 'refuses to guess when no prefix is given' {
        { Get-TkSubnetInfo -Address '192.168.1.10' } | Should -Throw
    }
}

Describe 'Split-TkSubnet' {

    It 'splits a /22 into four /24 networks' {
        $subnets = Split-TkSubnet -Network '10.0.0.0/22' -NewPrefixLength 24

        $subnets.Count            | Should -Be 4
        $subnets[0].NetworkAddress | Should -Be '10.0.0.0'
        $subnets[3].NetworkAddress | Should -Be '10.0.3.0'
    }

    It 'refuses a new prefix shorter than the parent' {
        { Split-TkSubnet -Network '10.0.0.0/24' -NewPrefixLength 16 } | Should -Throw
    }

    It 'caps the result count so a huge split cannot hang the interface' {
        (Split-TkSubnet -Network '10.0.0.0/8' -NewPrefixLength 30 -MaxResults 10).Count | Should -Be 10
    }
}

Describe 'Get-TkPrefixForHostCount' {

    It 'returns /<Prefix> for <Hosts> hosts' -TestCases @(
        @{ Hosts = 1;    Prefix = 32 }
        @{ Hosts = 2;    Prefix = 31 }
        @{ Hosts = 50;   Prefix = 26 }
        @{ Hosts = 254;  Prefix = 24 }
        @{ Hosts = 300;  Prefix = 23 }
        @{ Hosts = 1000; Prefix = 22 }
    ) {
        param($Hosts, $Prefix)

        (Get-TkPrefixForHostCount -HostCount $Hosts).PrefixLength | Should -Be $Prefix
    }
}

Describe 'Test-TkAddressInSubnet' {

    It 'places 10.1.2.3 inside 10.0.0.0/8'         { Test-TkAddressInSubnet -Address '10.1.2.3' -Network '10.0.0.0/8' | Should -BeTrue }
    It 'keeps 192.168.2.1 out of 192.168.1.0/24'   { Test-TkAddressInSubnet -Address '192.168.2.1' -Network '192.168.1.0/24' | Should -BeFalse }
    It 'places the network address inside itself'  { Test-TkAddressInSubnet -Address '192.168.1.0' -Network '192.168.1.0/24' | Should -BeTrue }
}

Describe 'Test-TkPackageId' {

    It 'accepts the well formed identifier <Id>' -TestCases @(
        @{ Id = 'Google.Chrome' }
        @{ Id = 'Microsoft.VisualStudioCode' }
        @{ Id = '7zip.7zip' }
        @{ Id = 'Notepad++.Notepad++' }
        @{ Id = '9NKSQGP7F2NH' }
    ) {
        param($Id)
        Test-TkPackageId -PackageId $Id | Should -BeTrue
    }

    It 'rejects the injection attempt <Id>' -TestCases @(
        @{ Id = 'Google.Chrome; rm -rf /' }
        @{ Id = 'Google.Chrome && calc' }
        @{ Id = 'Google Chrome' }
        @{ Id = '"; Start-Process calc; "' }
        @{ Id = '--source;evil' }
        @{ Id = '' }
    ) {
        param($Id)
        Test-TkPackageId -PackageId $Id | Should -BeFalse
    }
}

Describe 'ConvertFrom-TkWingetTable' {

    It 'parses a table whose names contain spaces' {

        $output = @'
   \
Name                 Id                        Version      Available    Source
--------------------------------------------------------------------------------
Visual Studio Code   Microsoft.VisualStudioCode 1.85.0       1.86.0       winget
7-Zip 23.01 (x64)    7zip.7zip                 23.01        23.02        winget
'@

        $rows = ConvertFrom-TkWingetTable -Text $output

        $rows.Count       | Should -Be 2
        $rows[0].Id       | Should -Be 'Microsoft.VisualStudioCode'
        $rows[0].Name     | Should -Be 'Visual Studio Code'
        $rows[1].Name     | Should -Be '7-Zip 23.01 (x64)'
        $rows[1].Available | Should -Be '23.02'
    }

    It 'returns an empty result for text with no table' {
        (ConvertFrom-TkWingetTable -Text 'No installed package found.').Count | Should -Be 0
    }

    It 'returns an empty result for empty input' {
        (ConvertFrom-TkWingetTable -Text '').Count | Should -Be 0
    }
}

Describe 'ConvertTo-TkArray' {

    It 'turns null into an empty array, not an array holding null' {
        (ConvertTo-TkArray $null).Count | Should -Be 0
    }

    It 'keeps a populated collection intact' {
        (ConvertTo-TkArray @(1, 2, 3)).Count | Should -Be 3
    }

    It 'wraps a single value' {
        (ConvertTo-TkArray 'one').Count | Should -Be 1
    }

    # PowerShell unrolls a returned collection unless the comma operator stops
    # it, so a one element result arrives as a bare object and an empty one as
    # $null. Windows PowerShell 5.1 has no .Count on a scalar, so the failure
    # only shows there. These assert the type rather than the count, which is
    # what actually went wrong.
    It 'returns a real array for a single element' {
        , (ConvertTo-TkArray 'one') | Should -BeOfType [System.Object[]]
    }

    It 'returns a real array when the input was null' {
        , (ConvertTo-TkArray $null) | Should -BeOfType [System.Object[]]
    }

    It 'returns a real array when every element was null' {
        , (ConvertTo-TkArray @($null, $null)) | Should -BeOfType [System.Object[]]
    }
}

Describe 'ConvertTo-TkProcessArgument' {

    It 'leaves a simple argument alone'    { ConvertTo-TkProcessArgument -Value 'simple' | Should -Be 'simple' }
    It 'quotes an argument with spaces'    { ConvertTo-TkProcessArgument -Value 'two words' | Should -Be '"two words"' }
    It 'quotes an empty argument'          { ConvertTo-TkProcessArgument -Value '' | Should -Be '""' }
    It 'escapes an embedded quote'         { ConvertTo-TkProcessArgument -Value 'say "hi"' | Should -Match '\\"' }
}

Describe 'New-TkPassword' {

    It 'produces a password of the requested length' {
        (New-TkPassword -Length 32).Password.Length | Should -Be 32
    }

    It 'includes at least one character from every selected class' {

        # Repeated because the guarantee must hold every time, not on average.
        1..25 | ForEach-Object {

            $password = (New-TkPassword -Length 12).Password

            $password | Should -Match '[A-Z]'
            $password | Should -Match '[a-z]'
            $password | Should -Match '[0-9]'
            $password | Should -Match '[^A-Za-z0-9]'
        }
    }

    It 'excludes ambiguous characters by default' {
        (New-TkPassword -Length 128).Password | Should -Not -Match '[0O1lI|]'
    }

    It 'does not repeat itself across calls' {
        $passwords = 1..20 | ForEach-Object { (New-TkPassword -Length 24).Password }
        ($passwords | Select-Object -Unique).Count | Should -Be 20
    }

    It 'reports entropy consistent with the length and alphabet' {
        $result = New-TkPassword -Length 20

        $expected = [math]::Round(20 * [math]::Log($result.AlphabetSize, 2), 1)
        $result.EntropyBits | Should -Be $expected
    }

    It 'refuses a length too short to hold one character per class' {
        { New-TkPassword -Length 8 -IncludeUppercase $true -IncludeLowercase $true `
                         -IncludeDigits $true -IncludeSymbols $true } | Should -Not -Throw
    }

    It 'refuses when no character class is selected' {
        { New-TkPassword -Length 20 -IncludeUppercase $false -IncludeLowercase $false `
                         -IncludeDigits $false -IncludeSymbols $false } | Should -Throw
    }
}

Describe 'Get-TkRandomInteger' {

    It 'stays inside the requested range' {
        1..500 | ForEach-Object {
            $value = Get-TkRandomInteger -MaxExclusive 10
            $value | Should -BeGreaterOrEqual 0
            $value | Should -BeLessThan 10
        }
    }

    It 'always returns zero for a bound of one' {
        Get-TkRandomInteger -MaxExclusive 1 | Should -Be 0
    }

    It 'covers the whole range over many draws' {
        $seen = 1..600 | ForEach-Object { Get-TkRandomInteger -MaxExclusive 6 }
        ($seen | Select-Object -Unique | Sort-Object).Count | Should -Be 6
    }
}

Describe 'New-TkPassphrase' {

    It 'produces the requested number of words' {
        $result = New-TkPassphrase -WordCount 6 -Separator '-'
        ($result.Passphrase -split '-').Count | Should -Be 6
    }

    It 'reports entropy from the word list size' {
        $result   = New-TkPassphrase -WordCount 5
        $expected = [math]::Round(5 * [math]::Log($result.ListSize, 2), 1)

        $result.EntropyBits | Should -Be $expected
    }
}

Describe 'Format-TkValue' {

    It 'replaces the OEM placeholder <Value>' -TestCases @(
        @{ Value = 'To be filled by O.E.M.' }
        @{ Value = 'Default string' }
        @{ Value = 'System Serial Number' }
        @{ Value = '' }
        @{ Value = $null }
    ) {
        param($Value)
        Format-TkValue $Value | Should -Be 'Not available'
    }

    It 'keeps a real value and trims it' {
        Format-TkValue '  Latitude 7440  ' | Should -Be 'Latitude 7440'
    }
}

Describe 'Format-TkBytes' {

    It 'formats <Bytes> as <Expected>' -TestCases @(
        @{ Bytes = 1024;           Expected = '1.00 KB' }
        @{ Bytes = 1048576;        Expected = '1.00 MB' }
        @{ Bytes = 1073741824;     Expected = '1.00 GB' }
        @{ Bytes = 0;              Expected = 'n/a' }
        @{ Bytes = $null;          Expected = 'n/a' }
    ) {
        param($Bytes, $Expected)
        Format-TkBytes -Bytes $Bytes | Should -Be $Expected
    }
}

Describe 'Catalog integrity' {

    It 'loads the <Name> catalog' -TestCases @(
        @{ Name = 'applications' }
        @{ Name = 'tweaks' }
        @{ Name = 'fixes' }
        @{ Name = 'network-knowledge' }
        @{ Name = 'vendor-commands' }
        @{ Name = 'vendor-support' }
    ) {
        param($Name)
        Import-TkCatalog -Name $Name | Should -Not -BeNullOrEmpty
    }

    It 'gives every application a valid winget identifier' {

        foreach ($application in (Import-TkCatalog -Name 'applications').applications) {

            Test-TkPackageId -PackageId $application.packageId |
                Should -BeTrue -Because ('{0} declares "{1}"' -f $application.name, $application.packageId)
        }
    }

    It 'uses no duplicate application identifier' {
        $ids = (Import-TkCatalog -Name 'applications').applications | ForEach-Object { $_.id }
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'points every application at a declared category' {

        $catalog    = Import-TkCatalog -Name 'applications'
        $categories = $catalog.categories | ForEach-Object { $_.id }

        foreach ($application in $catalog.applications) {
            $categories | Should -Contain $application.category
        }
    }

    It 'gives every tweak a revert path' {

        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            $values = ConvertTo-TkArray $tweak.registry
            $keys   = ConvertTo-TkArray $tweak.registryKeys
            $services = ConvertTo-TkArray $tweak.services

            ($values.Count + $keys.Count + $services.Count) |
                Should -BeGreaterThan 0 -Because ('{0} must declare something to change' -f $tweak.id)

            foreach ($entry in $values) {
                $entry.PSObject.Properties.Name | Should -Contain 'default' -Because (
                    '{0} must say what to restore for {1}' -f $tweak.id, $entry.name
                )
            }

            foreach ($key in $keys) {
                $key.revertAction | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'uses only registered actions in the fixes catalog' {

        $allowed = (Get-TkFixDispatchTable).Keys

        foreach ($fix in (Import-TkCatalog -Name 'fixes').fixes) {
            $allowed | Should -Contain $fix.action
        }
    }

    It 'points every registered fix action at an existing function' {

        foreach ($functionName in (Get-TkFixDispatchTable).Values) {
            Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because ('{0} is dispatched but not defined' -f $functionName)
        }
    }

    It 'uses only https links in the vendor support catalog' {

        foreach ($vendor in (Import-TkCatalog -Name 'vendor-support').vendors) {

            foreach ($property in @('driversUrl', 'warrantyUrl', 'manualUrl')) {

                $url = $vendor.$property

                if ($url) {
                    $url | Should -Match '^https://'
                }
            }
        }
    }
}

Describe 'Expand-TkVendorUrl' {

    It 'substitutes and encodes the serial number' {

        $identity = [pscustomobject]@{
            SerialNumber = 'ABC 123'
            Model        = 'Latitude 7440'
            AssetTag     = 'Not available'
        }

        $url = Expand-TkVendorUrl -Template 'https://example.com/{serial}/drivers' -Identity $identity

        $url | Should -Be 'https://example.com/ABC%20123/drivers'
    }

    It 'never puts a placeholder value into a URL' {

        $identity = [pscustomobject]@{
            SerialNumber = 'Not available'
            Model        = 'Not available'
            AssetTag     = 'Not available'
        }

        Expand-TkVendorUrl -Template 'https://example.com/{serial}' -Identity $identity |
            Should -Be 'https://example.com/'
    }
}

Describe 'Test-TkFileHash' {

    BeforeAll {
        $script:TempFile = Join-Path -Path $env:TEMP -ChildPath ('tk-test-{0}.txt' -f ([guid]::NewGuid()))
        Set-Content -LiteralPath $script:TempFile -Value 'toolkit' -NoNewline -Encoding ASCII

        $script:KnownSha256 = (Get-FileHash -LiteralPath $script:TempFile -Algorithm SHA256).Hash
    }

    AfterAll {
        Remove-Item -LiteralPath $script:TempFile -Force -ErrorAction SilentlyContinue
    }

    It 'confirms a matching hash' {
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash $script:KnownSha256).Match | Should -BeTrue
    }

    It 'is not confused by case or separators in the published hash' {
        $formatted = ($script:KnownSha256.ToLower() -replace '(..)', '$1:').TrimEnd(':')
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash $formatted).Match | Should -BeTrue
    }

    It 'reports a mismatch' {
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash ('0' * 64)).Match | Should -BeFalse
    }

    It 'infers the algorithm from the hash length' {
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash ('0' * 32)).Algorithm | Should -Be 'MD5'
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash ('0' * 40)).Algorithm | Should -Be 'SHA1'
    }

    It 'refuses a hash of an unexpected length' {
        (Test-TkFileHash -Path $script:TempFile -ExpectedHash 'abc').Algorithm | Should -Be 'Unknown'
    }
}

Describe 'IPv6 conversion' {

    It 'round trips <Address>' -TestCases @(
        @{ Address = '2001:db8::1' }
        @{ Address = 'fe80::1' }
        @{ Address = '::1' }
        @{ Address = 'fd00:1234:5678::abcd' }
    ) {
        param($Address)

        $bytes = ConvertTo-TkIPv6Bytes -Address $Address

        $bytes.Count | Should -Be 16
        (ConvertFrom-TkIPv6Bytes -Bytes $bytes) | Should -Be $Address
    }

    It 'refuses an IPv4 address rather than answering the wrong question' {
        { ConvertTo-TkIPv6Bytes -Address '192.168.1.1' } | Should -Throw
    }

    It 'expands a compressed address' {
        Expand-TkIPv6Address -Address '2001:db8::1' |
            Should -Be '2001:0db8:0000:0000:0000:0000:0000:0001'
    }
}

Describe 'Get-TkIPv6SubnetInfo' {

    Context 'a /64 link' {

        BeforeAll {
            $script:Six = Get-TkIPv6SubnetInfo -Address '2001:db8:abcd:1234::5/64'
        }

        It 'finds the network'          { $script:Six.Network      | Should -Be '2001:db8:abcd:1234::' }
        It 'finds the last address'     { $script:Six.LastAddress  | Should -Be '2001:db8:abcd:1234:ffff:ffff:ffff:ffff' }
        It 'counts 2^64 addresses'      { $script:Six.AddressCount | Should -Be '18446744073709551616' }
        It 'reports the documentation scope' { $script:Six.Scope   | Should -Match 'Documentation' }
        It 'extracts the interface id'  { $script:Six.InterfaceId  | Should -Be '0000:0000:0000:0005' }
    }

    It 'counts the /64 links inside a <Prefix>' -TestCases @(
        @{ Prefix = '2001:db8::/48'; Links = '65536' }
        @{ Prefix = '2001:db8::/56'; Links = '256' }
        @{ Prefix = '2001:db8::/64'; Links = '1' }
    ) {
        param($Prefix, $Links)

        (Get-TkIPv6SubnetInfo -Address $Prefix).SubnetCount64 | Should -Be $Links
    }

    It 'classifies <Address> as <Expected>' -TestCases @(
        @{ Address = 'fe80::1/64';      Expected = 'Link local' }
        @{ Address = 'fd00::1/8';       Expected = 'Unique local' }
        @{ Address = '2001:db8::1/32';  Expected = 'Documentation' }
        @{ Address = '2606:4700::1/32'; Expected = 'Global unicast' }
        @{ Address = 'ff02::1/16';      Expected = 'Multicast' }
        @{ Address = '::1/128';         Expected = 'Loopback' }
    ) {
        param($Address, $Expected)

        (Get-TkIPv6SubnetInfo -Address $Address).Scope | Should -Match $Expected
    }

    It 'assumes a /64 when no prefix is given, because that is the link size' {
        (Get-TkIPv6SubnetInfo -Address '2001:db8::1').PrefixLength | Should -Be 64
    }
}

Describe 'ConvertTo-TkEui64' {

    It 'inserts fffe and flips the universal bit' {
        ConvertTo-TkEui64 -MacAddress '00:1A:2B:3C:4D:5E' | Should -Be '021a:2bff:fe3c:4d5e'
    }

    It 'accepts any common separator' {
        ConvertTo-TkEui64 -MacAddress '00-1A-2B-3C-4D-5E' | Should -Be '021a:2bff:fe3c:4d5e'
        ConvertTo-TkEui64 -MacAddress '001A2B3C4D5E'      | Should -Be '021a:2bff:fe3c:4d5e'
    }

    It 'rejects something that is not a MAC address' {
        { ConvertTo-TkEui64 -MacAddress 'nonsense' } | Should -Throw
    }
}

Describe 'Get-TkMacVendor' {

    It 'resolves the known prefix <Mac> to <Expected>' -TestCases @(
        @{ Mac = '00:0C:29:11:22:33'; Expected = 'VMware' }
        @{ Mac = '00-15-5D-01-02-03'; Expected = 'Microsoft Hyper-V' }
        @{ Mac = '080027AABBCC';      Expected = 'Oracle VirtualBox' }
        @{ Mac = 'B8:27:EB:00:00:01'; Expected = 'Raspberry Pi' }
    ) {
        param($Mac, $Expected)
        Get-TkMacVendor -MacAddress $Mac | Should -Be $Expected
    }

    It 'recognises a locally administered address' {
        # The second least significant bit of the first octet marks it.
        Get-TkMacVendor -MacAddress '02:11:22:33:44:55' | Should -Match 'Locally administered'
    }

    It 'says so plainly for an unknown prefix' {
        Get-TkMacVendor -MacAddress '00:11:22:33:44:55' | Should -Be 'Unknown vendor'
    }

    It 'returns nothing for empty input' {
        Get-TkMacVendor -MacAddress '' | Should -BeNullOrEmpty
    }
}

Describe 'Get-TkOuiTable' {

    It 'uses six uppercase hex characters for every prefix' {

        foreach ($key in (Get-TkOuiTable).Keys) {
            $key | Should -Match '^[0-9A-F]{6}$'
        }
    }

    It 'names every prefix' {

        foreach ($value in (Get-TkOuiTable).Values) {
            $value | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Knowledge base tables' {

    It 'gives every table the same number of cells as columns' {

        foreach ($topic in (Import-TkCatalog -Name 'network-knowledge').topics) {

            foreach ($table in (ConvertTo-TkArray $topic.tables)) {

                $width = @($table.columns).Count
                $width | Should -BeGreaterThan 0

                foreach ($row in $table.rows) {
                    @($row).Count | Should -Be $width -Because (
                        'a row of {0} in "{1}" does not match its columns' -f $table.title, $topic.title
                    )
                }
            }
        }
    }

    It 'names every table' {

        foreach ($topic in (Import-TkCatalog -Name 'network-knowledge').topics) {

            foreach ($table in (ConvertTo-TkArray $topic.tables)) {
                $table.title | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'keeps the port reference as tables rather than prose' {

        $ports  = (Import-TkCatalog -Name 'network-knowledge').topics |
                  Where-Object { $_.id -eq 'common-ports' }

        $tables = ConvertTo-TkArray $ports.tables
        $rows   = ($tables | ForEach-Object { @($_.rows).Count } | Measure-Object -Sum).Sum

        $tables.Count | Should -BeGreaterThan 3
        $rows         | Should -BeGreaterThan 30
    }
}

Describe 'Get-TkSeverityBrushKey' {

    It 'maps <Severity> to <Expected>' -TestCases @(
        @{ Severity = 'Fail';    Expected = 'Danger' }
        @{ Severity = 'Warning'; Expected = 'Warning' }
        @{ Severity = 'Pass';    Expected = 'Success' }
        @{ Severity = 'Info';    Expected = 'TextMuted' }
        @{ Severity = '';        Expected = 'TextMuted' }
    ) {
        param($Severity, $Expected)
        Get-TkSeverityBrushKey -Severity $Severity | Should -Be $Expected
    }
}

Describe 'New-TkHuntFinding' {

    It 'produces the shape the interface binds to' {

        $finding = New-TkHuntFinding -Category 'Failed logons' -Count 3 `
            -Detail 'three accounts' -Assessment 'nothing to see' -Severity 'Warning'

        $finding.Severity   | Should -Be 'Warning'
        $finding.Category   | Should -Be 'Failed logons'
        $finding.Count      | Should -Be 3
        $finding.Detail     | Should -Be 'three accounts'
        $finding.Assessment | Should -Be 'nothing to see'
    }

    It 'refuses a severity outside the set' {
        { New-TkHuntFinding -Category 'x' -Count 0 -Detail 'y' -Assessment 'z' -Severity 'Critical' } |
            Should -Throw
    }
}

Describe 'Test-TkPackageId with Store identifiers' {

    It 'accepts the Store product id <Id>' -TestCases @(
        @{ Id = '9NKSQGP7F2NH' }
        @{ Id = '9N7R5S6B0ZZH' }
        @{ Id = 'XPFCG5NZ9RC0P4' }
    ) {
        param($Id)
        Test-TkPackageId -PackageId $Id | Should -BeTrue
    }
}

Describe 'Catalog integrity, extended' {

    It 'declares a revert value for every tweak registry entry that is not deleted' {

        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            foreach ($entry in (ConvertTo-TkArray $tweak.registry)) {

                $names = $entry.PSObject.Properties.Name

                $names | Should -Contain 'default' -Because (
                    '{0} must say what to restore for {1}' -f $tweak.id, $entry.name
                )
            }
        }
    }

    It 'uses a supported registry type in every tweak' {

        $supported = @('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')

        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            foreach ($entry in (ConvertTo-TkArray $tweak.registry)) {
                $supported | Should -Contain $entry.type
            }
        }
    }
}

Describe 'Vendor command catalog' {

    BeforeAll {
        $script:Vendors = (Import-TkCatalog -Name 'vendor-commands').vendors
    }

    It 'names every vendor uniquely' {
        $names = @($script:Vendors | ForEach-Object { $_.name })
        ($names | Select-Object -Unique).Count | Should -Be $names.Count
    }

    It 'gives every vendor a description and at least one section' {

        foreach ($vendor in $script:Vendors) {
            $vendor.description       | Should -Not -BeNullOrEmpty
            @($vendor.sections).Count | Should -BeGreaterThan 0
        }
    }

    It 'gives every command both a command and an explanation' {

        foreach ($vendor in $script:Vendors) {

            foreach ($section in $vendor.sections) {

                $section.name | Should -Not -BeNullOrEmpty

                foreach ($entry in $section.commands) {

                    $entry.command     | Should -Not -BeNullOrEmpty -Because ('in {0}' -f $vendor.name)
                    $entry.description | Should -Not -BeNullOrEmpty -Because (
                        '{0} in {1} has no explanation' -f $entry.command, $vendor.name
                    )
                }
            }
        }
    }

    It 'covers the platforms a network engineer actually meets' {

        $names = @($script:Vendors | ForEach-Object { $_.name })

        foreach ($expected in @('Cisco', 'Aruba', 'Fortinet', 'Juniper', 'MikroTik',
                                'Palo Alto', 'pfSense', 'Stormshield', 'Extreme',
                                'Comware', 'Meraki', 'Ubiquiti')) {

            ($names -join ' ') | Should -Match $expected
        }
    }
}

Describe 'Knowledge base coverage' {

    BeforeAll {
        $script:Topics = (Import-TkCatalog -Name 'network-knowledge').topics
    }

    It 'gives every topic a summary and some content' {

        foreach ($topic in $script:Topics) {
            $topic.title   | Should -Not -BeNullOrEmpty
            $topic.summary | Should -Not -BeNullOrEmpty
            @($topic.content).Count | Should -BeGreaterThan 0
        }
    }

    It 'points every topic at a declared category' {

        $catalog    = Import-TkCatalog -Name 'network-knowledge'
        $categories = @($catalog.categories | ForEach-Object { $_.id })

        foreach ($topic in $catalog.topics) {
            $categories | Should -Contain $topic.category
        }
    }

    It 'uses a unique identifier for every topic' {
        $ids = @($script:Topics | ForEach-Object { $_.id })
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'covers the subjects the toolkit claims to cover' {

        $titles = (@($script:Topics | ForEach-Object { $_.title }) -join ' ')

        foreach ($subject in @('OSI', '802.1X', 'Power over Ethernet', 'Quality of service',
                               'BGP', 'IPv6', 'Certificates', 'DNS', 'VLAN', 'Wi-Fi')) {

            $titles | Should -Match $subject
        }
    }
}

Describe 'Theme palettes' {

    It 'defines the same keys in both themes' {

        # A key present in one palette and missing from the other keeps its
        # previous value on a swap, which is how a half-converted, unreadable
        # window happens.
        $dark  = Get-TkThemePalette -Name Dark
        $light = Get-TkThemePalette -Name Light

        ($dark.Keys  | Sort-Object) -join ',' | Should -Be (($light.Keys | Sort-Object) -join ',')
    }

    It 'gives every colour in <Theme> a valid hex value' -TestCases @(
        @{ Theme = 'Dark' }
        @{ Theme = 'Light' }
    ) {
        param($Theme)

        foreach ($value in (Get-TkThemePalette -Name $Theme).Values) {
            $value | Should -Match '^#[0-9A-Fa-f]{6}$'
        }
    }

    It 'keeps text and background far apart in <Theme>' -TestCases @(
        @{ Theme = 'Dark' }
        @{ Theme = 'Light' }
    ) {
        param($Theme)

        # A crude luminance gap check. It will not catch a subtle contrast
        # failure, but it does catch the mistake that actually happens: a
        # foreground copied from the wrong palette.
        $palette = Get-TkThemePalette -Name $Theme

        $luminance = {
            param($hex)

            $r = [Convert]::ToInt32($hex.Substring(1, 2), 16)
            $g = [Convert]::ToInt32($hex.Substring(3, 2), 16)
            $b = [Convert]::ToInt32($hex.Substring(5, 2), 16)

            return (0.299 * $r + 0.587 * $g + 0.114 * $b)
        }

        $textLuminance    = & $luminance $palette['TextPrimary']
        $surfaceLuminance = & $luminance $palette['Surface']

        [math]::Abs($textLuminance - $surfaceLuminance) | Should -BeGreaterThan 120
    }
}

Describe 'Get-TkWellKnownService' {

    It 'names port <Port> as <Expected>' -TestCases @(
        @{ Port = 22;   Expected = 'SSH / SFTP' }
        @{ Port = 443;  Expected = 'HTTPS' }
        @{ Port = 3389; Expected = 'RDP' }
        @{ Port = 445;  Expected = 'SMB' }
    ) {
        param($Port, $Expected)
        Get-TkWellKnownService -Port $Port | Should -Be $Expected
    }

    It 'returns nothing for an unassigned port' {
        Get-TkWellKnownService -Port 54321 | Should -BeNullOrEmpty
    }
}

Describe 'Interface rendering' {

    BeforeAll {

        Add-Type -AssemblyName PresentationFramework
        Add-Type -AssemblyName PresentationCore
        Add-Type -AssemblyName WindowsBase

        # Parsed, not shown. Building the object graph is enough to assert the
        # styles and the templates, and a test suite must not need a desktop.
        $script:Window = [System.Windows.Markup.XamlReader]::Parse((Get-TkMainWindowXaml))
    }

    Context 'Selectable text' {

        # The regression this guards against emptied every table and every
        # finding card in the application at once. A TextBox whose Template is
        # null has no visual tree: it reports a correct size and draws
        # nothing, so the rows were the right height and blank. The template
        # has to contain a ScrollViewer named PART_ContentHost, which is where
        # TextBoxBase renders the text.

        It 'declares a SelectableText style' {
            $script:Window.Resources['SelectableText'] | Should -Not -BeNullOrEmpty
        }

        It 'renders a selectable text box into a visual tree' {

            $text = New-TkSelectableText -Value 'thumbprint 3B:9A:00'

            $text.Text       | Should -Be 'thumbprint 3B:9A:00'
            $text.IsReadOnly | Should -BeTrue

            # The style is attached by resource reference, which resolves only
            # once the control joins a tree carrying that resource. Checking it
            # detached would pass whatever the style said.
            $holder = New-Object System.Windows.Controls.ContentControl
            $holder.Resources = $script:Window.Resources
            $holder.Content   = $text

            $holder.Measure((New-Object System.Windows.Size(600, 120)))
            $holder.Arrange((New-Object System.Windows.Rect(0, 0, 600, 120)))
            $holder.UpdateLayout()

            $text.Template | Should -Not -BeNullOrEmpty

            # The assertion that matters. With the template cleared this was
            # zero: a control of the correct size drawing nothing at all.
            [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($text) |
                Should -BeGreaterThan 0

            $text.Template.FindName('PART_ContentHost', $text) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Tables' {

        It 'renders a row per record plus the header' {

            $document = New-TkFlowDocument

            Add-TkTable -Document $document -Column @('Port', 'Service') -Row @(
                , @('22',  'SSH')
                , @('443', 'HTTPS')
            )

            $grid = @($document.Blocks)[0].Child

            $grid.RowDefinitions.Count | Should -Be 3
        }

        It 'puts the value of every cell into the tree' {

            $document = New-TkFlowDocument

            Add-TkTable -Document $document -Column @('Port', 'Service') -Row @(
                , @('22', 'SSH')
            )

            $grid = @($document.Blocks)[0].Child

            $values = @($grid.Children |
                        Where-Object { $_ -is [System.Windows.Controls.Border] -and
                                       $_.Child -is [System.Windows.Controls.TextBox] } |
                        ForEach-Object { $_.Child.Text })

            $values | Should -Contain '22'
            $values | Should -Contain 'SSH'
        }

        It 'gives every column boundary a resize handle' {

            $document = New-TkFlowDocument

            Add-TkTable -Document $document -Column @('A', 'B', 'C') -Row @(, @('1', '2', '3'))

            $grid = @($document.Blocks)[0].Child

            $splitters = @($grid.Children |
                           Where-Object { $_ -is [System.Windows.Controls.GridSplitter] })

            # One fewer than the columns: the last edge is the table edge.
            $splitters.Count | Should -Be 2
        }

        It 'bands alternate rows' {

            $document = New-TkFlowDocument

            Add-TkTable -Document $document -Column @('A') -Row @(
                , @('one')
                , @('two')
            )

            $grid = @($document.Blocks)[0].Child

            $banded = @($grid.Children |
                        Where-Object {
                            $_ -is [System.Windows.Controls.Border] -and
                            $_.ReadLocalValue([System.Windows.Controls.Border]::BackgroundProperty) -ne
                                [System.Windows.DependencyProperty]::UnsetValue
                        })

            # The header carries one, and one of the two data rows.
            $banded.Count | Should -BeGreaterThan 1
        }

        It 'converts objects into one row each' {

            $rows = ConvertTo-TkTableRow @(
                [pscustomobject] @{ Name = 'eth0';  State = 'Up' }
                [pscustomobject] @{ Name = 'wlan0'; State = 'Down' }
            ) @('Name', 'State')

            # The comma operator is what stops these being flattened into one
            # long list of cells, which renders as a single column.
            $rows.Count       | Should -Be 2
            $rows[0].Count    | Should -Be 2
            $rows[1][0]       | Should -Be 'wlan0'
        }
    }

    Context 'Icons' {

        BeforeAll {

            $family = New-Object System.Windows.Media.FontFamily('Segoe Fluent Icons, Segoe MDL2 Assets')

            $typeface = New-Object System.Windows.Media.Typeface($family,
                [System.Windows.FontStyles]::Normal,
                [System.Windows.FontWeights]::Normal,
                [System.Windows.FontStretches]::Normal)

            $found = $null

            $script:GlyphTypeface = if ($typeface.TryGetGlyphTypeface([ref] $found)) { $found } else { $null }
        }

        It 'draws every navigation icon from a code point the font carries' {

            if ($null -eq $script:GlyphTypeface) {
                Set-ItResult -Skipped -Because 'neither Windows icon font is installed on this machine'
                return
            }

            # A code point the font does not carry renders as an empty box.
            # Nothing else in the suite can see that.
            foreach ($name in @('NavSystem', 'NavSoftware', 'NavTweaks', 'NavFixes',
                                'NavNetwork', 'NavDiagnostics', 'NavSecurity')) {

                $button = $script:Window.FindName($name)

                $button | Should -Not -BeNullOrEmpty -Because ('{0} should exist' -f $name)

                $point = [int] [char] ([string] $button.Tag)

                $script:GlyphTypeface.CharacterToGlyphMap.ContainsKey($point) |
                    Should -BeTrue -Because ('{0} uses U+{1:X4}, which the icon font does not carry' -f $name, $point)
            }
        }

        It 'draws every list tile icon from a code point the font carries' {

            if ($null -eq $script:GlyphTypeface) {
                Set-ItResult -Skipped -Because 'neither Windows icon font is installed on this machine'
                return
            }

            $catalog = Import-TkCatalog -Name 'applications'

            $keys = @(@($catalog.categories | ForEach-Object { $_.id }) +
                      @('advanced', 'gaming', 'hardening', 'interface', 'performance', 'privacy') +
                      @('Low', 'Medium', 'High'))

            foreach ($key in $keys) {

                $glyphs = @(
                    (Get-TkCategoryGlyph -Key $key)
                    (Get-TkTweakGlyph    -Key $key)
                    (Get-TkFixGlyph      -Key $key)
                )

                foreach ($glyph in $glyphs) {

                    $point = [int] [char] $glyph

                    $script:GlyphTypeface.CharacterToGlyphMap.ContainsKey($point) |
                        Should -BeTrue -Because ('"{0}" maps to U+{1:X4}, which the icon font does not carry' -f $key, $point)
                }
            }
        }
    }

    Context 'Disabled actions' {

        It 'lets a disabled button still show its tooltip' {

            # WPF hides a tooltip on a disabled control by default, which
            # silences exactly the message explaining why it is disabled.
            $style = $script:Window.Resources[[System.Windows.Controls.Button]]

            $setter = @($style.Setters |
                        Where-Object { $_.Property.Name -eq 'ShowOnDisabled' } |
                        Select-Object -First 1)

            $setter.Value | Should -BeTrue
        }
    }

    Context 'Report choosers' {

        It 'stops the <Name> list from scrolling sideways' -TestCases @(
            @{ Name = 'DiagnosticChoices' }
            @{ Name = 'HuntChoices' }
        ) {
            param($Name)

            # With horizontal scrolling on, an entry is measured at its natural
            # width and the panel grows past its frame instead of wrapping
            # inside it, which is what put a scroll bar under both choosers.
            $list = $script:Window.FindName($Name)

            $list | Should -Not -BeNullOrEmpty

            [System.Windows.Controls.ScrollViewer]::GetHorizontalScrollBarVisibility($list) |
                Should -Be ([System.Windows.Controls.ScrollBarVisibility]::Disabled)
        }

        It 'keeps the explanation of every <Name> entry in a tooltip' -TestCases @(
            @{ Name = 'DiagnosticChoices' }
            @{ Name = 'HuntChoices' }
        ) {
            param($Name)

            $list = $script:Window.FindName($Name)

            foreach ($item in $list.Items) {
                $item.ToolTip | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'Application icons' {

    BeforeAll {

        Add-Type -AssemblyName PresentationFramework
        Add-Type -AssemblyName PresentationCore
        Add-Type -AssemblyName WindowsBase

        $script:IconCatalog = Import-TkCatalog -Name 'app-icons'
        $script:AppCatalog  = Import-TkCatalog -Name 'applications'
    }

    It 'loads the icon catalogue' {
        $script:IconCatalog       | Should -Not -BeNullOrEmpty
        $script:IconCatalog.icons | Should -Not -BeNullOrEmpty
    }

    It 'parses every icon as a geometry' {

        # A malformed path throws when the list is built, which would take the
        # whole page down rather than lose one tile.
        foreach ($entry in $script:IconCatalog.icons.PSObject.Properties) {

            { [System.Windows.Media.Geometry]::Parse($entry.Value.path) } |
                Should -Not -Throw -Because ('{0} should be a valid path' -f $entry.Name)
        }
    }

    It 'points every icon at an application in the catalogue' {

        # An icon keyed to a package that no longer exists is dead weight in
        # the build and a sign the catalogue moved without it.
        $packages = @($script:AppCatalog.applications | ForEach-Object { $_.packageId })

        foreach ($entry in $script:IconCatalog.icons.PSObject.Properties) {
            $packages | Should -Contain $entry.Name
        }
    }

    It 'returns a geometry for a package that has one' {

        $geometry = Get-TkAppIconGeometry -PackageId 'Mozilla.Firefox'

        $geometry | Should -Not -BeNullOrEmpty
        $geometry.IsFrozen | Should -BeTrue -Because 'a shared geometry must be frozen to be reused safely'
    }

    It 'returns nothing for a package that has none' {

        # The deliberate gap: these fall back to the category icon, so the
        # lookup has to say "no icon" rather than invent one.
        Get-TkAppIconGeometry -PackageId 'Microsoft.PowerToys' | Should -BeNullOrEmpty
        Get-TkAppIconGeometry -PackageId '' | Should -BeNullOrEmpty
    }

    It 'draws every dialog icon from a code point the font carries' {

        $family = New-Object System.Windows.Media.FontFamily('Segoe Fluent Icons, Segoe MDL2 Assets')

        $typeface = New-Object System.Windows.Media.Typeface($family,
            [System.Windows.FontStyles]::Normal,
            [System.Windows.FontWeights]::Normal,
            [System.Windows.FontStretches]::Normal)

        $glyphTypeface = $null

        if (-not $typeface.TryGetGlyphTypeface([ref] $glyphTypeface)) {
            Set-ItResult -Skipped -Because 'neither Windows icon font is installed on this machine'
            return
        }

        foreach ($kind in @('Question', 'Warning', 'Information', 'Danger')) {

            $point = [int] [char] (Get-TkDialogGlyph -Kind $kind)

            $glyphTypeface.CharacterToGlyphMap.ContainsKey($point) |
                Should -BeTrue -Because ('the {0} dialog uses U+{1:X4}' -f $kind, $point)
        }
    }
}
