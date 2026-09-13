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

Describe 'Launch from the one liner' {

    <#
        irm | iex is how the toolkit is run: the downloaded text executes with
        no script file behind it and no argument. That launch left the
        elevation restart with nothing to replay, so "Restart as administrator"
        logged an error and did nothing, and the security audit, which needs
        elevation, could not be reached from it.
    #>

    BeforeAll {
        $script:LauncherEntryScript = $script:TkEntryScript
    }

    AfterAll {
        # Put the development launch back as it was for the tests that follow.
        $script:TkEntryScript = $script:LauncherEntryScript
        Start-Toolkit -NoGui | Out-Null
    }

    It 'replays the published build when there is no script file and no source' {

        $script:TkEntryScript = ''

        $ctx = Start-Toolkit -NoGui

        $ctx.SourceUri | Should -Be $script:TkDefaultSourceUri
    }

    It 'publishes over HTTPS, which is the only source an elevation restart accepts' {

        $script:TkDefaultSourceUri | Should -Match '^https://'
        $script:TkDefaultSourceUri | Should -Match '/dist/toolkit\.ps1$'
    }

    It 'keeps a source given explicitly' {

        $script:TkEntryScript = ''

        $ctx = Start-Toolkit -NoGui -SourceUri 'https://example.org/toolkit.ps1'

        $ctx.SourceUri | Should -Be 'https://example.org/toolkit.ps1'
    }

    It 'sets no source when a script file was run, because that file is re-run instead' {

        $script:TkEntryScript = $script:LauncherEntryScript

        $ctx = Start-Toolkit -NoGui

        $ctx.SourceUri | Should -BeNullOrEmpty
    }
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
        @{ Name = 'bug-checks' }
        @{ Name = 'bug-check-names' }
        @{ Name = 'device-problems' }
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
            foreach ($name in @(Get-TkPageName | ForEach-Object { 'Nav{0}' -f $_ })) {

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

    Context 'Text field placeholders' {

        It 'aligns the placeholder with the caret' {

            # The hint and the real text are siblings in the same grid, so two
            # independent insets drifted apart: a literal margin on one and a
            # template binding on the other. Bound to the same Padding they
            # cannot separate again, whatever a control sets.
            # Read from the markup rather than the built template: XamlWriter
            # serialises a template with its bindings already resolved, so the
            # very thing under test disappears from the output.
            $markup = Get-TkMainWindowXaml

            $start = $markup.IndexOf('<Style TargetType="TextBox">')
            $start | Should -BeGreaterThan 0

            $body = $markup.Substring($start, 3000)

            # The hint and the content host both take their inset from Padding.
            ([regex]::Matches($body, 'Margin="\{TemplateBinding Padding\}"')).Count |
                Should -BeGreaterOrEqual 2

            $body | Should -Not -Match 'Margin="9,6,9,6"'
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

Describe 'winget exit codes' {

    # This table was wrong by one row in three before it was checked against
    # winget itself, and the log then reported a refused installer hash as
    # "more than one package matched". The symbol names below are locale
    # independent, which is what makes comparing them safe on any machine.

    It 'gives <Code> a sentence' -TestCases @(
        @{ Code = -1978335231; Word = 'internal' }
        @{ Code = -1978335216; Word = 'installers' }
        @{ Code = -1978335215; Word = 'hash' }
        @{ Code = -1978335212; Word = 'found' }
        @{ Code = -1978335211; Word = 'sources' }
        @{ Code = -1978335210; Word = 'more than one' }
        @{ Code = -1978334971; Word = 'disk is full' }
        @{ Code = -1978334967; Word = 'restarted' }
    ) {
        param($Code, $Word)

        Get-TkWingetErrorText -ExitCode $Code | Should -BeLike ('*{0}*' -f $Word)
    }

    It 'returns nothing for a code it does not know' {

        # The caller then prints whatever winget actually wrote, which is
        # better than inventing a reason.
        Get-TkWingetErrorText -ExitCode 12345 | Should -BeNullOrEmpty
    }

    It 'agrees with winget about what each code means' {

        if (-not (Get-Command -Name 'winget' -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'winget is not installed on this machine'
            return
        }

        # Symbol names rather than messages: winget speaks the machine's
        # language, and this suite has to pass on any of them.
        $expected = @{
            -1978335216 = 'NO_APPLICABLE_INSTALLER'
            -1978335215 = 'INSTALLER_HASH_MISMATCH'
            -1978335212 = 'NO_APPLICATIONS_FOUND'
            -1978335210 = 'MULTIPLE_APPLICATIONS_FOUND'
        }

        foreach ($code in $expected.Keys) {

            $hex    = '0x{0:X8}' -f [uint32] ([int64] $code + 4294967296)
            $answer = (& winget error $hex 2>&1 | Out-String)

            $answer | Should -BeLike ('*{0}*' -f $expected[$code]) -Because (
                'the table claims {0} is "{1}"' -f $code, (Get-TkWingetErrorText -ExitCode $code)
            )
        }
    }
}

Describe 'Package source selection' {

    # The bug this guards against: the Store id pattern lived in a script
    # variable that was never seeded into the background runspace, so inside
    # it the pattern was $null. PowerShell reads "-cmatch $null" as a match
    # against the empty pattern, which matches every string, so every package
    # looked like a Store product and every install was pinned to msstore,
    # where none of them exist. Every install failed with "no package found"
    # in about half a second, for every application in the catalogue.

    It 'treats <PackageId> as a Store product: <Expected>' -TestCases @(
        @{ PackageId = '9NKSQGP7F2NH'; Expected = $true }
        @{ PackageId = 'XPDC2RH70K22MN'; Expected = $false }   # too long
        @{ PackageId = 'Mozilla.Firefox'; Expected = $false }
        @{ PackageId = 'TorProject.TorBrowser'; Expected = $false }
        @{ PackageId = 'ZAP.ZAP'; Expected = $false }
        @{ PackageId = '7zip.7zip'; Expected = $false }
        @{ PackageId = ''; Expected = $false }
    ) {
        param($PackageId, $Expected)

        Test-TkStoreProductId -PackageId $PackageId | Should -Be $Expected
    }

    It 'still rejects an identifier that could reach a command line' {

        # The same fragility applies to this guard, and matters more: a null
        # pattern would make "-notmatch" false for every string and wave
        # everything through while still looking present in the source.
        Test-TkPackageId -PackageId 'Google.Chrome; rm -rf /' | Should -BeFalse
        Test-TkPackageId -PackageId 'Google.Chrome && calc'   | Should -BeFalse
        Test-TkPackageId -PackageId 'Google Chrome'           | Should -BeFalse
        Test-TkPackageId -PackageId 'Google.Chrome'           | Should -BeTrue
    }
}

Describe 'Runspace state' {

    It 'seeds every feature script variable into the background runspaces' {

        # Feature code runs in a runspace. A script variable it reads that is
        # not on the shared list is $null there, silently, and the failure
        # shows up as wrong behaviour rather than an error. Anything defined
        # at file scope under src/Features therefore has to be declared.
        $root = Split-Path -Path $PSScriptRoot -Parent

        $threading = Get-Content -LiteralPath (Join-Path $root 'src\Core\Threading.ps1') -Raw
        $declared  = @([regex]::Matches($threading, "'(?<name>Tk[A-Za-z0-9]+)'") |
                       ForEach-Object { $_.Groups['name'].Value })

        $defined = @()

        foreach ($file in (Get-ChildItem -Path (Join-Path $root 'src\Features') -Filter '*.ps1' -Recurse)) {

            $text = Get-Content -LiteralPath $file.FullName -Raw

            foreach ($match in [regex]::Matches($text, '(?m)^\$script:(?<name>Tk[A-Za-z0-9]+)\s*=')) {
                $defined += $match.Groups['name'].Value
            }
        }

        foreach ($name in ($defined | Sort-Object -Unique)) {

            $declared | Should -Contain $name -Because (
                '$script:{0} is read inside a background runspace and would be $null there ' +
                'unless Initialize-TkRunspacePool seeds it' -f $name
            )
        }
    }
}

Describe 'Keyboard map' {

    BeforeAll {
        $script:Layouts = Get-TkKeyboardLayoutName
        $script:Map     = Get-TkKeyboardMap
    }

    It 'offers the four layouts, French first' {

        $script:Layouts.Count | Should -Be 4
        $script:Layouts[0]    | Should -BeLike 'FR*'
        ($script:Layouts -join ' ') | Should -BeLike '*QWERTZ*'
    }

    It 'draws three blocks rather than one stack of rows' {

        # The navigation cluster and the keypad sit beside the main block on a
        # real board. Stacking all three underneath each other is what made the
        # old board read as a heap of keys.
        $script:Map.Main.Count       | Should -BeGreaterThan 4
        $script:Map.Navigation.Count | Should -BeGreaterThan 1
        $script:Map.Numpad.Count     | Should -BeGreaterThan 1
    }

    It 'draws 105 keys for <Layout>' -TestCases @(
        @{ Layout = 'FR AZERTY (French)' }
        @{ Layout = 'US QWERTY (US/International)' }
        @{ Layout = 'GB QWERTY (United Kingdom)' }
        @{ Layout = 'DE QWERTZ (German)' }
    ) {
        param($Layout)

        # Every layout is the same ISO board with a different legend, so the
        # count and the geometry must not move between them.
        $keys = Get-TkKeyboardKey -Map (Get-TkKeyboardMap -Layout $Layout)

        @($keys).Count | Should -Be 105
    }

    It 'identifies every key uniquely by physical position, on <Layout>' -TestCases @(
        @{ Layout = 'FR AZERTY (French)' }
        @{ Layout = 'US QWERTY (US/International)' }
        @{ Layout = 'GB QWERTY (United Kingdom)' }
        @{ Layout = 'DE QWERTZ (German)' }
    ) {
        param($Layout)

        # The invariant the whole test rests on: pressing one physical key must
        # light exactly one block. The navigation cluster and the keypad share
        # scan codes and are told apart only by the extended flag, and Pause
        # shares one with Num Lock without either being extended.
        $keys = Get-TkKeyboardKey -Map (Get-TkKeyboardMap -Layout $Layout)
        $seen = @{}

        foreach ($key in $keys) {

            $seen.ContainsKey($key.Key) |
                Should -BeFalse -Because ('{0} is drawn twice' -f $key.Label)

            $seen[$key.Key] = $true
        }

        $seen.Count | Should -Be 105
    }

    It 'gives every key a width and a label' {

        foreach ($key in (Get-TkKeyboardKey -Map $script:Map)) {
            $key.Width | Should -BeGreaterThan 0
            $key.Label | Should -Not -BeNullOrEmpty
        }
    }

    It 'tells the keypad Enter from the main Enter' {

        # The one key the public WPF Key cannot distinguish: both report
        # Key.Return. Only the extended flag on the scan code separates them,
        # which is why the test reads the scan code WPF keeps on the event.
        $enters = @(Get-TkKeyboardKey -Map $script:Map | Where-Object { $_.ScanCode -eq 0x1C })

        $enters.Count | Should -Be 2
        @($enters | Where-Object { $_.Extended }).Count     | Should -Be 1
        @($enters | Where-Object { -not $_.Extended }).Count | Should -Be 1
    }

    It 'separates Pause from Num Lock by virtual key' {

        # Both are scan code 0x45 and neither is extended.
        $shared = @(Get-TkKeyboardKey -Map $script:Map | Where-Object { $_.ScanCode -eq 0x45 })

        $shared.Count | Should -Be 2
        @($shared | ForEach-Object { $_.VirtualKey }) | Should -Not -Contain 0
    }

    It 'keeps the ISO key and both hands of every modifier' {

        $keys = Get-TkKeyboardKey -Map $script:Map

        # The extra key beside the left Shift is what makes a board ISO rather
        # than ANSI, and it is missing from a 104 key layout.
        @($keys | Where-Object { $_.ScanCode -eq 0x56 }).Count | Should -Be 1

        foreach ($scanCode in @(0x1D, 0x38)) {   # Ctrl, Alt
            @($keys | Where-Object { $_.ScanCode -eq $scanCode }).Count | Should -Be 2
        }
    }

    It 'redraws the same geometry with a different legend' {

        # A layout change must move letters, not keys: same positions, same
        # widths, different labels.
        $french = Get-TkKeyboardKey -Map (Get-TkKeyboardMap -Layout 'FR AZERTY (French)')
        $german = Get-TkKeyboardKey -Map (Get-TkKeyboardMap -Layout 'DE QWERTZ (German)')

        @($french | ForEach-Object { $_.Key }) -join ',' |
            Should -Be (@($german | ForEach-Object { $_.Key }) -join ',')

        # The Y and Z positions swap between AZERTY and QWERTZ, so the legends
        # cannot be identical.
        @($french | ForEach-Object { $_.Label }) -join ',' |
            Should -Not -Be (@($german | ForEach-Object { $_.Label }) -join ',')
    }

    It 'names every key the way the key reader will' {

        # The contract that makes the whole test work: the identity the map
        # stores has to be the identity Resolve-TkKeyIdentity builds from a
        # key event, or every press would look like an unknown key.
        foreach ($key in (Get-TkKeyboardKey -Map $script:Map)) {

            $expected = if ($key.VirtualKey -gt 0) {
                            '{0}:{1}:{2}' -f $key.ScanCode, [int] $key.Extended, $key.VirtualKey
                        }
                        else {
                            '{0}:{1}' -f $key.ScanCode, [int] $key.Extended
                        }

            $key.Key | Should -Be $expected
        }
    }

    It 'says which keys cannot be observed' {

        # Ctrl+Alt+Delete is handled on a desktop no application can reach.
        # Saying so beats letting those keys look broken.
        $notes = Get-TkUntestableKeyNote

        $notes.Count | Should -BeGreaterThan 0
        ($notes -join ' ') | Should -BeLike '*Ctrl+Alt+Delete*'
    }
}

Describe 'Keyboard key events' {

    <#
        The keyboard test was dead twice. First it never started. Then it
        started and still lit nothing: it read keys from a window message hook,
        and WPF handles keyboard messages in its message pump, so a key marked
        handled there, as the test marks every key, never reaches the window
        procedure the hook listens on. Keys are now read from the WPF event.
    #>

    BeforeAll {

        $script:Markup = Get-TkMainWindowXaml

        $script:Known = @{}

        foreach ($key in (Get-TkKeyboardKey -Map (Get-TkKeyboardMap -Layout 'FR AZERTY (French)'))) {
            $script:Known[$key.Key] = $true
        }
    }

    It 'finds the scan code and the extended flag on the WPF key event' {

        # Both are internal to WPF. If a future version renamed them the test
        # would still run, but could no longer tell the two Enter keys apart.
        $flags = [System.Reflection.BindingFlags] 'Instance, Public, NonPublic'
        $type  = [System.Windows.Input.KeyEventArgs]

        $type.GetProperty('ScanCode', $flags).PropertyType      | Should -Be ([int])
        $type.GetProperty('IsExtendedKey', $flags).PropertyType | Should -Be ([bool])
    }

    It 'tells the keypad Enter from the main Enter' {

        $main   = Resolve-TkKeyIdentity -ScanCode 0x1C -Extended $false -VirtualKey 0x0D -Known $script:Known
        $keypad = Resolve-TkKeyIdentity -ScanCode 0x1C -Extended $true  -VirtualKey 0x0D -Known $script:Known

        $main   | Should -Not -Be $keypad
        $script:Known.ContainsKey($main)   | Should -BeTrue
        $script:Known.ContainsKey($keypad) | Should -BeTrue
    }

    It 'separates Pause from Num Lock, whether or not Num Lock arrives extended' {

        $pause   = Resolve-TkKeyIdentity -ScanCode 0x45 -Extended $false -VirtualKey 0x13 -Known $script:Known
        $numLock = Resolve-TkKeyIdentity -ScanCode 0x45 -Extended $false -VirtualKey 0x90 -Known $script:Known
        $numExt  = Resolve-TkKeyIdentity -ScanCode 0x45 -Extended $true  -VirtualKey 0x90 -Known $script:Known

        $pause   | Should -Not -Be $numLock
        $numExt  | Should -Be $numLock
        $script:Known.ContainsKey($pause)   | Should -BeTrue
        $script:Known.ContainsKey($numLock) | Should -BeTrue
    }

    It 'recovers the position of a key that reports no scan code' {

        # Injected keys and some remote sessions send the virtual key only.
        $identity = Resolve-TkKeyIdentity -ScanCode 0 -VirtualKey 0x20 -Known $script:Known

        $identity | Should -Be '57:0'
    }

    It 'gives no name to a key with no position at all' {

        Resolve-TkKeyIdentity -ScanCode 0 -VirtualKey 0 -Known $script:Known | Should -Be ''
    }

    It 'draws no start or stop button, because the test follows its panel' {

        $script:Markup | Should -Not -Match 'x:Name="BtnKeyboardStart"'
        $script:Markup | Should -Not -Match 'x:Name="BtnKeyboardStop"'
        $script:Markup | Should -Match 'x:Name="KeyboardLayout"'
    }
}

Describe 'Crash analysis' {

    It 'reads the stop code and its parameters from the untranslated event property' {

        # The property of the blue screen of 13 September 2026 on the machine
        # this was written on.
        $parsed = ConvertFrom-TkBugCheckText -Text '0x000000f7 (0xffffc18bfc43e460, 0x00005eafe2bb4f1b, 0xffffa1501d44b0e4, 0x0000000000000000)'

        $parsed.Code              | Should -Be 247
        $parsed.CodeHex           | Should -Be '0x000000F7'
        $parsed.Parameters.Count  | Should -Be 4
        $parsed.Parameters[0]     | Should -Be '0xffffc18bfc43e460'
    }

    It 'returns nothing for text that holds no stop code' {
        ConvertFrom-TkBugCheckText -Text 'The computer has rebooted.' | Should -BeNullOrEmpty
    }

    It 'prints a stop code on eight digits, even one PowerShell reads as negative' {
        Format-TkBugCheckCode -Code 0xC000021A | Should -Be '0xC000021A'
        Format-TkBugCheckCode -Code 10         | Should -Be '0x0000000A'
    }

    It 'names and explains a stop code a support call meets' {

        $info = Get-TkBugCheckInfo -Code 0xF7

        $info.Name          | Should -Be 'DRIVER_OVERRAN_STACK_BUFFER'
        $info.Kind          | Should -Be 'driver'
        $info.Meaning       | Should -Not -BeNullOrEmpty
        @($info.Steps).Count | Should -BeGreaterThan 0
    }

    It 'names a rare stop code without inventing advice for it' {

        $info = Get-TkBugCheckInfo -Code 0x1

        $info.Name    | Should -Be 'APC_INDEX_MISMATCH'
        $info.Meaning | Should -BeNullOrEmpty
    }

    It 'says so when a stop code is not in the published list' {
        (Get-TkBugCheckInfo -Code 0x7777).Name | Should -Match 'not in the published list'
    }

    It 'names every code it explains, and declares every family it cites' {

        $names   = (Import-TkCatalog -Name 'bug-check-names').names
        $details = Import-TkCatalog -Name 'bug-checks'
        $kinds   = @($details.kinds | ForEach-Object { $_.id })

        foreach ($entry in $details.codes) {
            $names.PSObject.Properties[$entry.code] | Should -Not -BeNullOrEmpty -Because $entry.code
            $kinds | Should -Contain $entry.kind -Because $entry.code
        }
    }

    It 'flags only the drivers registered before more than one blue screen' {

        $driver = { param($name) [pscustomobject] @{ Name = $name; ImagePath = "C:\$name.sys"; When = (Get-Date) } }

        $crashes = @(
            [pscustomobject] @{ Code = 0xF7;  Drivers = @((& $driver 'RTCore64'), (& $driver 'cpuz160'), (& $driver 'travis')) }
            [pscustomobject] @{ Code = 0x1AA; Drivers = @((& $driver 'RTCore64'), (& $driver 'RTCore64'), (& $driver 'cpuz160')) }
            [pscustomobject] @{ Code = 0;     Drivers = @((& $driver 'travis')) }
        )

        $recurring = @(Get-TkRecurringCrashDriver -Crash $crashes)

        @($recurring | ForEach-Object { $_.Name }) | Should -Be @('cpuz160', 'RTCore64')

        # Registered twice before one crash still counts as one crash.
        ($recurring | Where-Object { $_.Name -eq 'RTCore64' }).Crashes | Should -Be 2
    }

    It 'finds nothing recurring with a single blue screen' {

        $crashes = @([pscustomobject] @{ Code = 0xF7; Drivers = @([pscustomobject] @{ Name = 'RTCore64'; ImagePath = ''; When = (Get-Date) }) })

        @(Get-TkRecurringCrashDriver -Crash $crashes).Count | Should -Be 0
    }
}

Describe 'Device problems' {

    It 'explains every code Device Manager reports, from 1 to 54' {

        foreach ($code in 1..54) {

            $info = Get-TkDeviceProblemInfo -Code $code

            $info.Name     | Should -Match '^CM_PROB_' -Because $code
            $info.Severity | Should -BeIn @('Fail', 'Warning', 'Info') -Because $code
            $info.Action   | Should -Not -BeNullOrEmpty -Because $code
        }
    }

    It 'treats a device disabled on purpose as information, not a fault' {
        (Get-TkDeviceProblemInfo -Code 22).Severity | Should -Be 'Info'
    }

    It 'points a USB device that never identified itself at the connection' {

        # The device on the machine this was written on.
        $info = Get-TkDeviceProblemInfo -Code 43 -HardwareId 'USB\VID_0000&PID_0002\8&23E2028E&0&2'

        $info.Severity | Should -Be 'Fail'
        $info.Hint     | Should -Match 'never identified itself'
    }

    It 'gives no hint to a device that identified itself' {
        (Get-TkDeviceProblemInfo -Code 43 -HardwareId 'USB\VID_046D&PID_0A87\1').Hint | Should -BeNullOrEmpty
    }

    It 'keeps a code missing from the catalog visible' {

        $info = Get-TkDeviceProblemInfo -Code 99

        $info.Severity | Should -Be 'Warning'
        $info.Meaning  | Should -Match '99'
    }

    It 'opens Device Manager through the allow list, and nothing appended to it' {

        (Get-TkRemediationTable)['open-device-manager'].Kind | Should -Be 'Open'

        Test-TkRemediationTarget -Target 'devmgmt.msc'        | Should -BeTrue
        Test-TkRemediationTarget -Target 'devmgmt.msc & calc' | Should -BeFalse
    }
}

Describe 'Diagnostic reports' {

    BeforeAll {
        $script:Markup = Get-TkMainWindowXaml
    }

    It 'runs a report for every entry of the list, in the same order' {

        # The list used to be wired by position, so inserting an entry sent
        # every entry below it to the wrong report.
        $start  = $script:Markup.IndexOf('x:Name="DiagnosticChoices"')
        $end    = $script:Markup.IndexOf('</ListBox>', $start)
        $slice  = $script:Markup.Substring($start, $end - $start)
        $titles = @([regex]::Matches($slice, 'Text="(?<title>[^"]+)" Style="\{StaticResource ChoiceTitle\}"') |
                    ForEach-Object { $_.Groups['title'].Value })

        ($titles -join ',') | Should -Be ((@(Get-TkDiagnosticReport) | ForEach-Object { $_.Title }) -join ',')
    }

    It 'names functions that exist' {

        foreach ($report in (Get-TkDiagnosticReport)) {
            Get-Command -Name $report.Show -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because $report.Title
        }
    }
}

Describe 'Test tone' {

    It 'writes a valid RIFF WAVE header' {

        $stream = New-TkToneStream -Channel 'Both' -Seconds 1
        $bytes  = $stream.ToArray()
        $stream.Dispose()

        [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)  | Should -Be 'RIFF'
        [System.Text.Encoding]::ASCII.GetString($bytes, 8, 4)  | Should -Be 'WAVE'
        [System.Text.Encoding]::ASCII.GetString($bytes, 12, 4) | Should -Be 'fmt '

        # Stereo, sixteen bit, 44100.
        [System.BitConverter]::ToInt16($bytes, 22) | Should -Be 2
        [System.BitConverter]::ToInt32($bytes, 24) | Should -Be 44100
        [System.BitConverter]::ToInt16($bytes, 34) | Should -Be 16

        # The size in the header has to match what follows it, or the player
        # reads past the end and throws.
        [System.BitConverter]::ToInt32($bytes, 4) | Should -Be ($bytes.Length - 8)
    }

    It 'puts sound in the <Channel> channel only' -TestCases @(
        @{ Channel = 'Left';  Silent = 'Right' }
        @{ Channel = 'Right'; Silent = 'Left' }
    ) {
        param($Channel, $Silent)

        # The point of the sound test. A tone played on both channels cannot
        # tell a working speaker from a dead one.
        $stream = New-TkToneStream -Channel $Channel -Seconds 1
        $bytes  = $stream.ToArray()
        $stream.Dispose()

        $leftPeak  = 0
        $rightPeak = 0

        # 44 bytes of header, then interleaved sixteen bit pairs.
        for ($i = 44; $i -lt ($bytes.Length - 4); $i += 4) {

            $left  = [math]::Abs([System.BitConverter]::ToInt16($bytes, $i))
            $right = [math]::Abs([System.BitConverter]::ToInt16($bytes, $i + 2))

            if ($left  -gt $leftPeak)  { $leftPeak  = $left }
            if ($right -gt $rightPeak) { $rightPeak = $right }
        }

        if ($Silent -eq 'Right') {
            $rightPeak | Should -Be 0
            $leftPeak  | Should -BeGreaterThan 1000
        }
        else {
            $leftPeak  | Should -Be 0
            $rightPeak | Should -BeGreaterThan 1000
        }
    }

    It 'drives both channels when asked for both' {

        $stream = New-TkToneStream -Channel 'Both' -Seconds 1
        $bytes  = $stream.ToArray()
        $stream.Dispose()

        $leftPeak  = 0
        $rightPeak = 0

        for ($i = 44; $i -lt ($bytes.Length - 4); $i += 4) {

            $left  = [math]::Abs([System.BitConverter]::ToInt16($bytes, $i))
            $right = [math]::Abs([System.BitConverter]::ToInt16($bytes, $i + 2))

            if ($left  -gt $leftPeak)  { $leftPeak  = $left }
            if ($right -gt $rightPeak) { $rightPeak = $right }
        }

        $leftPeak  | Should -BeGreaterThan 1000
        $rightPeak | Should -BeGreaterThan 1000
    }
}

Describe 'WMI string decoding' {

    It 'turns a zero padded character array into text' {

        # WMI returns these as arrays of character codes with trailing zeros.
        $code = @(68, 69, 76, 76, 0, 0, 0)

        ConvertTo-TkWmiString -Code $code | Should -Be 'DELL'
    }

    It 'returns nothing for a missing value' {
        ConvertTo-TkWmiString -Code $null | Should -Be ''
    }
}

Describe 'Support bundle' {

    It 'renders a titled section from objects' {

        $text = ConvertTo-TkBundleText -Title 'Adapters' -As Table -InputObject @(
            [pscustomobject] @{ Name = 'Ethernet'; Status = 'Up' }
        )

        $text | Should -BeLike '*Adapters*'
        $text | Should -BeLike '*Ethernet*'
    }

    It 'says so rather than drawing an empty table for no data' {

        $text = ConvertTo-TkBundleText -Title 'Listening ports' -InputObject @()

        $text | Should -BeLike '*nothing to report*'
    }

    It 'keeps a failing collector from sinking the bundle' {

        # The rule the whole bundle rests on: one section that throws is
        # recorded and the rest still get written.
        $errors = New-Object 'System.Collections.Generic.List[string]'

        $text = Get-TkBundleSection -Title 'Network' -Errors $errors -Collector {
            throw 'the adapter service is down'
        }

        $errors.Count | Should -Be 1
        $errors[0]    | Should -BeLike '*adapter service is down*'
        $text         | Should -BeLike '*could not be collected*'
    }

    It 'returns the collector text when it succeeds, and records no error' {

        $errors = New-Object 'System.Collections.Generic.List[string]'

        $text = Get-TkBundleSection -Title 'System' -Errors $errors -Collector { 'a clean section' }

        $text          | Should -Be 'a clean section'
        $errors.Count  | Should -Be 0
    }

    It 'bounds the recent error events to the cap' {

        # A machine mid meltdown must not turn the bundle into a gigabyte of
        # event text.
        $events = Get-TkRecentErrorEvent -Days 3 -Maximum 25

        @($events).Count | Should -BeLessOrEqual 25
    }
}

Describe 'Security audit engine' {

    BeforeAll {
        # A finding reduced to what the score reads.
        $script:NewScoredFinding = {
            param([string] $Status, [int] $Weight)

            [pscustomobject] @{ Status = $Status; Weight = $Weight }
        }
    }

    Context 'Control table' {

        It 'names only controls that exist' {

            $controls = @(Get-TkAuditControl)

            $controls.Count | Should -BeGreaterThan 20

            foreach ($control in $controls) {
                Get-Command -Name $control.Function -ErrorAction SilentlyContinue |
                    Should -Not -BeNullOrEmpty -Because ('{0} is in the control table' -f $control.Function)
            }
        }

        It 'weights every control between 1 and 10 and gives it a known level' {

            foreach ($control in (Get-TkAuditControl)) {
                $control.Weight | Should -BeGreaterOrEqual 1
                $control.Weight | Should -BeLessOrEqual 10
                $control.Level  | Should -BeIn @('Essential', 'Full')
            }
        }

        It 'runs a strict subset at the Essential level' {

            $essential = @(Get-TkAuditControl -Level Essential)
            $full      = @(Get-TkAuditControl -Level Full)

            $essential.Count | Should -BeGreaterThan 0
            $essential.Count | Should -BeLessThan $full.Count

            foreach ($control in $essential) {
                $full.Function | Should -Contain $control.Function
            }
        }

        It 'files every control under one of the known categories' {

            # The report groups by category. A control that invents its own
            # splits one subject across two headings: the BitLocker key once sat
            # under "Recovery" while BitLocker itself sat under "Data protection".
            $known = @(
                'Data protection', 'Endpoint', 'Platform', 'Credentials',
                'Network', 'Remote access', 'Accounts', 'Servicing', 'Logging'
            )

            $used = @()

            foreach ($file in @('SecurityAudit.ps1', 'HardeningCheck.ps1')) {

                $path = Join-Path $script:RepositoryRoot ('src\Features\Security\{0}' -f $file)
                $text = Get-Content -LiteralPath $path -Raw

                # Anchored on the identifier, so only findings are read: the log
                # calls in the same files carry a -Category of their own.
                foreach ($match in [regex]::Matches($text, "-Id '[A-Z]+-\d+'[^\r\n]*?-Category '(?<name>[^']+)'")) {
                    $used += $match.Groups['name'].Value
                }
            }

            $used.Count | Should -BeGreaterThan 20

            foreach ($name in ($used | Sort-Object -Unique)) {
                $known | Should -Contain $name
            }
        }

        It 'refers only to remediations that are registered' {

            # A finding that names a correction the allow list does not have
            # would draw a button that does nothing.
            $table = Get-TkRemediationTable
            $named = @()

            foreach ($file in @('SecurityAudit.ps1', 'HardeningCheck.ps1')) {

                $path = Join-Path $script:RepositoryRoot ('src\Features\Security\{0}' -f $file)

                foreach ($line in (Get-Content -LiteralPath $path | Where-Object { $_ -match 'RemediationId' })) {

                    foreach ($match in [regex]::Matches($line, "'(?<id>[a-z0-9]+(?:-[a-z0-9]+)+)'")) {
                        $named += $match.Groups['id'].Value
                    }
                }
            }

            $named.Count | Should -BeGreaterThan 5

            foreach ($id in ($named | Sort-Object -Unique)) {
                $table.Keys | Should -Contain $id
            }
        }

        It 'backs every correction with what it needs: a function to fix, a vetted page to open' {

            $table = Get-TkRemediationTable

            foreach ($id in $table.Keys) {

                $entry = $table[$id]

                $entry.Kind | Should -BeIn @('Fix', 'Open') -Because $id

                if ($entry.Kind -eq 'Fix') {
                    Get-Command -Name $entry.Action -ErrorAction SilentlyContinue |
                        Should -Not -BeNullOrEmpty -Because ('{0} names {1}' -f $id, $entry.Action)
                }
                else {
                    Test-TkRemediationTarget -Target $entry.Target | Should -BeTrue -Because $id

                    if ($entry.ContainsKey('Fallback')) {
                        Test-TkRemediationTarget -Target $entry.Fallback | Should -BeTrue -Because $id
                    }
                }
            }
        }

        It 'gives every control an action for its warnings and failures' {

            # No warning is left without a way forward: a correction where one
            # safe step exists, the page where the setting lives otherwise.
            $table = Get-TkRemediationTable

            foreach ($control in (Get-TkAuditControl)) {
                $control.Action | Should -Not -BeNullOrEmpty -Because $control.Function
                $table.Keys     | Should -Contain $control.Action
            }
        }
    }

    Context 'Score' {

        It 'gives 100 when everything measured passes' {

            $score = Get-TkAuditScore -Finding @(
                (& $script:NewScoredFinding 'Pass' 10)
                (& $script:NewScoredFinding 'Pass' 3)
            )

            $score.Score  | Should -Be 100
            $score.Passed | Should -Be 2
        }

        It 'lets one heavy failure outweigh a light pass' {

            # A plain count would say 50. The unencrypted disk is the finding.
            $score = Get-TkAuditScore -Finding @(
                (& $script:NewScoredFinding 'Fail' 10)
                (& $script:NewScoredFinding 'Pass' 2)
            )

            $score.Score  | Should -Be 17
            $score.Failed | Should -Be 1
        }

        It 'counts a warning as half' {

            $score = Get-TkAuditScore -Finding @(
                (& $script:NewScoredFinding 'Pass'    10)
                (& $script:NewScoredFinding 'Warning' 10)
            )

            $score.Score    | Should -Be 75
            $score.Warnings | Should -Be 1
        }

        It 'leaves a control that could not be read out of the score' {

            $score = Get-TkAuditScore -Finding @(
                (& $script:NewScoredFinding 'Pass'        5)
                (& $script:NewScoredFinding 'NotAssessed' 10)
            )

            $score.Score       | Should -Be 100
            $score.NotAssessed | Should -Be 1
            $score.Assessed    | Should -Be 1
        }

        It 'lets an informational result cost nothing' {

            $score = Get-TkAuditScore -Finding @(
                (& $script:NewScoredFinding 'Pass' 5)
                (& $script:NewScoredFinding 'Info' 10)
            )

            $score.Score    | Should -Be 100
            $score.Assessed | Should -Be 1
        }

        It 'scores nothing measured as zero rather than failing' {

            (Get-TkAuditScore -Finding @()).Score | Should -Be 0
        }
    }

    Context 'Antivirus product state' {

        It 'reads a third party product that is running with current signatures' {

            # The value ESET Security reports on a protected machine.
            $state = ConvertFrom-TkProductState -State 266240

            $state.RealTimeEnabled   | Should -BeTrue
            $state.SignaturesCurrent | Should -BeTrue
        }

        It 'reads Defender standing aside as not running, which is not a fault' {

            $state = ConvertFrom-TkProductState -State 393472

            $state.RealTimeEnabled | Should -BeFalse
        }

        It 'reads out of date signatures' {

            (ConvertFrom-TkProductState -State 0x041010).SignaturesCurrent | Should -BeFalse
        }

        It 'answers unknown rather than guessing at a pattern it does not know' {

            (ConvertFrom-TkProductState -State 0x04FF00).RealTimeEnabled | Should -BeNullOrEmpty
        }
    }

    Context 'Local account policy' {

        It 'reads a French Windows by position, not by label' {

            # Accents dropped from the fixture: the parser never reads a label,
            # which is the point.
            $text = @'
Fermeture forcee de la session apres expiration ?:        Jamais
Duree de vie minimale du mot de passe (jours) :          0
Duree de vie maximale du mot de passe (jours) :          42
Longueur minimale du mot de passe :                      0
Nombre de mots de passe anterieurs a conserver :         Aucune
Seuil de verrouillage :                                  10
Duree du verrouillage (min) :                            10
Fenetre d'observation du verrouillage (min) :            10
Role de l'ordinateur :                                   STATION
La commande s'est terminee correctement.
'@

            $policy = ConvertFrom-TkNetAccountsOutput -Text $text

            $policy.MinimumPasswordLength | Should -Be 0
            $policy.LockoutThreshold      | Should -Be 10
        }

        It 'reads an English Windows, and a word on the threshold row as no threshold' {

            $text = @'
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              12
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
'@

            $policy = ConvertFrom-TkNetAccountsOutput -Text $text

            $policy.MinimumPasswordLength | Should -Be 12
            $policy.LockoutThreshold      | Should -Be 0
        }

        It 'returns nothing it could not read' {

            $policy = ConvertFrom-TkNetAccountsOutput -Text ''

            $policy.MinimumPasswordLength | Should -BeNullOrEmpty
            $policy.LockoutThreshold      | Should -BeNullOrEmpty
        }
    }

    Context 'Actions' {

        BeforeAll {
            $script:ExampleControl = [pscustomobject] @{
                Function = 'Test-Example'; Weight = 6; Level = 'Essential'; Action = 'open-windows-update'
            }
        }

        It 'gives a warning the action of its control when the check chose none' {

            $finding = New-TkAuditFinding -Id 'X-001' -Name 'Example' -Category 'Endpoint' -Status 'Warning' -Detail 'x'

            (Set-TkFindingControlDefault -Finding $finding -Control $script:ExampleControl).RemediationId |
                Should -Be 'open-windows-update'
        }

        It 'keeps the action a check chose for itself' {

            $finding = New-TkAuditFinding -Id 'X-001' -Name 'Example' -Category 'Endpoint' -Status 'Fail' `
                                          -Detail 'x' -RemediationId 'enable-rdp-nla'

            (Set-TkFindingControlDefault -Finding $finding -Control $script:ExampleControl).RemediationId |
                Should -Be 'enable-rdp-nla'
        }

        It 'puts no button on a pass, an informational result, or what could not be read' {

            foreach ($status in @('Pass', 'Info', 'NotAssessed')) {

                $finding = New-TkAuditFinding -Id 'X-001' -Name 'Example' -Category 'Endpoint' -Status $status -Detail 'x'

                (Set-TkFindingControlDefault -Finding $finding -Control $script:ExampleControl).RemediationId |
                    Should -BeNullOrEmpty -Because $status
            }
        }

        It 'takes the weight and the level from the table' {

            $finding = New-TkAuditFinding -Id 'X-001' -Name 'Example' -Category 'Endpoint' -Status 'Pass' `
                                          -Detail 'x' -Weight 1 -Level 'Full'

            $stamped = Set-TkFindingControlDefault -Finding $finding -Control $script:ExampleControl

            $stamped.Weight | Should -Be 6
            $stamped.Level  | Should -Be 'Essential'
        }

        It 'opens the pages it is meant to open' {

            foreach ($target in @(
                'ms-settings:windowsupdate'
                'windowsdefender://threat'
                'lusrmgr.msc'
                'control.exe /name Microsoft.BitLockerDriveEncryption'
                'https://learn.microsoft.com/windows-server/identity/laps/laps-overview'
            )) {
                Test-TkRemediationTarget -Target $target | Should -BeTrue -Because $target
            }
        }

        It 'refuses to open anything else' {

            foreach ($target in @(
                ''
                'cmd.exe'
                'powershell.exe -c calc'
                'ms-settings:windowsupdate & calc'
                'windowsdefender://threat;calc'
                'file:///C:/Windows/System32/calc.exe'
                'http://learn.microsoft.com/x'
                'https://learn.microsoft.com.evil.example/x'
                'LUSRMGR.MSC'
                'lusrmgr.msc /s'
                'control.exe /name Microsoft.Something'
            )) {
                Test-TkRemediationTarget -Target $target | Should -BeFalse -Because $target
            }
        }

        It 'refuses to run an entry that only opens a page' {

            Invoke-TkRemediation -Id 'open-windows-update' -Confirm:$false | Should -BeFalse
        }

        It 'offers Credential Guard only where the edition can run it' {

            foreach ($edition in @('Enterprise', 'EnterpriseS', 'Education', 'IoTEnterprise', 'ServerStandard')) {
                Test-TkCredentialGuardEdition -EditionId $edition | Should -BeTrue -Because $edition
            }

            foreach ($edition in @('Professional', 'ProfessionalEducation', 'Core', 'Unknown')) {
                Test-TkCredentialGuardEdition -EditionId $edition | Should -BeFalse -Because $edition
            }
        }
    }

    Context 'Drive encryption' {

        BeforeAll {
            # A volume shaped like Get-BitLockerVolume output. Enum values are
            # compared as strings by the control, so strings stand in for them.
            $script:NewVolume = {
                param(
                    [string]   $Mount,
                    [string]   $Type       = 'Data',
                    [string]   $Status     = 'FullyEncrypted',
                    [string]   $Protection = 'On',
                    [string]   $Method     = 'XtsAes128',
                    [string[]] $Protectors = @('Tpm', 'RecoveryPassword'),
                    [bool]     $AutoUnlock = $false
                )

                [pscustomobject] @{
                    MountPoint           = $Mount
                    VolumeType           = $Type
                    VolumeStatus         = $Status
                    ProtectionStatus     = $Protection
                    EncryptionMethod     = $Method
                    EncryptionPercentage = 100
                    AutoUnlockEnabled    = $AutoUnlock
                    KeyProtector         = @($Protectors | ForEach-Object {
                        [pscustomobject] @{
                            KeyProtectorType    = $_
                            AutoUnlockProtector = ($AutoUnlock -and $_ -eq 'ExternalKey')
                        }
                    })
                }
            }
        }

        It 'passes when every fixed drive is protected and recoverable' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Protectors @('TpmPin', 'RecoveryPassword'))
                (& $script:NewVolume -Mount 'D:' -Protectors @('ExternalKey', 'RecoveryPassword') -AutoUnlock $true)
            )

            $finding.Status   | Should -Be 'Pass'
            $finding.Measured | Should -Be '2 of 2 fixed drive(s) protected'
        }

        It 'fails on an unencrypted data drive even when the system drive is protected' {

            # The case the old control could not see: it only ever asked about C:.
            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem')
                (& $script:NewVolume -Mount 'D:' -Status 'FullyDecrypted' -Protection 'Off' -Method 'None' -Protectors @())
            )

            $finding.Status         | Should -Be 'Fail'
            $finding.Detail         | Should -Match 'D: \(data\): not encrypted'
            $finding.Recommendation | Should -Match 'D:'
        }

        It 'fails a system drive with no recovery password' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Protectors @('Tpm'))
            )

            $finding.Status | Should -Be 'Fail'
        }

        It 'warns when protection is suspended, and offers to resume it' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Protection 'Off')
            )

            $finding.Status        | Should -Be 'Warning'
            $finding.RemediationId | Should -Be 'resume-bitlocker'
        }

        It 'says how each drive unlocks' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Protectors @('TpmPin', 'RecoveryPassword'))
                (& $script:NewVolume -Mount 'D:' -Protectors @('ExternalKey', 'RecoveryPassword') -AutoUnlock $true)
            )

            $finding.Detail | Should -Match 'C: \(system\): protected, XTS-AES 128, TPM \+ PIN, recovery password present'
            $finding.Detail | Should -Match 'D: \(data\): protected, XTS-AES 128, automatic unlock, recovery password present'
        }

        It 'notes TPM alone on the system drive without marking it down' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Protectors @('Tpm', 'RecoveryPassword'))
            )

            $finding.Status | Should -Be 'Pass'
            $finding.Detail | Should -Match 'TPM and PIN'
        }

        It 'warns about the legacy AES-CBC ciphers' {

            $finding = ConvertTo-TkBitLockerFinding -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem' -Method 'Aes128')
            )

            $finding.Status | Should -Be 'Warning'
            $finding.Detail | Should -Match 'AES-CBC 128'
        }

        It 'skips volumes without a letter and never fails a removable drive' {

            $finding = ConvertTo-TkBitLockerFinding -RemovableMountPoint @('E:') -Volume @(
                (& $script:NewVolume -Mount 'C:' -Type 'OperatingSystem')
                (& $script:NewVolume -Mount '\\?\Volume{0a1b2c3d-0000-0000-0000-000000000000}\' -Status 'FullyDecrypted' -Protection 'Off' -Protectors @())
                (& $script:NewVolume -Mount 'E:' -Status 'FullyDecrypted' -Protection 'Off' -Protectors @())
            )

            $finding.Status | Should -Be 'Pass'
            $finding.Detail | Should -Match 'E: \(removable\): not encrypted'
            $finding.Detail | Should -Not -Match 'Volume\{'
        }
    }

    Context 'Audit policy' {

        It 'lists eight baseline subcategories, each by GUID' {

            $baseline = @(Get-TkAuditPolicyBaseline)

            $baseline.Count | Should -Be 8

            foreach ($item in $baseline) {
                $item.Guid | Should -Match '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$'
            }
        }

        It 'reads each setting by GUID, whatever language the names are in' {

            $text = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
PC,System,Ouvrir la session,{0CCE9215-69AE-11D9-BED3-505054503030},Succes et echec,,3
PC,System,Creation du processus,{0CCE922B-69AE-11D9-BED3-505054503030},Aucun audit,,0
PC,System,Verrouillage du compte,{0cce9217-69ae-11d9-bed3-505054503030},Succes,,1
,,Option:CrashOnAuditFail,,Disabled,,0
'@

            $settings = ConvertFrom-TkAuditPolicyBackup -Text $text

            $settings.Count | Should -Be 3
            $settings['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 3
            $settings['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 0
            $settings['{0CCE9217-69AE-11D9-BED3-505054503030}'] | Should -Be 1
        }

        It 'returns nothing from something that is not a backup' {

            (ConvertFrom-TkAuditPolicyBackup -Text 'not a backup').Count | Should -Be 0
        }
    }

    Context 'Administrator exclusions' {

        BeforeAll {
            $script:Admins = @(
                [pscustomobject] @{ Name = 'PC\Administrator';   ObjectClass = 'User';  Source = 'Local';           Sid = 'S-1-5-21-1-500' }
                [pscustomobject] @{ Name = 'CORP\Domain Admins'; ObjectClass = 'Group'; Source = 'ActiveDirectory'; Sid = 'S-1-5-21-2-512' }
                [pscustomobject] @{ Name = 'PC\tech';            ObjectClass = 'User';  Source = 'Local';           Sid = 'S-1-5-21-1-1001' }
            )
        }

        It 'leaves an excluded account out of the count' {

            $finding = Test-TkAuditLocalAdministrators -Member $script:Admins -ExcludedAccount @('CORP\Domain Admins')

            $finding.Measured | Should -Be '2 counted'
        }

        It 'names what was excluded, so the report cannot hide it' {

            $finding = Test-TkAuditLocalAdministrators -Member $script:Admins -ExcludedAccount @('CORP\Domain Admins')

            $finding.Detail | Should -Match 'Excluded by the operator'
            $finding.Detail | Should -Match 'Domain Admins'
        }

        It 'says nothing about exclusions when there are none' {

            $finding = Test-TkAuditLocalAdministrators -Member $script:Admins -ExcludedAccount @()

            $finding.Measured | Should -Be '3 counted'
            $finding.Detail   | Should -Not -Match 'Excluded'
        }

        It 'does not assess a group it could not read' {

            (Test-TkAuditLocalAdministrators -Member @() -ExcludedAccount @()).Status | Should -Be 'NotAssessed'
        }
    }
}

Describe 'Dashboard and pages' {

    BeforeAll {
        $script:Markup = Get-TkMainWindowXaml
    }

    Context 'Pages' {

        It 'gives every page a navigation button and a panel' {

            foreach ($page in (Get-TkPageName)) {
                $script:Markup | Should -Match ('x:Name="Nav{0}"' -f $page)
                $script:Markup | Should -Match ('x:Name="Page{0}"' -f $page)
            }
        }

        It 'has no page in the markup that the page list does not know' {

            # A panel added to the markup but not to the list can never be
            # shown; a button would do nothing.
            $known = @(Get-TkPageName)

            foreach ($match in [regex]::Matches($script:Markup, 'x:Name="(?:Nav|Page)(?<name>[A-Za-z]+)"')) {

                $name = $match.Groups['name'].Value

                if ($name -eq 'Host') {
                    continue
                }

                $known | Should -Contain $name
            }
        }

        It 'pairs every loading placeholder with its content and its text' {

            # A card that reads in the background shows a moving bar until its
            # answer lands. A placeholder without its content would spin for
            # ever; content without a placeholder would sit empty again.
            $names = @([regex]::Matches($script:Markup, 'x:Name="(?<name>\w+)Loading"') |
                       ForEach-Object { $_.Groups['name'].Value })

            $names.Count | Should -BeGreaterOrEqual 8

            foreach ($name in $names) {
                $script:Markup | Should -Match ('x:Name="{0}Content"' -f $name)
                $script:Markup | Should -Match ('x:Name="{0}LoadingText"' -f $name)
            }
        }

        It 'shows the quick actions on the Dashboard only' {

            $script:Markup | Should -Match 'x:Name="DashQuickActions"'
            $script:Markup | Should -Not -Match 'SystemQuickActions'
        }

        It 'draws a bar for every volume rather than a selector' {

            # A selector showed one drive at a time, and the drive filling up
            # was rarely the one selected.
            $script:Markup | Should -Match 'x:Name="SystemVolumeList"'
            $script:Markup | Should -Not -Match 'SystemVolumeChoice'
        }

        It 'still runs a first load registered after its page was already shown' {

            # At start up the theme showed the last page of the previous
            # session before that page had registered what to load. The page was
            # marked opened with nothing run, and the System page later opened
            # with every card reading for ever.
            $script:FirstLoadCount = 0

            Show-TkPage -Name 'Fixes'
            Register-TkFirstShow -PageName 'Fixes' -Action { $script:FirstLoadCount++ }

            Show-TkPage -Name 'Tweaks'
            Show-TkPage -Name 'Fixes'

            $script:FirstLoadCount | Should -Be 1

            Show-TkPage -Name 'Tweaks'
            Show-TkPage -Name 'Fixes'

            $script:FirstLoadCount | Should -Be 1
        }

        It 'lists the navigation in the order of the page list' {

            # The page list is the one declaration of what the navigation holds
            # and in which order; the markup has to agree with it.
            $order = @([regex]::Matches($script:Markup, 'x:Name="Nav(?<name>[A-Za-z]+)"') |
                       ForEach-Object { $_.Groups['name'].Value })

            ($order -join ',') | Should -Be (@(Get-TkPageName) -join ',')
        }

        It 'groups the navigation under the four kinds of work' {

            $headings = @([regex]::Matches($script:Markup, '<TextBlock Text="(?<text>[A-Z]+)" Style="\{StaticResource NavSection\}"') |
                          ForEach-Object { $_.Groups['text'].Value })

            ($headings -join ',') | Should -Be 'WORKSTATION,TROUBLESHOOTING,SECURITY,REFERENCE'
        }

        It 'opens on the Dashboard' {

            @(Get-TkPageName)[0] | Should -Be 'Dashboard'
        }
    }

    Context 'Quick actions' {

        It 'point at pages, tabs and functions that exist' {

            $actions = @(Get-TkQuickAction)
            $pages   = @(Get-TkPageName)

            $actions.Count | Should -BeGreaterThan 2

            foreach ($action in $actions) {

                if ($action.Page) {
                    $pages | Should -Contain $action.Page -Because $action.Id
                }

                if ($action.TabControl) {
                    # Other attributes such as Grid.Row may come before the name.
                    $script:Markup | Should -Match ('<TabControl[^>]*\sx:Name="{0}"' -f $action.TabControl) -Because $action.Id
                    $script:Markup | Should -Match ('<TabItem Header="{0}"' -f [regex]::Escape($action.Tab)) -Because $action.Id
                }

                Get-Command -Name $action.Start -ErrorAction SilentlyContinue |
                    Should -Not -BeNullOrEmpty -Because ('{0} starts {1}' -f $action.Id, $action.Start)
            }
        }

        It 'have unique identifiers' {

            $ids = @(Get-TkQuickAction | ForEach-Object { $_.Id })

            @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        }
    }

    Context 'Readings' {

        It 'judges free space with one set of thresholds' {

            (Get-TkFreeSpaceAssessment -FreePercent 4.9).Severity  | Should -Be 'Fail'
            (Get-TkFreeSpaceAssessment -FreePercent 5).Severity    | Should -Be 'Warning'
            (Get-TkFreeSpaceAssessment -FreePercent 11.9).Severity | Should -Be 'Warning'
            (Get-TkFreeSpaceAssessment -FreePercent 12).Severity   | Should -Be 'Pass'
        }

        It 'works out volume usage, and does not judge a volume with no size' {

            $usage = @(ConvertTo-TkVolumeUsage -LogicalDisk @(
                [pscustomobject] @{ DeviceID = 'C:'; VolumeName = 'System'; FileSystem = 'NTFS'; Size = 100GB; FreeSpace = 10GB }
                [pscustomobject] @{ DeviceID = 'F:'; VolumeName = '';       FileSystem = '';     Size = 0;     FreeSpace = 0 }
            ))

            $usage.Count          | Should -Be 2
            $usage[0].UsedPercent | Should -Be 90
            $usage[0].FreePercent | Should -Be 10
            $usage[0].Severity    | Should -Be 'Warning'
            $usage[1].UsedPercent | Should -Be 0
            $usage[1].Severity    | Should -Be 'Info'
        }

        It 'picks the adapter with a gateway over a VPN without one' {

            $vpn      = [pscustomobject] @{ Name = 'VPN';      IPv4Address = '10.8.0.2';     Gateway = 'None' }
            $ethernet = [pscustomobject] @{ Name = 'Ethernet'; IPv4Address = '192.168.1.20'; Gateway = '192.168.1.1' }

            (Select-TkPrimaryAdapter -Adapter @($vpn, $ethernet)).Name | Should -Be 'Ethernet'
        }

        It 'falls back to an adapter with an address, then to none' {

            $noAddress = [pscustomobject] @{ Name = 'Bluetooth'; IPv4Address = 'None';       Gateway = 'None' }
            $address   = [pscustomobject] @{ Name = 'Wi-Fi';     IPv4Address = '172.16.0.4'; Gateway = 'None' }

            (Select-TkPrimaryAdapter -Adapter @($noAddress, $address)).Name | Should -Be 'Wi-Fi'
            Select-TkPrimaryAdapter -Adapter @() | Should -BeNullOrEmpty
        }

        It 'unrolls a reader that returns its array with the comma operator' {

            # Get-TkBatteryState returns , @() on a desktop. Taken as one item,
            # that empty array was counted as a battery.
            @(Read-TkDashboardPart -Part 'Empty' -Reader { return , @() }).Count        | Should -Be 0
            @(Read-TkDashboardPart -Part 'Two'   -Reader { return , @('a', 'b') }).Count | Should -Be 2
        }

        It 'lists volumes with the system drive first, then by letter' {

            $ordered = @(Get-TkVolumeDisplayOrder -SystemDrive 'C:' -Volume @(
                [pscustomobject] @{ Drive = 'D:' }
                [pscustomobject] @{ Drive = 'H:' }
                [pscustomobject] @{ Drive = 'C:' }
                [pscustomobject] @{ Drive = 'A:' }
            ))

            (@($ordered | ForEach-Object { $_.Drive }) -join ',') | Should -Be 'C:,A:,D:,H:'
        }

        It 'loads the modules behind commands, and skips a command this machine lacks' {

            # Loaded together by several workers at launch, NetAdapter failed to
            # load and the network reader returned no adapter. Imports now go
            # one runspace at a time; a command that does not exist is not an
            # error, so a Server without Defender still reads its firewall.
            Import-TkCommandModule -Command @('Get-Date', 'Get-TkCommandThatDoesNotExist') | Should -BeTrue
            Get-Module -Name 'Microsoft.PowerShell.Utility' | Should -Not -BeNullOrEmpty
        }

        It 'reads disk health, media and bus whether they arrive as names or numbers' {

            # With the Storage module loaded properly the values arrive as names;
            # an integer cast of "Healthy" threw and failed the storage reading.
            ConvertFrom-TkDiskHealth -Value 0           | Should -Be 'Healthy'
            ConvertFrom-TkDiskHealth -Value 'Healthy'   | Should -Be 'Healthy'
            ConvertFrom-TkDiskHealth -Value 2           | Should -Be 'Unhealthy'
            ConvertFrom-TkDiskHealth -Value 'Unhealthy' | Should -Be 'Unhealthy'
            ConvertFrom-TkDiskHealth -Value $null       | Should -Be 'Unknown'

            ConvertFrom-TkMediaType -Code 4     | Should -Be 'SSD'
            ConvertFrom-TkMediaType -Code 'SSD' | Should -Be 'SSD'
            ConvertFrom-TkMediaType -Code $null | Should -Be 'Unspecified'

            ConvertFrom-TkBusType -Code 17     | Should -Be 'NVMe'
            ConvertFrom-TkBusType -Code 'NVMe' | Should -Be 'NVMe'
            ConvertFrom-TkBusType -Code 99     | Should -Be 'Unknown'
            ConvertFrom-TkBusType -Code $null  | Should -Be 'Unknown'
        }

        It 'judges patch age with the same thresholds as the audit' {

            Get-TkPatchAgeSeverity -Days 35 | Should -Be 'Pass'
            Get-TkPatchAgeSeverity -Days 36 | Should -Be 'Warning'
            Get-TkPatchAgeSeverity -Days 60 | Should -Be 'Warning'
            Get-TkPatchAgeSeverity -Days 61 | Should -Be 'Fail'
        }

        It 'takes the most recent dated hotfix and skips undated ones' {

            $last = Select-TkLastHotFix -HotFix @(
                [pscustomobject] @{ HotFixID = 'KB1'; InstalledOn = [datetime] '2026-08-01' }
                [pscustomobject] @{ HotFixID = 'KB2'; InstalledOn = $null }
                [pscustomobject] @{ HotFixID = 'KB3'; InstalledOn = [datetime] '2026-09-01' }
            )

            $last.HotFixID | Should -Be 'KB3'
        }
    }

    Context 'Network adapters' {

        BeforeAll {
            $script:Ethernet = [pscustomobject] @{ Name = 'Ethernet'; InterfaceIndex = 12; IPv4Address = '192.168.1.101'; Gateway = '192.168.1.254'; RouteMetric = 20;    Physical = $true }
            $script:WiFi     = [pscustomobject] @{ Name = 'Wi-Fi';    InterfaceIndex = 14; IPv4Address = '192.168.1.55';  Gateway = '192.168.1.254'; RouteMetric = 45;    Physical = $true }
            $script:VmNet1   = [pscustomobject] @{ Name = 'VMware Network Adapter VMnet1'; InterfaceIndex = 16; IPv4Address = '192.168.202.1'; Gateway = 'None'; RouteMetric = $null; Physical = $false }
            $script:VmNet8   = [pscustomobject] @{ Name = 'VMware Network Adapter VMnet8'; InterfaceIndex = 24; IPv4Address = '192.168.216.1'; Gateway = 'None'; RouteMetric = $null; Physical = $false }
        }

        It 'picks the link Windows routes through, by effective metric' {

            # Listed in the order Get-NetAdapter returned them on a real machine:
            # the virtual switches first, the wired link last.
            (Select-TkPrimaryAdapter -Adapter @($script:VmNet8, $script:VmNet1, $script:WiFi, $script:Ethernet)).Name |
                Should -Be 'Ethernet'
        }

        It 'follows a connected VPN, because that is where traffic goes' {

            $vpn = [pscustomobject] @{ Name = 'NordLynx'; InterfaceIndex = 12; IPv4Address = '10.5.0.2'; Gateway = '10.5.0.1'; RouteMetric = 5; Physical = $false }

            (Select-TkPrimaryAdapter -Adapter @($script:Ethernet, $vpn)).Name | Should -Be 'NordLynx'
        }

        It 'prefers a physical link to a virtual switch when nothing is routed' {

            $offline = [pscustomobject] @{ Name = 'Ethernet'; InterfaceIndex = 12; IPv4Address = '192.168.1.101'; Gateway = 'None'; RouteMetric = $null; Physical = $true }

            (Select-TkPrimaryAdapter -Adapter @($script:VmNet8, $offline)).Name | Should -Be 'Ethernet'
        }

        It 'uses only an address that is in use' {

            $picked = Select-TkUsableIPv4 -Address @(
                [pscustomobject] @{ IPAddress = '169.254.5.254'; AddressState = 'Preferred'; PrefixOrigin = 'WellKnown' }
                [pscustomobject] @{ IPAddress = '10.5.0.2';      AddressState = 'Tentative'; PrefixOrigin = 'Manual' }
                [pscustomobject] @{ IPAddress = '192.168.1.101'; AddressState = 'Preferred'; PrefixOrigin = 'Dhcp' }
            )

            $picked.IPAddress | Should -Be '192.168.1.101'

            # A tunnel that is down leaves only link local and tentative ones.
            Select-TkUsableIPv4 -Address @(
                [pscustomobject] @{ IPAddress = '169.254.219.111'; AddressState = 'Tentative'; PrefixOrigin = 'WellKnown' }
                [pscustomobject] @{ IPAddress = '10.100.0.2';      AddressState = 'Tentative'; PrefixOrigin = 'Manual' }
            ) | Should -BeNullOrEmpty
        }

        It 'builds an adapter record from the machine wide readings' {

            $record = ConvertTo-TkAdapterRecord `
                -Adapter ([pscustomobject] @{ Name = 'Ethernet'; InterfaceDescription = 'Intel Ethernet'; Status = 'Up'; MacAddress = 'A0-36-BC-CF-E8-4B'; LinkSpeed = '2.5 Gbps'; InterfaceIndex = 12; HardwareInterface = $true }) `
                -Address @(
                    [pscustomobject] @{ InterfaceIndex = 24; IPAddress = '192.168.216.1'; PrefixLength = 24; AddressState = 'Preferred'; PrefixOrigin = 'Dhcp' }
                    [pscustomobject] @{ InterfaceIndex = 12; IPAddress = '192.168.1.101'; PrefixLength = 24; AddressState = 'Preferred'; PrefixOrigin = 'Dhcp' }
                ) `
                -Route @([pscustomobject] @{ InterfaceIndex = 12; NextHop = '192.168.1.254'; RouteMetric = 0 }) `
                -Interface @([pscustomobject] @{ InterfaceIndex = 12; InterfaceMetric = 20; Dhcp = 'Enabled' }) `
                -DnsServer @([pscustomobject] @{ InterfaceIndex = 12; ServerAddresses = @('192.168.1.151', '192.168.1.254') })

            $record.IPv4Address | Should -Be '192.168.1.101'
            $record.SubnetMask  | Should -Be '255.255.255.0'
            $record.Gateway     | Should -Be '192.168.1.254'
            $record.RouteMetric | Should -Be 20
            $record.DnsServers  | Should -Be '192.168.1.151, 192.168.1.254'
            $record.Dhcp        | Should -Be 'Enabled'
            $record.Physical    | Should -BeTrue
        }

        It 'gives an adapter without a default route no gateway and no metric' {

            $record = ConvertTo-TkAdapterRecord `
                -Adapter ([pscustomobject] @{ Name = 'VMware Network Adapter VMnet8'; Status = 'Up'; InterfaceIndex = 24; HardwareInterface = $false }) `
                -Address @([pscustomobject] @{ InterfaceIndex = 24; IPAddress = '192.168.216.1'; PrefixLength = 24; AddressState = 'Preferred'; PrefixOrigin = 'Dhcp' }) `
                -Route @([pscustomobject] @{ InterfaceIndex = 12; NextHop = '192.168.1.254'; RouteMetric = 0 })

            $record.Gateway     | Should -Be 'None'
            $record.RouteMetric | Should -BeNullOrEmpty
            $record.Physical    | Should -BeFalse
        }

        It 'names the other connected links and only counts the virtual switches' {

            $line = Get-TkSecondaryAdapterSummary -Adapter @($script:Ethernet, $script:WiFi, $script:VmNet1, $script:VmNet8) `
                                                  -Primary $script:Ethernet

            $line | Should -Match 'Also connected: Wi-Fi 192\.168\.1\.55\.'
            $line | Should -Match '2 virtual adapter\(s\) up'
            $line | Should -Not -Match 'Ethernet'
        }

        It 'reads enumeration values whether they arrive as names or numbers' {

            $state = @{ 1 = 'Tentative'; 4 = 'Preferred' }

            ConvertFrom-TkCimEnum -Value 4           -Name $state | Should -Be 'Preferred'
            ConvertFrom-TkCimEnum -Value '4'         -Name $state | Should -Be 'Preferred'
            ConvertFrom-TkCimEnum -Value 'Preferred' -Name $state | Should -Be 'Preferred'
            ConvertFrom-TkCimEnum -Value 9           -Name $state | Should -Be '9'
            ConvertFrom-TkCimEnum -Value $null       -Name $state | Should -Be ''
        }

        It 'finds the address and the addressing when the cmdlets return raw numbers' {

            # What a background worker handed the Dashboard: states, origins and
            # DHCP as numbers. Compared with names they matched nothing, and the
            # card read "Not connected" with "1" under Addressing.
            $record = ConvertTo-TkAdapterRecord `
                -Adapter ([pscustomobject] @{ Name = 'Ethernet'; Status = 'Up'; InterfaceIndex = 12; HardwareInterface = $true }) `
                -Address @(
                    [pscustomobject] @{ InterfaceIndex = 12; IPAddress = '169.254.5.254'; PrefixLength = 16; AddressState = 4; PrefixOrigin = 2 }
                    [pscustomobject] @{ InterfaceIndex = 12; IPAddress = '10.5.0.2';      PrefixLength = 32; AddressState = 1; PrefixOrigin = 1 }
                    [pscustomobject] @{ InterfaceIndex = 12; IPAddress = '192.168.1.101'; PrefixLength = 24; AddressState = 4; PrefixOrigin = 3 }
                ) `
                -Route @([pscustomobject] @{ InterfaceIndex = 12; NextHop = '192.168.1.254'; RouteMetric = 0 }) `
                -Interface @([pscustomobject] @{ InterfaceIndex = 12; InterfaceMetric = 20; Dhcp = 1 })

            $record.IPv4Address | Should -Be '192.168.1.101'
            $record.Dhcp        | Should -Be 'Enabled'
            $record.RouteMetric | Should -Be 20
        }

        It 'says nothing when the primary link is the only one' {

            Get-TkSecondaryAdapterSummary -Adapter @($script:Ethernet) -Primary $script:Ethernet | Should -Be ''
        }
    }

    Context 'Dashboard writers' {

        It 'fills the network card with no adapter at all, instead of failing' {

            # An empty adapter list once became null on its way in and failed
            # the completion handler, leaving the card half written.
            { Write-TkDashboardNetwork -Part ([pscustomobject] @{ Adapter = $null; Adapters = @() }) } | Should -Not -Throw
            { Write-TkDashboardNetwork -Part $null } | Should -Not -Throw
        }
    }

    Context 'Busy state' {

        It 'stays busy until the last piece of work ends, and never goes below zero' {

            # Pages read in several parts at once; the first to finish must not
            # declare the window ready while the others are still reading.
            $before = Get-TkBusyCount

            Enter-TkBusy -Text 'first part'
            Enter-TkBusy -Text 'second part'
            Exit-TkBusy

            Get-TkBusyCount | Should -Be ($before + 1)

            Exit-TkBusy

            Get-TkBusyCount | Should -Be $before

            if ($before -eq 0) {
                Exit-TkBusy
                Get-TkBusyCount | Should -Be 0
            }
        }
    }

    Context 'Health tiles' {

        BeforeAll {
            $script:Snapshot = [pscustomobject] @{
                Reboot     = [pscustomobject] @{ Pending = $true; Reasons = @('Windows Update is waiting for a restart.'); Uptime = '3 days' }
                LastHotFix = [pscustomobject] @{ HotFixID = 'KB5099999'; InstalledOn = [datetime] '2026-08-01' }
                Volumes    = @(
                    [pscustomobject] @{ Drive = 'D:'; UsedPercent = 20;   Free = '800 GB'; Size = '1 TB';   Severity = 'Pass' }
                    [pscustomobject] @{ Drive = 'C:'; UsedPercent = 96.5; Free = '17 GB';  Size = '476 GB'; Severity = 'Fail' }
                )
                Disks      = @(
                    [pscustomobject] @{ Name = 'NVMe 1TB'; Severity = 'Pass'; Notes = '' }
                )
                Battery    = @()
                Devices    = @(
                    [pscustomobject] @{ Name = 'Unknown USB device'; Severity = 'Fail'; Code = 43 }
                    [pscustomobject] @{ Name = 'Serial port';        Severity = 'Info'; Code = 22 }
                )
                Crashes    = @(
                    [pscustomobject] @{ When = [datetime] '2026-09-01 08:00'; Code = 0;   Info = $null }
                    [pscustomobject] @{ When = [datetime] '2026-09-13 11:47'; Code = 247
                                        Info = [pscustomobject] @{ CodeHex = '0x000000F7'; Name = 'DRIVER_OVERRAN_STACK_BUFFER' } }
                )
            }

            $script:Tiles = @(ConvertTo-TkDashboardHealth -Snapshot $script:Snapshot `
                                                          -Now ([datetime] '2026-09-13') -SystemDrive 'C:')
        }

        It 'draws one tile per question' {

            $script:Tiles.Count | Should -Be 7
        }

        It 'counts the devices with a problem, not the ones disabled on purpose' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Devices' }

            $tile.Severity | Should -Be 'Fail'
            $tile.Value    | Should -Be '1 failing'
            $tile.Detail   | Should -Not -Match 'Serial port'
            $tile.Choice   | Should -Be 'Devices'
        }

        It 'counts blue screens and names the last one, leaving hard resets out' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Blue screens' }

            $tile.Severity | Should -Be 'Fail'
            $tile.Value    | Should -Be '1 in 30 days'
            $tile.Detail   | Should -Match 'DRIVER_OVERRAN_STACK_BUFFER'
            $tile.Choice   | Should -Be 'Crashes'
        }

        It 'says unknown rather than healthy when devices and crashes were not read' {

            $old = [pscustomobject] @{ Reboot = $null; LastHotFix = $null; Volumes = @(); Disks = @(); Battery = @() }

            foreach ($title in @('Devices', 'Blue screens')) {
                (@(ConvertTo-TkDashboardHealth -Snapshot $old) | Where-Object { $_.Title -eq $title }).Severity |
                    Should -Be 'NotAssessed' -Because $title
            }
        }

        It 'flags a pending restart and says why' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Restart' }

            $tile.Severity | Should -Be 'Warning'
            $tile.Detail   | Should -Match 'Windows Update'
        }

        It 'reports storage for the system drive, not the first drive listed' {

            $tile = $script:Tiles | Where-Object { $_.Title -like 'Storage*' }

            $tile.Title    | Should -Be 'Storage C:'
            $tile.Severity | Should -Be 'Fail'
            $tile.Percent  | Should -Be 96.5
            $tile.Page     | Should -Be 'System'
        }

        It 'measures patch age from the date it is given' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Updates' }

            $tile.Value    | Should -Be '43 days ago'
            $tile.Severity | Should -Be 'Warning'
        }

        It 'reports a machine with no battery without marking it down' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Battery' }

            $tile.Value    | Should -Be 'No battery'
            $tile.Severity | Should -Be 'Info'
        }

        It 'opens the tab a tile is about, in a tab control that has it' {

            foreach ($tile in @($script:Tiles | Where-Object { $_.TabControl })) {
                $script:Markup | Should -Match ('<TabControl Grid.Row="1" x:Name="{0}"|<TabControl x:Name="{0}"' -f $tile.TabControl) -Because $tile.Title
                $script:Markup | Should -Match ('<TabItem Header="{0}"' -f [regex]::Escape($tile.Tab)) -Because $tile.Title
            }

            $battery = $script:Tiles | Where-Object { $_.Title -eq 'Battery' }

            $battery.Page | Should -Be 'Diagnostics'
            $battery.Tab  | Should -Be 'Hardware tests'
        }

        It 'opens the entry a tile is about, in a list that has it' {

            # The page alone was not enough: the battery tile landed on the
            # Hardware page with the keyboard test selected.
            foreach ($tile in @($script:Tiles | Where-Object { $_.List })) {

                $start = $script:Markup.IndexOf(('x:Name="{0}"' -f $tile.List))
                $start | Should -BeGreaterThan 0 -Because $tile.Title

                $end   = $script:Markup.IndexOf('</ListBox>', $start)
                $slice = $script:Markup.Substring($start, $end - $start)

                $slice | Should -Match ('Text="{0}"' -f [regex]::Escape($tile.Choice)) -Because $tile.Title
            }

            $battery = $script:Tiles | Where-Object { $_.Title -eq 'Battery' }

            $battery.List   | Should -Be 'HardwareChoices'
            $battery.Choice | Should -Be 'Battery'
        }

        It 'starts the full diagnostic from an entry that exists' {

            $start = $script:Markup.IndexOf('x:Name="DiagnosticChoices"')
            $end   = $script:Markup.IndexOf('</ListBox>', $start)

            $script:Markup.Substring($start, $end - $start) | Should -Match 'Text="Full check"'
        }

        It 'names a page that exists on every tile' {

            foreach ($tile in $script:Tiles) {
                @(Get-TkPageName) | Should -Contain $tile.Page
            }
        }
    }
}
