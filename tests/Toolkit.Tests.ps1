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
