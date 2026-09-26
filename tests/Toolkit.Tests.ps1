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

Describe 'Headless reports' {

    BeforeAll {
        # Journaled to a temporary folder, never to the account that runs the tests.
        $script:HeadlessDataRoot = (Get-TkContext).DataRoot
        (Get-TkContext).DataRoot = Join-Path $TestDrive 'data'
    }

    AfterAll {
        (Get-TkContext).DataRoot = $script:HeadlessDataRoot
        $script:TkQuietConsole   = $false
    }

    It 'lists each report once, with collectors whose commands exist' {

        $table = @(Get-TkHeadlessReport)

        $table.Count | Should -BeGreaterThan 10
        @($table | ForEach-Object { $_.Name } | Sort-Object -Unique).Count | Should -Be $table.Count

        foreach ($entry in $table) {

            $entry.Description | Should -Not -BeNullOrEmpty -Because $entry.Name

            $commands = @($entry.Collect.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                          ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -like '*-Tk*' })

            $commands.Count | Should -BeGreaterThan 0 -Because $entry.Name

            foreach ($command in $commands) {
                Get-Command -Name $command -ErrorAction SilentlyContinue |
                    Should -Not -BeNullOrEmpty -Because ('{0} calls {1}' -f $entry.Name, $command)
            }
        }

        # Only the audit reads what a standard user cannot see.
        (@($table | Where-Object { $_.Elevated } | ForEach-Object { $_.Name })) -join ',' | Should -Be 'Audit'
    }

    It 'expands All, splits a comma separated list in any case, and refuses an unknown name' {

        @(Resolve-TkHeadlessReportName -Name 'All').Count                     | Should -Be @(Get-TkHeadlessReport).Count
        (Resolve-TkHeadlessReportName -Name 'storage,Reboot') -join ','       | Should -Be 'Storage,Reboot'
        (Resolve-TkHeadlessReportName -Name @('Wifi', 'wifi', 'Proxy')) -join ',' | Should -Be 'Wifi,Proxy'

        { Resolve-TkHeadlessReportName -Name 'Nope' } | Should -Throw '*Available*'
    }

    It 'writes dates, time spans, enumerations and single row arrays the same way on 5.1 and 7' {

        $data = ConvertTo-TkPlainData -InputObject ([pscustomobject] @{
            When    = [datetime]::new(2026, 9, 14, 7, 30, 0)
            Uptime  = [timespan]::new(1, 2, 3, 4)
            Day     = [System.DayOfWeek]::Monday
            Id      = [guid] '835099d0-542e-48d4-bade-8b3bdec58d94'
            Rows    = @([pscustomobject] @{ Name = 'only row' })
            Table   = @{ Key = 'value' }
            Ratio   = [double]::NaN
            Rounded = [math]::Round(12.04, 1)
            Whole   = [math]::Round(42.3)
            Missing = $null
            Script  = { 'never run' }
        })

        $data.When      | Should -Be '2026-09-14T07:30:00.0000000'
        $data.Uptime    | Should -Be '1.02:03:04'
        $data.Day       | Should -Be 'Monday'
        $data.Id        | Should -Be '835099d0-542e-48d4-bade-8b3bdec58d94'
        $data.Table.Key | Should -Be 'value'
        $data.Ratio     | Should -BeNullOrEmpty
        $data.Script    | Should -BeNullOrEmpty

        # Whole numbers as integers, so neither version writes 12.0.
        $data.Rounded   | Should -BeOfType [long]
        $data.Whole     | Should -Be 42

        ($data.Rows -is [array]) | Should -BeTrue
        $data.Rows.Count         | Should -Be 1

        $json = ConvertTo-Json -InputObject $data -Depth 10

        $json | Should -Match '"Rows":\s*\['
        $json | Should -Match '"When":\s*"2026-09-14T07:30:00\.0000000"'
    }

    It 'names the worst judgement anywhere in a report' {

        $mixed = ConvertTo-TkPlainData -InputObject @(
            [pscustomobject] @{ Severity = 'Pass' }
            [pscustomobject] @{ Nested = @([pscustomobject] @{ Status = 'Warning' }, [pscustomobject] @{ Status = 'Fail' }) }
        )

        Get-TkWorstSeverity -Data $mixed | Should -Be 'Fail'

        Get-TkWorstSeverity -Data (ConvertTo-TkPlainData -InputObject @([pscustomobject] @{ Severity = 'Info' }, [pscustomobject] @{ Status = 'Pass' })) |
            Should -Be 'Pass'

        # A service state is not a judgement.
        Get-TkWorstSeverity -Data (ConvertTo-TkPlainData -InputObject ([pscustomobject] @{ Status = 'Running' })) | Should -Be ''
    }

    It 'skips a report that needs administrator rights, records one that fails, and keeps a single row as an array' {

        $needsAdmin = [pscustomobject] @{ Name = 'Needs admin'; Elevated = $true; Description = 'x'; Collect = { param($Options) $null = $Options; 'never' } }
        $skipped    = Invoke-TkHeadlessCollector -Entry $needsAdmin -Elevated $false

        $skipped.Status | Should -Be 'Skipped'
        $skipped.Reason | Should -BeLike '*administrator*'
        $skipped.Data   | Should -BeNullOrEmpty

        $broken = [pscustomobject] @{ Name = 'Broken'; Elevated = $false; Description = 'x'; Collect = { param($Options) $null = $Options; throw 'the provider is gone' } }
        $failed = Invoke-TkHeadlessCollector -Entry $broken

        $failed.Status | Should -Be 'Failed'
        $failed.Reason | Should -Be 'the provider is gone'

        $one = [pscustomobject] @{ Name = 'One row'; Elevated = $false; Description = 'x'; Collect = { param($Options) , @([pscustomobject] @{ Severity = 'Warning'; Level = $Options.AuditLevel }) } }
        $ok  = Invoke-TkHeadlessCollector -Entry $one -Options @{ AuditLevel = 'Full' }

        $ok.Status          | Should -Be 'Ok'
        $ok.Worst           | Should -Be 'Warning'
        ($ok.Data -is [array]) | Should -BeTrue
        $ok.Data[0].Level   | Should -Be 'Full'
    }

    It 'collects a real report into a JSON file without a byte order mark' {

        $path = Invoke-TkHeadlessReport -Report 'Reboot' -OutFile (Join-Path $TestDrive 'report.json')

        [System.IO.File]::ReadAllBytes($path)[0] | Should -Be 0x7B

        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json

        $document.Computer              | Should -Be $env:COMPUTERNAME
        $document.Reports.Reboot.Status | Should -Be 'Ok'
        $document.Reports.Reboot.Data   | Should -Not -BeNullOrEmpty
    }

    It 'lists the reports it knows, and which need administrator rights' {

        $list  = Invoke-TkHeadlessReport -Report 'List' | ConvertFrom-Json
        $items = @($list | ForEach-Object { $_ })

        $items.Count                                           | Should -Be @(Get-TkHeadlessReport).Count
        ($items | Where-Object { $_.Name -eq 'Audit' }).Elevated | Should -BeTrue
    }

    It 'takes the headless parameters at every entry point' {

        foreach ($name in @('Report', 'CompareWith', 'OutFile', 'AuditLevel')) {
            (Get-Command -Name 'Start-Toolkit').Parameters.Keys                                   | Should -Contain $name
            (Get-Command -Name (Join-Path $script:RepositoryRoot 'toolkit.ps1')).Parameters.Keys  | Should -Contain $name
        }

        # The compiled build is generated, so its entry point is read in the
        # template that writes it.
        $build = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'build\Build-Toolkit.ps1') -Raw

        $build | Should -Match '\[string\[\]\] `\$Report'
        $build | Should -Match '\[string\] `\$CompareWith'
        $build | Should -Match 'Start-Toolkit -Report `\$Report -CompareWith `\$CompareWith -OutFile `\$OutFile -AuditLevel `\$AuditLevel'
    }
}

Describe 'Portable build' {

    <#
        The portable edition is the same code laid out for an offline machine:
        a readable script with the catalogs and the interface left in plain
        files beside it, rather than one file full of base64. That shape leans
        on the disk fallbacks in the loaders, so the tests below assert both
        the build produces a de-blobbed script and the loaders find their data
        on disk when nothing is embedded.
    #>

    BeforeAll {
        $script:BuildScript    = Join-Path $script:RepositoryRoot 'build\Build-Toolkit.ps1'
        $script:PortableFolder = Join-Path $script:RepositoryRoot 'build\portable'

        $script:PortableScript = Join-Path $TestDrive 'Toolkit.ps1'
        & $script:BuildScript -NoEmbed -SkipAnalysis -OutputPath $script:PortableScript | Out-Null
        $script:PortableText = Get-Content -LiteralPath $script:PortableScript -Raw
    }

    It 'exposes a -NoEmbed switch on the build' {
        (Get-Command -Name $script:BuildScript).Parameters.Keys | Should -Contain 'NoEmbed'
    }

    It 'produces a script with no embedded catalog blob' {
        $script:PortableText | Should -Not -Match 'TkEmbeddedCatalogsRaw\s*=\s*@\{'
    }

    It 'leaves the embedded XAML empty so it is read from the file on disk' {
        $script:PortableText | Should -Match "TkEmbeddedXaml\s*=\s*''"
    }

    It 'still stamps the build metadata' {
        $script:PortableText | Should -Match "TkAppVersion\s*=\s*'"
    }

    It 'parses as valid PowerShell' {
        $errors = $null
        $tokens = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:PortableScript, [ref] $tokens, [ref] $errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'is materially smaller than the embedded build, because the blobs are gone' {
        $embedded = Join-Path $TestDrive 'toolkit-embedded.ps1'
        & $script:BuildScript -SkipAnalysis -OutputPath $embedded | Out-Null

        (Get-Item $script:PortableScript).Length | Should -BeLessThan (Get-Item $embedded).Length
    }

    It 'reads a catalog from a data folder in the working directory when none is embedded' {

        $dataDir = Join-Path $TestDrive 'work\data'
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dataDir 'portable-sample.json') -Value '{}' -Encoding UTF8

        Push-Location (Split-Path $dataDir -Parent)

        try {
            $found = Get-TkCatalogPath -Name 'portable-sample'
        }
        finally {
            Pop-Location
        }

        $found                       | Should -Not -BeNullOrEmpty
        (Split-Path $found -Leaf)    | Should -Be 'portable-sample.json'
    }

    It 'falls back to the interface file on disk when no XAML is embedded' {
        $script:TkEmbeddedXaml | Should -BeNullOrEmpty
        Get-TkMainWindowXaml   | Should -Match '<Window'
    }

    It 'ships a launcher and a readme template' {
        Test-Path (Join-Path $script:PortableFolder 'Start-Toolkit.cmd') | Should -BeTrue
        Test-Path (Join-Path $script:PortableFolder 'README.txt')        | Should -BeTrue
    }

    It 'launches with the apartment and policy the interface needs, and nothing more' {
        $launcher = Get-Content -LiteralPath (Join-Path $script:PortableFolder 'Start-Toolkit.cmd') -Raw
        $launcher | Should -Match '-Sta'
        $launcher | Should -Match '-ExecutionPolicy Bypass'
    }

    It 'fills the readme version tokens at package time' {
        $readme = Get-Content -LiteralPath (Join-Path $script:PortableFolder 'README.txt') -Raw
        $readme | Should -Match '\{\{VERSION\}\}'
        $readme | Should -Match '\{\{COMMIT\}\}'
    }

    It 'keeps the packaging and signing scripts parseable' {

        foreach ($name in @('New-PortablePackage.ps1', 'Sign-Toolkit.ps1', 'New-CodeSigningCertificate.ps1')) {

            $path   = Join-Path $script:RepositoryRoot ('build\{0}' -f $name)
            $errors = $null
            $tokens = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $errors) | Out-Null

            $errors | Should -BeNullOrEmpty -Because ('{0} must parse' -f $name)
        }
    }

    It 'signs by thumbprint or by pfx, and timestamps' {

        $sign = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'build\Sign-Toolkit.ps1') -Raw
        $parameters = (Get-Command -Name (Join-Path $script:RepositoryRoot 'build\Sign-Toolkit.ps1')).Parameters

        $parameters.Keys | Should -Contain 'Thumbprint'
        $parameters.Keys | Should -Contain 'PfxPath'
        $parameters.Keys | Should -Contain 'TimestampServer'
        $sign            | Should -Match 'Set-AuthenticodeSignature'
    }
}

Describe 'Report comparison' {

    BeforeAll {
        # Written to a temporary folder, never to the account that runs the tests.
        $script:ComparisonDataRoot = (Get-TkContext).DataRoot
        (Get-TkContext).DataRoot = Join-Path $TestDrive 'data'

        # A report document reduced to what the comparison reads.
        function New-ComparisonTestDocument {
            param([string] $Computer = 'PC-01', [hashtable] $Data = @{}, [hashtable] $Status = @{})

            $reports = [ordered] @{}

            foreach ($name in $Data.Keys) {

                $plain = ConvertTo-TkPlainData -InputObject $Data[$name]

                $reports[$name] = [ordered] @{
                    Status     = $(if ($Status.ContainsKey($name)) { $Status[$name] } else { 'Ok' })
                    Reason     = ''
                    DurationMs = 1
                    Worst      = (Get-TkWorstSeverity -Data $plain)
                    Data       = $plain
                }
            }

            [ordered] @{ Computer = $Computer; GeneratedAt = '2026-09-14T08:00:00.0000000'; Reports = $reports }
        }
    }

    AfterAll {
        (Get-TkContext).DataRoot = $script:ComparisonDataRoot
        $script:TkQuietConsole   = $false
    }

    It 'follows a drive that got worse, a device problem that went away, and one that appeared' {

        $before = New-ComparisonTestDocument -Data @{
            Storage = @([pscustomobject] @{ Kind = 'Disk'; Name = 'Samsung SSD'; Severity = 'Pass'; Health = 'Healthy' })
            Devices = @([pscustomobject] @{ DeviceId = 'USB\VID_0000&PID_0002'; Name = 'Unknown USB device'; Code = 43; Severity = 'Fail' })
        }

        $after = New-ComparisonTestDocument -Data @{
            Storage = @([pscustomobject] @{ Kind = 'Disk'; Name = 'Samsung SSD'; Severity = 'Warning'; Health = 'Warning' })
            Devices = @([pscustomobject] @{ DeviceId = 'PCI\VEN_8086&DEV_2725'; Name = 'Wi-Fi adapter'; Code = 10; Severity = 'Warning' })
        }

        $comparison = Compare-TkReportDocument -Reference $before -Difference $after

        $disk = $comparison.Changes | Where-Object { $_.Change -eq 'Judgement' }

        $disk.Item      | Should -Be 'Disk - Samsung SSD'
        $disk.Direction | Should -Be 'Worse'
        $disk.Before    | Should -Be 'Pass'
        $disk.After     | Should -Be 'Warning'

        ($comparison.Changes | Where-Object { $_.Change -eq 'Gone' }).Direction   | Should -Be 'Better'
        ($comparison.Changes | Where-Object { $_.Change -eq 'Appeared' }).Item    | Should -Be 'Wi-Fi adapter'

        $comparison.Counts.Worse  | Should -Be 2
        $comparison.Counts.Better | Should -Be 1

        ($comparison.Reports | Where-Object { $_.Report -eq 'Storage' }).Direction | Should -Be 'Worse'
    }

    It 'matches a finding whose heading carries a measurement' {

        $before = New-ComparisonTestDocument -Data @{ Wifi = [pscustomobject] @{ Findings = @([pscustomobject] @{ Heading = 'Signal -55 dBm on "Office"'; Severity = 'Pass' }) } }
        $after  = New-ComparisonTestDocument -Data @{ Wifi = [pscustomobject] @{ Findings = @([pscustomobject] @{ Heading = 'Signal -83 dBm on "Office"'; Severity = 'Fail' }) } }

        $changes = @((Compare-TkReportDocument -Reference $before -Difference $after).Changes)

        $changes.Count        | Should -Be 1
        $changes[0].Change    | Should -Be 'Judgement'
        $changes[0].Direction | Should -Be 'Worse'
        $changes[0].Item      | Should -Be 'Signal -83 dBm on "Office"'
    }

    It 'counts the crashes that are new, not the ones that aged out of the period' {

        $old = [pscustomobject] @{ When = '2026-08-01T10:00:00'; Kind = 'Blue screen'; Code = 247; Severity = 'Fail'; Info = [pscustomobject] @{ Name = 'DRIVER_OVERRAN_STACK_BUFFER' } }
        $new = [pscustomobject] @{ When = '2026-09-13T21:00:00'; Kind = 'Blue screen'; Code = 426; Severity = 'Fail'; Info = [pscustomobject] @{ Name = 'WIN32K_POWER_WATCHDOG_TIMEOUT' } }

        $before = New-ComparisonTestDocument -Data @{ Crashes = [pscustomobject] @{ Crashes = @($old); Stability = @() } }
        $after  = New-ComparisonTestDocument -Data @{ Crashes = [pscustomobject] @{ Crashes = @($new); Stability = @() } }

        $changes = @((Compare-TkReportDocument -Reference $before -Difference $after).Changes)

        $changes.Count        | Should -Be 1
        $changes[0].Change    | Should -Be 'New'
        $changes[0].Direction | Should -Be 'Worse'
        $changes[0].Item      | Should -Be 'Blue screen - WIN32K_POWER_WATCHDOG_TIMEOUT'
    }

    It 'follows the audit by control, names a changed measurement, and reads the score as a fact' {

        $before = New-ComparisonTestDocument -Data @{ Audit = [pscustomobject] @{
            Score    = [pscustomobject] @{ Score = 72 }
            Findings = @(
                [pscustomobject] @{ Id = 'AV-003'; Name = 'Antivirus exclusions'; Status = 'Fail'; Measured = '2 of 3 too broad' }
                [pscustomobject] @{ Id = 'UPD-002'; Name = 'Windows Update pause'; Status = 'Pass'; Measured = 'Not paused' }
            )
        } }

        $after = New-ComparisonTestDocument -Data @{ Audit = [pscustomobject] @{
            Score    = [pscustomobject] @{ Score = 88 }
            Findings = @(
                [pscustomobject] @{ Id = 'AV-003'; Name = 'Antivirus exclusions'; Status = 'Pass'; Measured = 'None' }
                [pscustomobject] @{ Id = 'UPD-002'; Name = 'Windows Update pause'; Status = 'Pass'; Measured = 'Pause expired' }
            )
        } }

        $comparison = Compare-TkReportDocument -Reference $before -Difference $after

        $fixed = $comparison.Changes | Where-Object { $_.Change -eq 'Judgement' }
        $fixed.Item      | Should -Be 'AV-003 - Antivirus exclusions'
        $fixed.Direction | Should -Be 'Better'

        ($comparison.Changes | Where-Object { $_.Change -eq 'Value' }).After | Should -Be 'Measured: Pause expired'

        $score = $comparison.Facts | Where-Object { $_.Fact -eq 'Audit score' }
        $score.Before | Should -Be '72'
        $score.After  | Should -Be '88'
    }

    It 'reads facts from the inventory, or from the dashboard when the inventory was not collected' {

        $before = New-ComparisonTestDocument -Data @{ Dashboard = [pscustomobject] @{
            OS       = [pscustomobject] @{ Build = '26100.4061'; DisplayVersion = '24H2' }
            Identity = [pscustomobject] @{ BiosVersion = '0502' }
        } }

        $after = New-ComparisonTestDocument -Data @{ Inventory = [pscustomobject] @{
            System   = [pscustomobject] @{ Build = '26200.9445'; DisplayVersion = '25H2' }
            Identity = [pscustomobject] @{ BiosVersion = '0801' }
        } }

        $facts = @((Compare-TkReportDocument -Reference $before -Difference $after).Facts)

        ($facts | Where-Object { $_.Fact -eq 'Windows build' }).After  | Should -Be '26200.9445'
        ($facts | Where-Object { $_.Fact -eq 'BIOS version' }).Before  | Should -Be '0502'
        ($facts | Where-Object { $_.Fact -eq 'Memory' })               | Should -BeNullOrEmpty
    }

    It 'leaves out a report skipped on one side, and says when the documents come from two computers' {

        $before = New-ComparisonTestDocument -Data @{ Audit = [pscustomobject] @{ Findings = @([pscustomobject] @{ Id = 'AV-003'; Name = 'x'; Status = 'Fail' }) } }
        $after  = New-ComparisonTestDocument -Computer 'PC-02' -Data @{ Audit = $null } -Status @{ Audit = 'Skipped' }

        $comparison = Compare-TkReportDocument -Reference $before -Difference $after

        $comparison.SameComputer | Should -BeFalse

        $audit = $comparison.Reports | Where-Object { $_.Report -eq 'Audit' }
        $audit.Compared | Should -BeFalse
        $audit.After    | Should -Be 'Skipped'

        @($comparison.Changes).Count | Should -Be 0
    }

    It 'names only reports the headless run knows, in its rules, its facts and its snapshot' {

        $known = @(Get-TkHeadlessReport | ForEach-Object { $_.Name })

        foreach ($rule in (Get-TkComparisonRule)) {
            $known     | Should -Contain $rule.Report
            $rule.Mode | Should -BeIn @('State', 'Event')
        }

        foreach ($fact in (Get-TkComparisonFact)) {
            foreach ($path in $fact.Path) {
                $known | Should -Contain ($path -split '\.')[0]
            }
        }

        foreach ($name in (Get-TkSnapshotReportName)) {
            $known | Should -Contain $name
        }
    }

    It 'collects the reports of a saved document again and compares them' {

        $path = Invoke-TkHeadlessReport -Report 'Reboot' -OutFile (Join-Path $TestDrive 'before.json')

        $document = Read-TkReportDocument -Json (Invoke-TkHeadlessReport -CompareWith $path)

        (@($document.Reports.Keys)) -join ',' | Should -Be 'Reboot'
        $document.Comparison.SameComputer     | Should -BeTrue

        ($document.Comparison.Reports | Where-Object { $_.Report -eq 'Reboot' }).Compared | Should -BeTrue
    }

    It 'refuses a file that is not a report' {

        $path = Join-Path $TestDrive 'other.json'
        Set-Content -LiteralPath $path -Value '{ "name": "not a report" }'

        { Read-TkReportDocument -Path $path }                                  | Should -Throw '*not a toolkit report*'
        { Read-TkReportDocument -Path (Join-Path $TestDrive 'missing.json') }  | Should -Throw '*does not exist*'
        { Invoke-TkHeadlessReport }                                             | Should -Throw '*-Report*'
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
        @{ Name = 'windows-errors' }
        @{ Name = 'windows-events' }
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

            $values       = ConvertTo-TkArray $tweak.registry
            $keys         = ConvertTo-TkArray $tweak.registryKeys
            $services     = ConvertTo-TkArray $tweak.services
            $features     = ConvertTo-TkArray $tweak.optionalFeatures
            $capabilities = ConvertTo-TkArray $tweak.capabilities
            $audits       = ConvertTo-TkArray $tweak.auditPolicy

            ($values.Count + $keys.Count + $services.Count + $features.Count + $capabilities.Count + $audits.Count) |
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

Describe 'Windows reference' {

    It 'reads <Text> as <Hex>' -TestCases @(
        @{ Text = '0x80070005';   Hex = '0x80070005'; Win32 = 5 }
        @{ Text = '80070005';     Hex = '0x80070005'; Win32 = 5 }
        @{ Text = '-2147024891';  Hex = '0x80070005'; Win32 = 5 }
        @{ Text = '2147942405';   Hex = '0x80070005'; Win32 = 5 }
        @{ Text = '5';            Hex = '0x80070005'; Win32 = 5 }
        @{ Text = '0xc000006a';   Hex = '0xC000006A'; Win32 = $null }
        @{ Text = 'C1900101';     Hex = '0xC1900101'; Win32 = $null }
        @{ Text = ' 0x800F081F '; Hex = '0x800F081F'; Win32 = $null }
    ) {
        param($Text, $Hex, $Win32)

        $code = ConvertTo-TkErrorCode -Text $Text

        $code.Hex   | Should -Be $Hex
        $code.Win32 | Should -Be $Win32
    }

    It 'refuses what is not a code' {

        ConvertTo-TkErrorCode -Text 'proxy'       | Should -BeNullOrEmpty
        ConvertTo-TkErrorCode -Text ''            | Should -BeNullOrEmpty
        ConvertTo-TkErrorCode -Text '99999999999' | Should -BeNullOrEmpty
    }

    It 'splits an HRESULT and an NTSTATUS into their parts' {

        $update = Get-TkErrorCodePart -Value ([Convert]::ToUInt32('8024402C', 16))

        $update.Kind         | Should -Be 'HRESULT error'
        $update.Facility     | Should -Be 36
        $update.FacilityName | Should -Be 'Windows Update'
        $update.Code         | Should -Be 0x402C

        $setup = Get-TkErrorCodePart -Value ([Convert]::ToUInt32('C1900101', 16))

        $setup.Kind     | Should -Be 'NTSTATUS'
        $setup.Facility | Should -Be 0x190
    }

    It 'explains a code from the catalog, with the steps of its family' {

        $info = Get-TkErrorCodeInfo -Code '0x800F081F'

        $info.Known     | Should -BeTrue
        $info.Name      | Should -Be 'CBS_E_SOURCE_MISSING'
        $info.GroupName | Should -Be 'The component store is damaged'
        $info.Steps[0]  | Should -BeLike '*RestoreHealth*'
        $info.Action    | Should -BeLike '*/Source*'
    }

    It 'decodes a Win32 code the catalog does not hold, without inventing a name' {

        $info = Get-TkErrorCodeInfo -Code 1223

        $info.Known         | Should -BeFalse
        $info.Name          | Should -Be ''
        $info.Hex           | Should -Be '0x800704C7'
        $info.Win32         | Should -Be 1223
        $info.FacilityName  | Should -Be 'Win32'
        $info.SystemMessage | Should -Not -BeNullOrEmpty
    }

    It 'summarizes a failed update the way the update history returns its code' {

        Get-TkErrorCodeSummary -Code (-2145124322) | Should -BeLike 'WU_E_SERVICE_STOP: *'
        Get-TkErrorCodeSummary -Code 'not a code'  | Should -Be ''
    }

    It 'reads the reason of a failed sign-in from its sub status, or its status when there is none' {

        Get-TkLogonFailureCode -Status ([uint32] 3221225581) -SubStatus ([uint32] 3221225578) | Should -Be '0xC000006A'
        Get-TkLogonFailureCode -Status ([uint32] 3221226036) -SubStatus ([uint32] 0)          | Should -Be '0xC0000234'
        Get-TkLogonFailureCode -Status 0 -SubStatus 0                                          | Should -Be ''
    }

    It 'finds an event by its ID, and tells one ID from two sources apart' {

        @(Get-TkEventReference -Id 41)[0].source                                       | Should -Be 'Kernel-Power'
        @(Get-TkEventReference -Id 1001).Count                                          | Should -BeGreaterOrEqual 2
        (Get-TkEventReference -Id 1001 -Source 'BugCheck').severity                     | Should -Be 'Fail'
        (Get-TkEventReference -Id 1001 -Source 'Microsoft-Windows-WER-SystemErrorReporting').source | Should -Be 'BugCheck'
        (Get-TkEventReference -Id 129 -Source 'stornvme').name                          | Should -BeLike '*reset*'
    }

    It 'searches by code, by event ID and by words' {

        (Find-TkWindowsReference -Query '0x80070005')[0].Title | Should -Be '0x80070005  E_ACCESSDENIED'

        # A short number is read as an event ID first, then as a Win32 code.
        $byNumber = @(Find-TkWindowsReference -Query '41')

        $byNumber[0].Kind         | Should -Be 'Event'
        $byNumber[0].Entry.source | Should -Be 'Kernel-Power'
        $byNumber[-1].Kind        | Should -Be 'Error code'

        # A system message that is only a template with inserts says nothing.
        (Get-TkErrorCodeInfo -Code 4625).SystemMessage | Should -Not -Match '%\d'

        @(Find-TkWindowsReference -Query 'kernel-power restarted' | Where-Object { $_.Kind -eq 'Event' }).Count | Should -BeGreaterThan 0

        $lockout = @(Find-TkWindowsReference -Query 'locked out')

        @($lockout | Where-Object { $_.Key -eq '0xC0000234' }).Count | Should -Be 1
        @($lockout | Where-Object { $_.Key -eq '4740' }).Count      | Should -Be 1

        Find-TkWindowsReference -Query '' | Should -BeNullOrEmpty
    }

    It 'explains <Code> with the <Group> steps' -TestCases @(
        @{ Code = '0xC0000005'; Group = 'An application crashed' }
        @{ Code = '0xE0434352'; Group = 'An application crashed' }
        @{ Code = '0xC004F074'; Group = 'Volume activation (KMS and MAK)' }
        @{ Code = '0x80180014'; Group = 'Device enrolment in Intune' }
    ) {
        param($Code, $Group)

        $info = Get-TkErrorCodeInfo -Code $Code

        $info.Known     | Should -BeTrue
        $info.GroupName | Should -Be $Group
        @($info.Steps).Count | Should -BeGreaterThan 0
    }

    It 'reads an application crash code as an NTSTATUS' {
        (Get-TkErrorCodeInfo -Code '0xC0000409').Kind | Should -Be 'NTSTATUS'
        (Get-TkErrorCodeInfo -Code '-1073740791').Name | Should -Be 'STATUS_STACK_BUFFER_OVERRUN'
    }

    It 'keeps the catalogs well formed' {

        $errors = Import-TkCatalog -Name 'windows-errors'
        $groups = @($errors.groups | ForEach-Object { $_.id })

        foreach ($code in $errors.codes) {
            [string] $code.code | Should -MatchExactly '^0x[0-9A-F]{8}$'
            $code.meaning       | Should -Not -BeNullOrEmpty -Because $code.code

            if ($code.group) {
                $groups | Should -Contain $code.group -Because $code.code
            }
        }

        @($errors.codes | Group-Object -Property code | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0

        $events = Import-TkCatalog -Name 'windows-events'

        foreach ($windowsEvent in $events.events) {
            $windowsEvent.severity | Should -BeIn @('Fail', 'Warning', 'Info')
            $windowsEvent.name     | Should -Not -BeNullOrEmpty
            $windowsEvent.log      | Should -Not -BeNullOrEmpty
        }

        @($events.events | Group-Object -Property { '{0}|{1}|{2}' -f $_.log, $_.source, $_.id } | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
    }

    It 'opens a code or an event from the search on the Windows codes tab, on the row it names' {

        $markup = Get-TkMainWindowXaml

        $markup | Should -Match '<TabItem Header="Windows codes">'
        $markup | Should -Match 'x:Name="ReferenceList"'

        $entries = @(Get-TkCatalogSearchEntry | Where-Object { $_.Kind -in @('Error code', 'Event') })

        $entries.Count | Should -BeGreaterThan 300

        # Every tenth entry: each one runs a search of its own.
        for ($index = 0; $index -lt $entries.Count; $index += 10) {

            $entry  = $entries[$index]
            $titles = @(Find-TkWindowsReference -Query $entry.SearchText | ForEach-Object { $_.Title })

            $titles | Should -Contain $entry.Choice -Because $entry.Title
        }
    }
}

Describe 'Tools calculators' {

    Context 'Random ports' {

        It 'draws distinct ports inside the range, never an excluded one' {

            $exclude = @(50000..50999)
            $ports   = @(Get-TkRandomPort -Minimum 49152 -Maximum 65535 -Count 100 -Exclude $exclude)

            $ports.Count                                  | Should -Be 100
            @($ports | Sort-Object -Unique).Count         | Should -Be 100
            @($ports | Where-Object { $_ -lt 49152 -or $_ -gt 65535 }).Count | Should -Be 0
            @($ports | Where-Object { $_ -in $exclude }).Count               | Should -Be 0
        }

        It 'returns every free port of a small range rather than drawing for ever' {

            $ports = @(Get-TkRandomPort -Minimum 1000 -Maximum 1004 -Count 10 -Exclude @(1002))

            ($ports | Sort-Object) -join ',' | Should -Be '1000,1001,1003,1004'
        }

        It 'leaves out the ports of known services when asked, and refuses a range upside down' {

            @(Get-TkRandomPort -Minimum 3389 -Maximum 3390 -Count 2 -SkipKnownServices) -join ',' | Should -Be '3390'

            { Get-TkRandomPort -Minimum 2000 -Maximum 1000 } | Should -Throw
        }

        It 'reads the reserved port ranges from netsh whatever the language of its headings' {

            $text = @(
                ''
                'Plage d''exclusion de ports du protocole tcp'
                ''
                'Port de début    Port de fin'
                '----------    --------'
                '     50000       50059     *'
                '     50060       50159'
                ''
                '* - Exclusions de port administrées.'
            ) -join "`r`n"

            $ranges = @(ConvertFrom-TkExcludedPortRange -Text $text)

            $ranges.Count    | Should -Be 2
            $ranges[0].Start | Should -Be 50000
            $ranges[1].End   | Should -Be 50159
        }
    }

    Context 'chmod' {

        It 'writes <Bits> as <Octal> and <Symbolic>' -TestCases @(
            @{ Bits = 493;  Octal = '755';  Symbolic = 'rwxr-xr-x' }
            @{ Bits = 420;  Octal = '644';  Symbolic = 'rw-r--r--' }
            @{ Bits = 2541; Octal = '4755'; Symbolic = 'rwsr-xr-x' }
            @{ Bits = 1023; Octal = '1777'; Symbolic = 'rwxrwxrwt' }
            @{ Bits = 950;  Octal = '1666'; Symbolic = 'rw-rw-rwT' }
            @{ Bits = 2468; Octal = '4644'; Symbolic = 'rwSr--r--' }
        ) {
            param($Bits, $Octal, $Symbolic)

            $mode = ConvertTo-TkUnixMode -Bits $Bits

            $mode.Octal    | Should -Be $Octal
            $mode.Symbolic | Should -BeExactly $Symbolic

            ConvertFrom-TkUnixModeText -Text $Octal    | Should -Be $Bits
            ConvertFrom-TkUnixModeText -Text $Symbolic | Should -Be $Bits
        }

        It 'writes both chmod commands' {

            $mode = ConvertTo-TkUnixMode -Bits 2541

            $mode.NumericCommand  | Should -Be 'chmod 4755 file'
            $mode.SymbolicCommand | Should -Be 'chmod u=rwxs,g=rx,o=rx file'
            $mode.Listing         | Should -Be '-rwsr-xr-x'
        }

        It 'reads a listing with its file type, and refuses what is not a mode' {

            ConvertFrom-TkUnixModeText -Text 'drwxrwxrwt' | Should -Be 1023
            ConvertFrom-TkUnixModeText -Text '0755'       | Should -Be 493
            ConvertFrom-TkUnixModeText -Text '888'        | Should -BeNullOrEmpty
            ConvertFrom-TkUnixModeText -Text 'rwxrwxrwz'  | Should -BeNullOrEmpty
            ConvertFrom-TkUnixModeText -Text 'RWXRWXRWX'  | Should -BeNullOrEmpty
        }
    }

    Context 'Regex' {

        It 'reports each match with its named groups, and the replacement' {

            $result = Test-TkRegularExpression -Pattern '(?<user>\w+)@(?<domain>[\w.]+)' -Text "a@b.com`nc@d.org" -Replace -Replacement '${domain}'

            $result.Valid                    | Should -BeTrue
            @($result.Matches).Count         | Should -Be 2
            $result.Matches[0].Groups[0].Name  | Should -Be 'user'
            $result.Matches[0].Groups[0].Value | Should -Be 'a'
            $result.Matches[1].Line          | Should -Be 2
            $result.Replaced                 | Should -Be "b.com`nd.org"
        }

        It 'applies the options' {

            @((Test-TkRegularExpression -Pattern '^b' -Text "a`nb").Matches).Count             | Should -Be 0
            @((Test-TkRegularExpression -Pattern '^b' -Text "a`nb" -Multiline).Matches).Count  | Should -Be 1
            @((Test-TkRegularExpression -Pattern 'A' -Text 'a' -IgnoreCase).Matches).Count     | Should -Be 1
            @((Test-TkRegularExpression -Pattern 'a.b' -Text "a`nb" -Singleline).Matches).Count | Should -Be 1
        }

        It 'says why a pattern is not valid, and stops one that backtracks without end' {

            $invalid = Test-TkRegularExpression -Pattern '(' -Text 'x'

            $invalid.Valid | Should -BeFalse
            $invalid.Error | Should -Not -BeNullOrEmpty

            $slow = Test-TkRegularExpression -Pattern '(a+)+$' -Text (('a' * 40) + '!') -TimeoutMilliseconds 100

            $slow.TimedOut | Should -BeTrue
        }

        It 'lists cheat sheet tokens with a description, and insertions that compile where they can stand alone' {

            $sheet = @(Get-TkRegexCheatSheet)

            $sheet.Count | Should -BeGreaterThan 30

            foreach ($entry in $sheet) {

                $entry.Section     | Should -Not -BeNullOrEmpty
                $entry.Token       | Should -Not -BeNullOrEmpty
                $entry.Insert      | Should -Not -BeNullOrEmpty
                $entry.Description | Should -Not -BeNullOrEmpty
                $entry.Target      | Should -BeIn @('Pattern', 'Replacement')
            }

            # Groups, lookarounds and options are complete once inserted.
            foreach ($entry in @($sheet | Where-Object { $_.Section -in @('Groups and alternatives', 'Lookaround', 'Inline options') -and $_.Insert -ne '\1' })) {
                (Test-TkRegularExpression -Pattern $entry.Insert -Text 'x').Valid | Should -BeTrue -Because $entry.Insert
            }
        }

        It 'matches the example of every ready-made pattern whole' {

            $ready = @(Get-TkRegexCheatSheet | Where-Object { $_.Section -eq 'Ready-made patterns' })

            $ready.Count | Should -BeGreaterThan 5

            foreach ($entry in $ready) {
                $entry.Example | Should -Not -BeNullOrEmpty -Because $entry.Token
                $entry.Example | Should -Match ('^(?:{0})$' -f $entry.Insert) -Because $entry.Token
            }

            'Contact jane.doe@example.com today' | Should -Match (Get-TkRegexCheatSheet | Where-Object Token -eq 'E-mail address').Insert
            '256.1.1.1'                          | Should -Not -Match ('^(?:{0})$' -f (Get-TkRegexCheatSheet | Where-Object Token -eq 'IPv4 address').Insert)
        }
    }

    Context 'Timestamps' {

        BeforeAll {
            $script:FixedNow = [datetime]::SpecifyKind([datetime]::new(2026, 9, 14, 8, 0, 0), [DateTimeKind]::Utc)
        }

        It 'reads Unix seconds and milliseconds' {

            $seconds = ConvertFrom-TkTimestamp -Text '1726300800' -Now $script:FixedNow

            $seconds.Kind        | Should -Be 'Unix time, seconds'
            $seconds.Utc         | Should -Be ([DateTimeOffset]::FromUnixTimeSeconds(1726300800).UtcDateTime)

            $milliseconds = ConvertFrom-TkTimestamp -Text '1726300800000' -Now $script:FixedNow

            $milliseconds.Kind        | Should -Be 'Unix time, milliseconds'
            $milliseconds.UnixSeconds | Should -Be 1726300800
        }

        It 'reads a Windows FILETIME, as Active Directory stores lastLogonTimestamp' {

            $fileTime = $script:FixedNow.AddDays(-3).ToFileTimeUtc()
            $result   = ConvertFrom-TkTimestamp -Text ([string] $fileTime) -Now $script:FixedNow

            $result.Kind     | Should -BeLike 'Windows FILETIME*'
            $result.Utc      | Should -Be $script:FixedNow.AddDays(-3)
            $result.Relative | Should -Be '3 day(s) ago'
        }

        It 'names the never values of Active Directory, and reads a date' {

            (ConvertFrom-TkTimestamp -Text '9223372036854775807' -Now $script:FixedNow).Kind | Should -Be 'Never'
            (ConvertFrom-TkTimestamp -Text '0' -Now $script:FixedNow).Note                   | Should -BeLike '*never*'

            $date = ConvertFrom-TkTimestamp -Text '2026-09-14T09:30:00Z' -Now $script:FixedNow

            $date.Kind     | Should -Be 'Date'
            $date.Iso      | Should -Be '2026-09-14T09:30:00.000Z'
            $date.Relative | Should -Be 'in 1 hour(s)'

            (ConvertFrom-TkTimestamp -Text 'banana').Valid | Should -BeFalse
        }
    }

    Context 'Encoding' {

        It 'converts text both ways, in UTF-8' {

            $accented = 'h{0}llo' -f [char] 0xE9

            Convert-TkText -Text $accented -Operation Base64Encode   | Should -Be 'aMOpbGxv'
            Convert-TkText -Text 'aMOpbGxv' -Operation Base64Decode  | Should -Be $accented
            Convert-TkText -Text 'a b&c' -Operation UrlEncode        | Should -Be 'a%20b%26c'
            Convert-TkText -Text '%C3%A9' -Operation UrlDecode       | Should -Be ([string] [char] 0xE9)
            Convert-TkText -Text '<b>' -Operation HtmlEncode         | Should -Be '&lt;b&gt;'
            Convert-TkText -Text 'AB' -Operation HexEncode           | Should -Be '4142'
            Convert-TkText -Text '41 42' -Operation HexDecode        | Should -Be 'AB'

            { Convert-TkText -Text 'abc' -Operation HexDecode }      | Should -Throw
            { Convert-TkText -Text 'a' -Operation Base64Decode }     | Should -Throw
        }

        It 'indents JSON the same way on every version, strings and empty containers untouched' {

            $text = '{"a":[1,{"b":"x, {y}: \"z\""}],"c":{},"d":[]}'

            Format-TkJsonText -Json $text | Should -Be (@(
                '{'
                '  "a": ['
                '    1,'
                '    {'
                '      "b": "x, {y}: \"z\""'
                '    }'
                '  ],'
                '  "c": {},'
                '  "d": []'
                '}'
            ) -join "`n")
        }

        It 'decodes a JWT, its expiry included, without claiming it is genuine' {

            $encode = { param($text) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
            $token  = '{0}.{1}.signature' -f (& $encode '{"alg":"HS256","typ":"JWT"}'), (& $encode '{"sub":"42","exp":1726300800}')

            $decoded = ConvertFrom-TkJwt -Token $token -Now ([datetime]::new(2026, 9, 14))

            $decoded.Header.alg   | Should -Be 'HS256'
            $decoded.Payload.sub  | Should -Be '42'
            $decoded.Expired      | Should -BeTrue
            $decoded.Signed       | Should -BeTrue

            # With no secret, the decode invites verification rather than vouching.
            Convert-TkText -Text $token -Operation JwtDecode | Should -Match 'Enter the HMAC secret'

            $decoded.PayloadText | Should -Be "{`n  `"sub`": `"42`",`n  `"exp`": 1726300800`n}"

            { ConvertFrom-TkJwt -Token 'not a token' } | Should -Throw
        }

        It 'verifies an HS256 signature against its secret' {

            # The canonical jwt.io example.
            $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

            (Test-TkJwtSignature -Token $token -Secret 'your-256-bit-secret').Result | Should -Be 'Valid'
            (Test-TkJwtSignature -Token $token -Secret 'wrong').Result               | Should -Be 'Invalid'
            (Test-TkJwtSignature -Token $token -Secret '').Result                    | Should -Be 'NoSecret'

            Convert-TkText -Text $token -Operation JwtDecode -Secret 'your-256-bit-secret' | Should -Match 'Signature \(HS256\): VALID'
        }

        It 'calls out an unsigned token and declines an asymmetric one' {

            $encode = { param($text) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

            $none = '{0}.{1}.' -f (& $encode '{"alg":"none"}'), (& $encode '{"sub":"x"}')
            (Test-TkJwtSignature -Token $none).Result | Should -Be 'Unsigned'

            $rs = '{0}.{1}.sig' -f (& $encode '{"alg":"RS256"}'), (& $encode '{"sub":"x"}')
            (Test-TkJwtSignature -Token $rs -Secret 'anything').Result | Should -Be 'Unsupported'
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

    It 'says so plainly for a prefix no IEEE block holds' {

        # Found in the registry rather than written down, so a block the IEEE
        # assigns later cannot turn this test red.
        $candidate = 0xA80000

        while (Find-TkMacVendorRecord -Hex ('{0:X6}' -f $candidate)) {
            $candidate++
        }

        Get-TkMacVendor -MacAddress (('{0:X6}000001' -f $candidate)) | Should -Be 'Unknown vendor'
    }

    It 'finds vendors beyond the short table, in the IEEE registry' {
        Get-TkMacVendor -MacAddress '00:11:22:33:44:55' | Should -Not -Be 'Unknown vendor'
    }

    It 'returns nothing for empty input' {
        Get-TkMacVendor -MacAddress '' | Should -BeNullOrEmpty
    }
}

Describe 'MAC address lookup' {

    It 'reads the IEEE registry built into the toolkit, all three block sizes' {

        $registry = Get-TkDataResource -Name 'mac-vendors.tsv'

        $registry | Should -Match '^# MAC address vendors from the IEEE'
        $registry | Should -Match '# Retrieved \d{4}-\d{2}-\d{2}'
        ([regex]::Matches($registry, "`n[0-9A-F]{6}`t")).Count | Should -BeGreaterThan 30000
        ([regex]::Matches($registry, "`n[0-9A-F]{7}`t")).Count | Should -BeGreaterThan 3000
        ([regex]::Matches($registry, "`n[0-9A-F]{9}`t")).Count | Should -BeGreaterThan 3000
    }

    It 'prefers the smallest block that holds the address' {

        (Find-TkMacVendorRecord -Hex '286FB9123456').Registry | Should -Be 'MA-L'
        (Find-TkMacVendorRecord -Hex '286FB9123456').Vendor   | Should -BeLike 'Nokia Shanghai Bell*'

        $medium = Find-TkMacVendorRecord -Hex 'C85CE2712345'
        $medium.Registry | Should -Be 'MA-M'
        $medium.Bits     | Should -Be 28
        $medium.Vendor   | Should -Be 'SYNERGY SYSTEMS AND SOLUTIONS'

        $small = Find-TkMacVendorRecord -Hex '8C1F64AFA012'
        $small.Registry | Should -Be 'MA-S'
        $small.Vendor   | Should -BeLike 'DATA ELECTRONIC DEVICES*'
    }

    It 'says what kind of address <Mac> is' -TestCases @(
        @{ Mac = 'FF:FF:FF:FF:FF:FF'; Kind = 'Broadcast*' }
        @{ Mac = '01:00:5E:00:00:FB'; Kind = 'IPv4 multicast*' }
        @{ Mac = '33:33:00:00:00:01'; Kind = 'IPv6 multicast*' }
        @{ Mac = '00:00:5E:00:01:0A'; Kind = 'VRRP*' }
        @{ Mac = '00:00:0C:07:AC:01'; Kind = 'HSRP*' }
        @{ Mac = 'DA:A1:19:12:34:56'; Kind = 'Locally administered*' }
        @{ Mac = '28-6F-B9-12-34-56'; Kind = 'Universally administered*' }
    ) {
        param($Mac, $Kind)

        (Get-TkMacAddressInfo -MacAddress $Mac).Kind | Should -BeLike $Kind
    }

    It 'reads the usual ways of writing an address, and refuses what is not one' {

        (Get-TkMacAddressInfo -MacAddress '286f.b912.3456').Address | Should -Be '28:6F:B9:12:34:56'
        (Get-TkMacAddressInfo -MacAddress '00:15:5D').Hint           | Should -Be 'Microsoft Hyper-V'
        (Get-TkMacAddressInfo -MacAddress 'DA:A1:19:12:34:56').Vendor | Should -BeNullOrEmpty
        (Get-TkMacAddressInfo -MacAddress 'not a mac').Valid         | Should -BeFalse
    }
}

Describe 'IPv6 unique local prefix' {

    It 'builds the prefix and its subnets from the global ID' {

        $ula = New-TkIPv6UniqueLocalPrefix -SubnetCount 3 -GlobalId ([byte[]] @(0x12, 0x34, 0x56, 0x78, 0x9a))

        $ula.Prefix   | Should -Be 'fd12:3456:789a::/48'
        $ula.GlobalId | Should -Be '123456789a'
        $ula.Subnets -join ',' | Should -Be 'fd12:3456:789a::/64,fd12:3456:789a:1::/64,fd12:3456:789a:2::/64'
    }

    It 'draws a different random global ID each time, inside fd00::/8' {

        $first  = New-TkIPv6UniqueLocalPrefix
        $second = New-TkIPv6UniqueLocalPrefix

        $first.Prefix         | Should -Match '^fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}::/48$'
        $first.GlobalId       | Should -Not -Be $second.GlobalId
        @($first.Subnets).Count | Should -Be 4

        { New-TkIPv6UniqueLocalPrefix -GlobalId ([byte[]] @(1, 2, 3)) } | Should -Throw
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

    It 'writes a text value as text, so its applied state can be read back' {

        # Test-TkTweakApplied compares as text; a String value declared as a
        # JSON number would still match, but would be written as a number.
        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            foreach ($entry in @(ConvertTo-TkArray $tweak.registry | Where-Object { $_.type -eq 'String' })) {
                $entry.value   | Should -BeOfType [string] -Because ('{0} {1}' -f $tweak.id, $entry.name)
                $entry.default | Should -BeOfType [string] -Because ('{0} {1}' -f $tweak.id, $entry.name)
            }
        }
    }

    It 'reaches every hive through a path the registry provider reads, and elevates outside the user hive' {

        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            # Read from the lists themselves: an absent list must add nothing,
            # not an empty entry.
            $paths = @(@($tweak.registry) + @($tweak.registryKeys) | Where-Object { $_ -and $_.path } | ForEach-Object { [string] $_.path })

            foreach ($path in $paths) {
                $path | Should -Match '^(HKLM:\\|HKCU:\\|Registry::HKEY_(USERS|LOCAL_MACHINE|CURRENT_USER)\\)' -Because $tweak.id
            }

            # Writing to the machine or to another user's hive needs rights the
            # interface has to ask for before it tries.
            $services = @(@($tweak.services) | Where-Object { $_ })

            if (@($paths | Where-Object { $_ -notmatch '^HKCU:\\|^Registry::HKEY_CURRENT_USER\\' }).Count -gt 0 -or $services.Count -gt 0) {
                $tweak.requiresElevation | Should -BeTrue -Because $tweak.id
            }
        }
    }

    It 'turns Num Lock on at the sign-in screen as well as in the session' {

        $tweak = (Import-TkCatalog -Name 'tweaks').tweaks | Where-Object { $_.id -eq 'numlock-at-startup' }

        @($tweak.registry | ForEach-Object { $_.path }) | Should -Contain 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard'
        @($tweak.registry | ForEach-Object { $_.path }) | Should -Contain 'HKCU:\Control Panel\Keyboard'
    }

    It 'names features, capabilities and audit subcategories in a form safe for a command line, with both states, and elevates for them' {

        foreach ($tweak in (Import-TkCatalog -Name 'tweaks').tweaks) {

            $features     = ConvertTo-TkArray $tweak.optionalFeatures
            $capabilities = ConvertTo-TkArray $tweak.capabilities
            $audits       = ConvertTo-TkArray $tweak.auditPolicy

            foreach ($feature in $features) {
                Test-TkServicingName -Name $feature.name | Should -BeTrue -Because $tweak.id
                $feature.state   | Should -BeIn @('Enabled', 'Disabled') -Because $tweak.id
                $feature.default | Should -BeIn @('Enabled', 'Disabled') -Because $tweak.id
            }

            foreach ($capability in $capabilities) {
                Test-TkServicingName -Name $capability.name | Should -BeTrue -Because $tweak.id
                $capability.state   | Should -BeIn @('Installed', 'NotPresent') -Because $tweak.id
                $capability.default | Should -BeIn @('Installed', 'NotPresent') -Because $tweak.id

                # Read back without rights, from a file the capability installs.
                $capability.installedPath | Should -Match '^%SystemRoot%\\' -Because $tweak.id
            }

            foreach ($audit in $audits) {
                $audit.subcategory | Should -Match '^\{[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}\}$' -Because $tweak.id

                foreach ($field in @('success', 'failure', 'defaultSuccess', 'defaultFailure')) {
                    $audit.$field | Should -BeIn @('enable', 'disable') -Because ('{0} {1}' -f $tweak.id, $field)
                }
            }

            if (($features.Count + $capabilities.Count + $audits.Count) -gt 0) {
                $tweak.requiresElevation | Should -BeTrue -Because $tweak.id
            }
        }
    }
}

Describe 'Tweak engine: optional features, capabilities and audit policy' {

    It 'refuses a servicing name a command line could read as something else' {

        Test-TkServicingName -Name 'OpenSSH.Server~~~~0.0.1.0'         | Should -BeTrue
        Test-TkServicingName -Name 'Microsoft-Windows-Subsystem-Linux' | Should -BeTrue
        Test-TkServicingName -Name '-All'                              | Should -BeFalse
        Test-TkServicingName -Name 'SMB1Protocol; Remove-Item C:\'     | Should -BeFalse
        Test-TkServicingName -Name ''                                  | Should -BeFalse
    }

    It 'reads a feature as enabled only when Windows says so, and an absent one as removed' {

        Test-TkOptionalFeatureState -InstallState 1     -Target 'Enabled'  | Should -BeTrue
        Test-TkOptionalFeatureState -InstallState 2     -Target 'Enabled'  | Should -BeFalse
        Test-TkOptionalFeatureState -InstallState 2     -Target 'Disabled' | Should -BeTrue

        # Not part of the build, as PowerShell 2.0 is from recent Windows 11.
        Test-TkOptionalFeatureState -InstallState 3     -Target 'Disabled' | Should -BeTrue
        Test-TkOptionalFeatureState -InstallState $null -Target 'Disabled' | Should -BeTrue
        Test-TkOptionalFeatureState -InstallState $null -Target 'Enabled'  | Should -BeFalse
    }

    It 'decides a feature tweak from the states it is given, and reads it as not applied when they could not be read' {

        $tweak = [pscustomobject] @{
            id               = 'example'
            optionalFeatures = @([pscustomobject] @{ name = 'SMB1Protocol'; state = 'Disabled'; default = 'Enabled' })
        }

        Test-TkTweakApplied -Tweak $tweak -FeatureStates @{ SMB1Protocol = 2 } | Should -BeTrue
        Test-TkTweakApplied -Tweak $tweak -FeatureStates @{ SMB1Protocol = 1 } | Should -BeFalse
        Test-TkTweakApplied -Tweak $tweak -FeatureStates $null                | Should -BeFalse
    }

    It 'counts an audit subcategory as applied when it records at least what the tweak asks' {

        Test-TkAuditSettingState -Setting 1 -Success enable -Failure disable | Should -BeTrue
        Test-TkAuditSettingState -Setting 3 -Success enable -Failure disable | Should -BeTrue
        Test-TkAuditSettingState -Setting 2 -Success enable -Failure disable | Should -BeFalse
        Test-TkAuditSettingState -Setting 1 -Success enable -Failure enable  | Should -BeFalse
    }

    It 'decides an audit tweak from the policy it is given, and never guesses when the policy is not readable' {

        $guid  = '{0CCE922B-69AE-11D9-BED3-505054503030}'
        $tweak = [pscustomobject] @{
            id          = 'example'
            auditPolicy = @([pscustomobject] @{ subcategory = $guid; name = 'Process Creation'; success = 'enable'; failure = 'disable' })
        }

        Test-TkTweakApplied -Tweak $tweak -AuditSettings @{ $guid = 1 } | Should -BeTrue
        Test-TkTweakApplied -Tweak $tweak -AuditSettings @{ $guid = 0 } | Should -BeFalse
        Test-TkTweakApplied -Tweak $tweak -AuditSettings $null          | Should -BeFalse
    }
}

Describe 'Fix helpers' {

    It 'takes the newest Defender platform folder by version, then the copy in Program Files' {

        $platform = Join-Path $TestDrive 'Platform'
        $program  = Join-Path $TestDrive 'Program Files'

        # As text 4.18.9999 sorts after 4.18.25080; as a version it is older.
        foreach ($name in @('4.18.24090.11-0', '4.18.25080.5-0', '4.18.9999.1-0')) {
            New-Item -ItemType File -Path (Join-Path (Join-Path $platform $name) 'MpCmdRun.exe') -Force | Out-Null
        }

        New-Item -ItemType Directory -Path (Join-Path $platform '4.18.26000.1-0') -Force | Out-Null

        Get-TkMpCmdRunPath -PlatformRoot $platform -ProgramFiles $program |
            Should -Be (Join-Path (Join-Path $platform '4.18.25080.5-0') 'MpCmdRun.exe')

        $missing = Join-Path $TestDrive 'none'

        Get-TkMpCmdRunPath -PlatformRoot $missing -ProgramFiles $program | Should -BeNullOrEmpty

        New-Item -ItemType File -Path (Join-Path $program 'Windows Defender\MpCmdRun.exe') -Force | Out-Null

        Get-TkMpCmdRunPath -PlatformRoot $missing -ProgramFiles $program | Should -Be (Join-Path $program 'Windows Defender\MpCmdRun.exe')
    }

    It 'looks for the cache of new and classic Teams in the account folders' {

        $folders = @(Get-TkTeamsCacheFolder -LocalAppData 'C:\Users\jane\AppData\Local' -AppData 'C:\Users\jane\AppData\Roaming')

        $folders.Path | Should -Contain 'C:\Users\jane\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
        $folders.Path | Should -Contain 'C:\Users\jane\AppData\Roaming\Microsoft\Teams'
    }

    It 'finds OneDrive where it is installed, per user before per machine' {

        $perMachine = Join-Path $TestDrive 'Microsoft OneDrive\OneDrive.exe'
        New-Item -ItemType File -Path $perMachine -Force | Out-Null

        Get-TkOneDriveExecutable -Candidate @((Join-Path $TestDrive 'missing\OneDrive.exe'), '', $perMachine) | Should -Be $perMachine
        Get-TkOneDriveExecutable -Candidate @((Join-Path $TestDrive 'missing\OneDrive.exe')) | Should -BeNullOrEmpty
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

    It 'opens with the Git, PowerShell, Bash and Linux cheat sheets' {

        $ids = @($script:Vendors | ForEach-Object { $_.id })

        $ids[0..3] -join ',' | Should -Be 'git,powershell,bash,linux-admin'
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count

        $powershell = $script:Vendors | Where-Object { $_.id -eq 'powershell' }
        $sections   = @($powershell.sections | ForEach-Object { $_.name }) -join ' | '

        foreach ($expected in @('Verbs', 'pipeline', 'Operators', 'classes', 'errors', 'administration')) {
            $sections | Should -Match $expected
        }
    }

    It 'carries the administration cheat sheets after the scripting ones' {

        $ids = @($script:Vendors | ForEach-Object { $_.id })

        foreach ($expected in @('active-directory', 'windows-cmd', 'intune-mdm', 'microsoft-graph-exchange',
                                'openssl', 'packet-capture', 'docker', 'kubernetes', 'virtualization')) {

            $ids | Should -Contain $expected
            [array]::IndexOf($ids, $expected) | Should -BeLessThan ([array]::IndexOf($ids, 'aruba-cx')) -Because $expected
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
                               'BGP', 'IPv6', 'Certificates', 'DNS', 'VLAN', 'Wi-Fi',
                               'Group Policy', 'Kerberos', 'Entra', 'recovery', 'WSUS',
                               'ransomware', 'incident', 'DMARC', 'MFA', 'SIDs',
                               'HTTP status', 'SMTP')) {

            $titles | Should -Match $subject
        }
    }

    It 'keeps every table rectangular, each row as long as its columns' {

        foreach ($topic in $script:Topics) {

            foreach ($table in (ConvertTo-TkArray $topic.tables)) {

                $width = @($table.columns).Count

                foreach ($row in @($table.rows)) {
                    @($row).Count | Should -Be $width -Because ('{0}: {1}' -f $topic.id, $table.title)
                }
            }
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

    It 'derives a faint fill for every severity and alpha from the palette, in both themes' {

        foreach ($theme in @('Dark', 'Light')) {

            $palette = Get-TkThemePalette -Name $theme
            $tints   = Get-TkThemeTint -Palette $palette

            foreach ($severity in @('Fail', 'Warning', 'Pass', 'Info', '')) {
                foreach ($alpha in @(38, 60)) {

                    $key    = Get-TkSeverityTintKey -Severity $severity -Alpha $alpha
                    $source = $palette[(Get-TkSeverityBrushKey -Severity $severity)]

                    $tints.ContainsKey($key) | Should -BeTrue -Because $key
                    $tints[$key] | Should -Be ('#{0:X2}{1}' -f $alpha, $source.TrimStart('#'))
                }
            }

            # A tint must never take the place of a palette colour.
            @($tints.Keys | Where-Object { $palette.ContainsKey($_) }).Count | Should -Be 0
        }
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

        It 'binds document colours to their key, so a document on screen follows a theme change' {

            $document = New-TkFlowDocument
            $document.Resources['Accent']          = [System.Windows.Media.Brushes]::Red
            $document.Resources['InputBackground'] = [System.Windows.Media.Brushes]::Red

            Add-TkHeading   -Document $document -Text 'Section' -Level 2
            Add-TkCodeBlock -Document $document -Text 'git status'

            $heading = @($document.Blocks)[0]
            $code    = @($document.Blocks)[1]

            $heading.Foreground.Color | Should -Be ([System.Windows.Media.Colors]::Red)

            # What Set-TkTheme does: a new brush behind the same key.
            $document.Resources['Accent']          = [System.Windows.Media.Brushes]::Blue
            $document.Resources['InputBackground'] = [System.Windows.Media.Brushes]::Blue

            $heading.Foreground.Color | Should -Be ([System.Windows.Media.Colors]::Blue)
            $code.Background.Color    | Should -Be ([System.Windows.Media.Colors]::Blue)
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

            # The editable text is drawn by an inner TextBoxView that applies
            # Padding on its own. So the inset must come from exactly one place:
            # the hint carries Padding to sit on the same line as the text, and
            # the content host carries no margin. Binding Padding onto the
            # content host as well applied it twice and pushed the caret a whole
            # Padding.Left to the right of the placeholder.
            # Read from the markup rather than the built template: XamlWriter
            # serialises a template with its bindings already resolved, so the
            # very thing under test disappears from the output.
            $markup = Get-TkMainWindowXaml

            $start = $markup.IndexOf('<Style TargetType="TextBox">')
            $start | Should -BeGreaterThan 0

            # Bound the search to this one style, whatever length its comments
            # grow to, so the next style's own content host cannot stand in.
            $next = $markup.IndexOf('<Style ', $start + 10)
            $body = $markup.Substring($start, $next - $start)

            # The hint sits at Padding.
            $hint = [regex]::Match($body, '<TextBlock x:Name="Hint".*?/>', 'Singleline')
            $hint.Success | Should -BeTrue
            $hint.Value   | Should -Match 'Margin="\{TemplateBinding Padding\}"'

            # The content host does not add Padding a second time.
            $contentHost = [regex]::Match($body, '<ScrollViewer x:Name="PART_ContentHost".*?/>', 'Singleline')
            $contentHost.Success | Should -BeTrue
            $contentHost.Value   | Should -Not -Match 'Margin='
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

Describe 'Sign-in and management' {

    BeforeAll {

        # dsregcmd /status on the machine this was written on: a workgroup
        # computer with no work account.
        $script:Workgroup = ConvertFrom-TkDsregStatus -Line @(
            '| Device State                                                         |'
            '             AzureAdJoined : NO'
            '          EnterpriseJoined : NO'
            '              DomainJoined : NO'
            '                    NgcSet : NO'
            '           WorkplaceJoined : NO'
            '                AzureAdPrt : NO'
            'For more information, please visit https://www.microsoft.com/aadjerrors'
        )

        # Built from the samples Microsoft publishes for dsregcmd.
        $script:EntraLines = @(
            '             AzureAdJoined : YES'
            '          EnterpriseJoined : NO'
            '              DomainJoined : NO'
            '          DeviceAuthStatus : SUCCESS'
            '                TenantName : Contoso'
            '                    MdmUrl : https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc'
            '                    NgcSet : YES'
        )

        $script:Stopped = [pscustomobject] @{ Status = 'Stopped'; StartType = 'Manual'; Server = 'pool.ntp.org,0x8' }
        $script:Running = [pscustomobject] @{ Status = 'Running'; StartType = 'Automatic'; Server = '' }
        $script:Now     = [datetime]::SpecifyKind([datetime] '2026-09-13 12:00', [DateTimeKind]::Utc)
    }

    It 'reads names with spaces, and values holding a colon' {

        $status = ConvertFrom-TkDsregStatus -Line @(
            '              DomainName : HYBRIDADFS'
            '     Previous Prt Attempt : 2020-07-18 20:10:33.789 UTC'
            '              Client Time : 2019-01-31 09:25:31.000 UTC'
        )

        $status['DomainName']           | Should -Be 'HYBRIDADFS'
        $status['Previous Prt Attempt'] | Should -Be '2020-07-18 20:10:33.789 UTC'
        $status['Client Time']          | Should -Be '2019-01-31 09:25:31.000 UTC'
    }

    It 'names the join type <Expected>' -TestCases @(
        @{ Entra = 'YES'; Enterprise = 'NO';  Domain = 'NO';  Workplace = 'NO';  Expected = 'Microsoft Entra joined' }
        @{ Entra = 'NO';  Enterprise = 'NO';  Domain = 'YES'; Workplace = 'NO';  Expected = 'Domain joined' }
        @{ Entra = 'YES'; Enterprise = 'NO';  Domain = 'YES'; Workplace = 'NO';  Expected = 'Microsoft Entra hybrid joined' }
        @{ Entra = 'NO';  Enterprise = 'YES'; Domain = 'YES'; Workplace = 'NO';  Expected = 'On-premises DRS joined' }
        @{ Entra = 'NO';  Enterprise = 'NO';  Domain = 'NO';  Workplace = 'YES'; Expected = 'Microsoft Entra registered' }
        @{ Entra = 'NO';  Enterprise = 'NO';  Domain = 'NO';  Workplace = 'NO';  Expected = 'Not joined' }
    ) {
        param($Entra, $Enterprise, $Domain, $Workplace, $Expected)

        $status = ConvertFrom-TkDsregStatus -Line @(
            "AzureAdJoined : $Entra", "EnterpriseJoined : $Enterprise", "DomainJoined : $Domain", "WorkplaceJoined : $Workplace"
        )

        Get-TkJoinType -Status $status | Should -Be $Expected
    }

    It 'reads a dsregcmd time as UTC' {

        $time = ConvertFrom-TkDsregTime -Text '2019-01-24 19:15:33.000 UTC'

        $time.Kind | Should -Be 'Utc'
        $time.Hour | Should -Be 19
    }

    It 'reads the clock offset from w32tm, with either decimal separator' {

        ConvertFrom-TkStripchartOffset -Line @('Tracking time.windows.com.', '19:42:54, -05.6530458s') | Should -Be -5.6530458
        ConvertFrom-TkStripchartOffset -Line @('19:42:54, +00,1250000s') | Should -Be 0.125
        ConvertFrom-TkStripchartOffset -Line @('The following error occurred') | Should -BeNullOrEmpty
    }

    It 'reports a workgroup computer as information only' {

        $rows = @(ConvertTo-TkIdentityHealth -Status $script:Workgroup -TimeService $script:Stopped -Now $script:Now)

        ($rows | Where-Object { $_.Kind -eq 'Join' }).Value | Should -Be 'Not joined'
        @($rows | Where-Object { $_.Severity -in @('Fail', 'Warning') }).Count | Should -Be 0
    }

    It 'fails single sign-on without a token, and says why the last attempt failed' {

        $status = ConvertFrom-TkDsregStatus -Line ($script:EntraLines + @('AzureAdPrt : NO', 'Attempt Status : 0xc000006d'))
        $sso    = ConvertTo-TkIdentityHealth -Status $status -TimeService $script:Running -Now $script:Now |
                  Where-Object { $_.Kind -eq 'Single sign-on' }

        $sso.Severity      | Should -Be 'Fail'
        $sso.Detail        | Should -Match '0xc000006d'
        $sso.RemediationId | Should -Be 'open-work-access'
    }

    It 'warns about a token not renewed for a day' {

        $status = ConvertFrom-TkDsregStatus -Line ($script:EntraLines + @('AzureAdPrt : YES', 'AzureAdPrtUpdateTime : 2026-09-12 06:00:00.000 UTC'))
        $sso    = ConvertTo-TkIdentityHealth -Status $status -TimeService $script:Running -Now $script:Now |
                  Where-Object { $_.Kind -eq 'Single sign-on' }

        $sso.Severity | Should -Be 'Warning'
        $sso.Value    | Should -Match '30 hours'
    }

    It 'fails a device disabled or deleted in Microsoft Entra ID' {

        $lines  = $script:EntraLines -replace 'DeviceAuthStatus : SUCCESS', 'DeviceAuthStatus : FAILED. Device is either disabled or deleted'
        $device = ConvertTo-TkIdentityHealth -Status (ConvertFrom-TkDsregStatus -Line $lines) -Now $script:Now |
                  Where-Object { $_.Kind -eq 'Entra device' }

        $device.Severity | Should -Be 'Fail'
    }

    It 'warns when the tenant enrolls devices automatically and this one is not enrolled' {

        $mdm = ConvertTo-TkIdentityHealth -Status (ConvertFrom-TkDsregStatus -Line ($script:EntraLines + 'AzureAdPrt : YES')) -Now $script:Now |
               Where-Object { $_.Kind -eq 'Device management' }

        $mdm.Severity | Should -Be 'Warning'
        $mdm.Value    | Should -Be 'Not enrolled'
    }

    It 'judges the clock of a domain member against Kerberos: <Offset> s is <Expected>' -TestCases @(
        @{ Offset = 0.4;  Expected = 'Pass' }
        @{ Offset = -90;  Expected = 'Warning' }
        @{ Offset = 400;  Expected = 'Fail' }
    ) {
        param($Offset, $Expected)

        $domain = [pscustomobject] @{ Domain = 'corp.contoso.com'; Name = 'DC01.corp.contoso.com'; Site = 'Paris'; Reachable = $true; Error = '' }

        $clock = ConvertTo-TkIdentityHealth -DomainJoined $true -Domain $domain -SecureChannel $true `
                                            -TimeService $script:Running -ClockOffset $Offset -Now $script:Now |
                 Where-Object { $_.Kind -eq 'Clock' }

        $clock.Severity | Should -Be $Expected
    }

    It 'fails a domain member that reaches no domain controller or has a broken secure channel' {

        $domain = [pscustomobject] @{ Domain = ''; Name = ''; Site = ''; Reachable = $false; Error = 'The specified domain either does not exist or could not be contacted.' }

        $rows = @(ConvertTo-TkIdentityHealth -DomainJoined $true -Domain $domain -SecureChannel $false -TimeService $script:Running -Now $script:Now)

        ($rows | Where-Object { $_.Kind -eq 'Domain controller' }).Severity | Should -Be 'Fail'
        ($rows | Where-Object { $_.Kind -eq 'Secure channel' }).Severity    | Should -Be 'Fail'
    }

    It 'does not warn a domain member of a domain that never set up hybrid join' {

        # What dsregcmd records on every member of an on-premises domain: the
        # automatic device join task found no join settings to discover.
        $status = ConvertFrom-TkDsregStatus -Line @(
            'AzureAdJoined : NO', 'DomainJoined : YES', 'DomainName : CORP', 'WorkplaceJoined : NO',
            'AzureAdPrt : NO', 'AD Connectivity Test : PASS', 'AD Configuration Test : FAIL [0x801c001d]',
            'Error Phase : discover', 'Client ErrorCode : 0x801c001d'
        )
        $domain = [pscustomobject] @{ Domain = 'corp.contoso.com'; Name = 'DC01.corp.contoso.com'; Site = 'Paris'; Reachable = $true; Error = '' }

        $rows = @(ConvertTo-TkIdentityHealth -Status $status -DomainJoined $true -Domain $domain -SecureChannel $true `
                                             -TimeService $script:Running -ClockOffset 0.2 -Now $script:Now)

        $hybrid = $rows | Where-Object { $_.Kind -eq 'Hybrid join' }

        $hybrid.Severity | Should -Be 'Info'
        $hybrid.Value    | Should -Be 'Not set up for this domain'
        @($rows | Where-Object { $_.Severity -in @('Fail', 'Warning') }).Count | Should -Be 0
        @($rows | Where-Object { $_.RemediationId -eq 'open-work-access' }).Count | Should -Be 0
    }

    It 'still warns when the domain publishes hybrid join settings and the device did not join' {

        $status = ConvertFrom-TkDsregStatus -Line @(
            'AzureAdJoined : NO', 'DomainJoined : YES', 'Error Phase : join', 'Client ErrorCode : 0x801c03f2',
            'Server Message : The device object by the given id is not found.'
        )

        $configured = ConvertTo-TkIdentityHealth -Status $status -DomainJoined $true -HybridConfigured $true -Now $script:Now |
                      Where-Object { $_.Kind -eq 'Hybrid join' }
        $unknown    = ConvertTo-TkIdentityHealth -Status $status -DomainJoined $true -Now $script:Now |
                      Where-Object { $_.Kind -eq 'Hybrid join' }
        $absent     = ConvertTo-TkIdentityHealth -Status $status -DomainJoined $true -HybridConfigured $false -Now $script:Now |
                      Where-Object { $_.Kind -eq 'Hybrid join' }

        $configured.Severity | Should -Be 'Warning'
        $configured.Detail   | Should -Match '0x801c03f2'
        $unknown.Severity    | Should -Be 'Warning'
        $absent.Severity     | Should -Be 'Info'
    }

    It 'offers only corrections the allow list knows' {

        $table  = Get-TkRemediationTable
        $status = ConvertFrom-TkDsregStatus -Line ($script:EntraLines + 'AzureAdPrt : NO')
        $domain = [pscustomobject] @{ Domain = 'x'; Name = 'DC01'; Site = ''; Reachable = $true; Error = '' }

        $rows = @(ConvertTo-TkIdentityHealth -Status $status -DomainJoined $true -Domain $domain -SecureChannel $true `
                                             -TimeService $script:Stopped -ClockOffset 400 -Now $script:Now)

        foreach ($id in @($rows | ForEach-Object { $_.RemediationId } | Where-Object { $_ })) {
            $table.Keys | Should -Contain $id
        }
    }
}

Describe 'Search' {

    BeforeAll {
        $script:Index = @(Get-TkSearchIndex -Markup (Get-TkMainWindowXaml) -Force)
    }

    It 'indexes every page, under the label of its navigation button' {

        $pages = @($script:Index | Where-Object { $_.Kind -eq 'Page' })

        @($pages | ForEach-Object { $_.Page }) | Should -Be @(Get-TkPageName)
        ($pages | Where-Object { $_.Page -eq 'Security' }).Title | Should -Be 'Audit'
    }

    It 'indexes tabs with the tab control that holds them' {

        $tab = $script:Index | Where-Object { $_.Kind -eq 'Tab' -and $_.Title -eq 'Hardware tests' }

        $tab.Page       | Should -Be 'Diagnostics'
        $tab.TabControl | Should -Be 'DiagnosticsTabs'
    }

    It 'indexes report entries with the tab and list they are in' {

        $report = $script:Index | Where-Object { $_.Kind -eq 'Report' -and $_.Title -eq 'Sign-in and management' }

        $report.Tab    | Should -Be 'Reports'
        $report.List   | Should -Be 'DiagnosticChoices'
        $report.Choice | Should -Be 'Sign-in and management'
    }

    It 'indexes tools with the list they are in, and not the category headings' {

        $tool = $script:Index | Where-Object { $_.Kind -eq 'Tool' -and $_.Title -eq 'Regex' }

        $tool.Page   | Should -Be 'SecurityTools'
        $tool.List   | Should -Be 'ToolChoices'
        $tool.Choice | Should -Be 'Regex'

        @($script:Index | Where-Object { $_.Page -eq 'SecurityTools' -and $_.Title -ceq 'SECURITY' }).Count | Should -Be 0
    }

    It 'indexes every catalog it promises' {

        foreach ($kind in @('Fix', 'Tweak', 'Application', 'Topic', 'Command', 'Hardware test', 'Investigation', 'Action', 'Tool')) {
            @($script:Index | Where-Object { $_.Kind -eq $kind }).Count | Should -BeGreaterThan 0 -Because $kind
        }

        $commandCount = 0

        foreach ($vendor in (Import-TkCatalog -Name 'vendor-commands').vendors) {
            foreach ($section in $vendor.sections) {
                $commandCount += @($section.commands).Count
            }
        }

        @($script:Index | Where-Object { $_.Kind -eq 'Command' }).Count | Should -Be $commandCount
    }

    It 'points every search box and list it names at a control in the markup' {

        $markup = Get-TkMainWindowXaml

        foreach ($name in @($script:Index | ForEach-Object { $_.SearchBox; $_.List; $_.TabControl } | Where-Object { $_ } | Sort-Object -Unique)) {
            $markup | Should -Match ('x:Name="{0}"' -f [regex]::Escape($name)) -Because $name
        }
    }

    It 'puts the page before the long lists when the words match both' {

        $hits = @(Find-TkSearchEntry -Index $script:Index -Query 'network')

        $hits[0].Kind  | Should -Be 'Page'
        $hits[0].Title | Should -Be 'Network'
    }

    It 'requires every word, in any order' {

        $hits = @(Find-TkSearchEntry -Index $script:Index -Query 'spooler print')

        $hits.Count | Should -BeGreaterThan 0
        foreach ($hit in $hits) {
            ('{0} {1} {2}' -f $hit.Title, $hit.Kind, $hit.Detail) | Should -Match 'spooler'
        }
    }

    It 'finds a vendor command and fills the vendor search box with it' {

        $hit = @(Find-TkSearchEntry -Index $script:Index -Query 'show vlan brief') | Where-Object { $_.Kind -eq 'Command' } | Select-Object -First 1

        $hit.Page      | Should -Be 'VendorCommands'
        $hit.SearchBox | Should -Be 'VendorSearch'
    }

    It 'returns nothing for an empty query, and caps the results' {

        @(Find-TkSearchEntry -Index $script:Index -Query '   ').Count | Should -Be 0
        @(Find-TkSearchEntry -Index $script:Index -Query 'e' -Limit 5).Count | Should -Be 5
    }
}

Describe 'Intervention journal' {

    BeforeAll {
        # Written to a temporary folder, never to the journal of the account
        # that runs the tests.
        $script:RealDataRoot = (Get-TkContext).DataRoot
        (Get-TkContext).DataRoot = Join-Path $TestDrive 'data'
    }

    AfterAll {
        (Get-TkContext).DataRoot = $script:RealDataRoot
    }

    It 'tells a change from a check: <Category> is <Kind>' -TestCases @(
        @{ Category = 'Tweaks';      Kind = 'Change' }
        @{ Category = 'Remediation'; Kind = 'Change' }
        @{ Category = 'Audit';       Kind = 'Check' }
        @{ Category = 'Bundle';      Kind = 'Collection' }
        @{ Category = 'Unheard of';  Kind = 'Other' }
    ) {
        param($Category, $Kind)

        Get-TkJournalKind -Category $Category | Should -Be $Kind
    }

    It 'reads back what it wrote, under this session' {

        Add-TkJournalEntry -Name 'Apply: Example tweak' -Category 'Tweaks' -DurationMs 42

        $entry = @(Get-TkJournalEntry -Since (Get-Date).AddMinutes(-1)) | Where-Object { $_.Name -eq 'Apply: Example tweak' }

        $entry.Kind       | Should -Be 'Change'
        $entry.Outcome    | Should -Be 'Done'
        $entry.Session    | Should -Be $script:TkSessionId
        $entry.Time       | Should -BeOfType ([datetime])
        $entry.DurationMs | Should -Be 42
    }

    It 'journals every operation timed through Stop-TkOperation' {

        $stopwatch = Start-TkOperation -Name 'Reset the example' -Category 'Fixes'
        Stop-TkOperation -Name 'Reset the example' -Stopwatch $stopwatch -Category 'Fixes' -Success $false

        $entry = @(Get-TkJournalEntry) | Where-Object { $_.Name -eq 'Reset the example' }

        $entry.Outcome | Should -Be 'Failed'
        $entry.Kind    | Should -Be 'Change'
    }

    It 'keeps only the session asked for, and skips a line cut short' {

        $path = Join-Path (Get-TkJournalFolder) ('journal-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd'))

        $other = New-TkJournalEntry -Name 'Earlier session' -Category 'Software'
        $other.Session = 'another-session'

        Add-Content -LiteralPath $path -Value ($other | ConvertTo-Json -Compress)
        Add-Content -LiteralPath $path -Value '{"Time":"2026-09-13T10:00'

        $mine = @(Get-TkJournalEntry -Session $script:TkSessionId)

        @($mine | Where-Object { $_.Name -eq 'Earlier session' }).Count | Should -Be 0
        @(Get-TkJournalEntry | Where-Object { $_.Name -eq 'Earlier session' }).Count | Should -Be 1
    }

    It 'turns the period chosen into a start and a session' {

        $now = [datetime] '2026-09-13 15:30'

        (Get-TkJournalPeriod -Choice 'Today' -Now $now).Since        | Should -Be ([datetime] '2026-09-13')
        (Get-TkJournalPeriod -Choice 'Last 7 days' -Now $now).Since  | Should -Be ([datetime] '2026-09-07')
        (Get-TkJournalPeriod -Choice 'This session' -Now $now).Session | Should -Be $script:TkSessionId
    }

    Context 'Report' {

        BeforeAll {
            $script:Report = [pscustomobject] @{
                Computer    = 'PC-<b>01</b>'
                GeneratedAt = [datetime] '2026-09-13 16:00'
                Toolkit     = 'Toolkit 1.0.0 (test)'
                Technician  = 'Kyllian'
                Ticket      = 'INC-1234'
                Notes       = "User reported blue screens.`n<script>alert(1)</script>"
                Period      = 'Today'
                Identity    = [pscustomobject] @{ Manufacturer = 'ASUS'; Model = 'Z790'; SerialNumber = 'SN1'; LoggedOnUser = 'PC\User'; Domain = 'WORKGROUP' }
                OS          = [pscustomobject] @{ Caption = 'Windows 11 Pro'; DisplayVersion = '25H2'; Build = '26200'; UptimeText = '0d 5h' }
                Tiles       = @([pscustomobject] @{ Title = 'Devices'; Value = '1 failing'; Severity = 'Fail'; Detail = 'Code 43' })
                Audit       = [pscustomobject] @{
                    Score    = [pscustomobject] @{ Score = 72; Passed = 20; Failed = 2; Warnings = 3; NotAssessed = 1 }
                    Findings = @([pscustomobject] @{ Id = 'ENC-001'; Name = 'Drive encryption'; Status = 'Fail'; Detail = 'C: is not encrypted' })
                }
                Entries     = @([pscustomobject] @{ Time = [datetime] '2026-09-13 15:10'; Kind = 'Change'; Name = 'Run the System File Checker'; Outcome = 'Done' })
            }

            $script:Html = ConvertTo-TkInterventionHtml -Report $script:Report
        }

        It 'encodes every value it was given, notes and computer name included' {

            $script:Html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
            $script:Html | Should -Match 'PC-&lt;b&gt;01&lt;/b&gt;'
            $script:Html | Should -Not -Match '<script'
        }

        It 'is one file, with nothing loaded from anywhere else' {
            $script:Html | Should -Not -Match '<link|<img|<iframe|\ssrc=|https?://'
        }

        It 'writes one row per machine fact, with its label and its whole value' {

            # A list of inline arrays is flattened by PowerShell, and the first
            # version printed each fact as a single letter.
            $script:Html | Should -Match '<tr><td>Manufacturer and model</td><td>ASUS Z790</td></tr>'
            $script:Html | Should -Match '<tr><td>Windows</td><td>Windows 11 Pro 25H2, build 26200</td></tr>'
            $script:Html | Should -Match '<tr><td>Serial number</td><td>SN1</td></tr>'
        }

        It 'carries the ticket, the health, the audit and what was done' {

            foreach ($expected in @('INC-1234', '1 failing', '72 of 100', 'ENC-001', 'Run the System File Checker')) {
                $script:Html | Should -Match ([regex]::Escape($expected))
            }
        }

        It 'says so when nothing was done and no audit was run' {

            $empty = $script:Report.PSObject.Copy()
            $empty.Entries = @()
            $empty.Audit   = $null

            $html = ConvertTo-TkInterventionHtml -Report $empty

            $html | Should -Match 'No operation was run through the toolkit'
            $html | Should -Not -Match 'Security audit</h2>'
        }
    }
}

Describe 'Switch port discovery' {

    BeforeAll {

        # Frames are built from their fields rather than pasted as hex, so the
        # lengths are computed and a test cannot pass on a miscounted byte.
        function Join-TestByte {
            param([object[]] $Part)
            $list = New-Object System.Collections.Generic.List[byte]
            foreach ($piece in $Part) { foreach ($value in @($piece)) { $list.Add([byte] $value) } }
            return , $list.ToArray()
        }

        function Get-TestAscii {
            param([string] $Text)
            return , [System.Text.Encoding]::ASCII.GetBytes($Text)
        }

        function New-TestLldpTlv {
            param([int] $Type, [byte[]] $Value)
            $word = ($Type -shl 9) -bor $Value.Length
            return , (Join-TestByte @(($word -shr 8), ($word -band 0xFF), $Value))
        }

        function New-TestCdpTlv {
            param([int] $Type, [byte[]] $Value)
            $length = $Value.Length + 4
            return , (Join-TestByte @(($Type -shr 8), ($Type -band 0xFF), ($length -shr 8), ($length -band 0xFF), $Value))
        }

        $lldpBody = Join-TestByte @(
            (New-TestLldpTlv 1 (Join-TestByte @(0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE)))
            (New-TestLldpTlv 2 (Join-TestByte @(0x05, (Get-TestAscii 'Gi1/0/12'))))
            (New-TestLldpTlv 3 (Join-TestByte @(0x00, 0x78)))
            (New-TestLldpTlv 4 (Get-TestAscii 'Office 2.14'))
            (New-TestLldpTlv 5 (Get-TestAscii 'SW-CORE-01'))
            (New-TestLldpTlv 6 (Get-TestAscii 'Aruba 2930F'))
            (New-TestLldpTlv 7 (Join-TestByte @(0x00, 0x14, 0x00, 0x14)))
            (New-TestLldpTlv 8 (Join-TestByte @(0x05, 0x01, 10, 0, 1, 5, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00)))
            (New-TestLldpTlv 127 (Join-TestByte @(0x00, 0x80, 0xC2, 0x01, 0x00, 20)))
            # LLDP-MED voice policy: tagged, VLAN 30, priority 5, DSCP 46.
            (New-TestLldpTlv 127 (Join-TestByte @(0x00, 0x12, 0xBB, 0x02, 0x01, 0x40, 0x3D, 0x6E)))
            (0x00, 0x00)
        )

        $script:LldpFrame = Join-TestByte @(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0xCC, $lldpBody)
        $script:TaggedLldpFrame = Join-TestByte @(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x81, 0x00, 0x00, 0x0A, 0x88, 0xCC, $lldpBody)

        $cdpBody = Join-TestByte @(
            (0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00)
            (0x02, 0xB4, 0x00, 0x00)
            (New-TestCdpTlv 0x0001 (Get-TestAscii 'SW-ACCESS-2'))
            (New-TestCdpTlv 0x0002 (Join-TestByte @(0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0xCC, 0x00, 0x04, 10, 0, 2, 10)))
            (New-TestCdpTlv 0x0003 (Get-TestAscii 'GigabitEthernet0/5'))
            (New-TestCdpTlv 0x0006 (Get-TestAscii 'cisco WS-C2960'))
            (New-TestCdpTlv 0x000A (Join-TestByte @(0x00, 40)))
            (New-TestCdpTlv 0x000E (Join-TestByte @(0x01, 0x00, 50)))
        )

        $script:CdpFrame = Join-TestByte @(0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC, 0x00, 0x11, 0x22, 0x33, 0x44, 0x66,
                                           ($cdpBody.Length -shr 8), ($cdpBody.Length -band 0xFF), $cdpBody)

        $script:ArpFrame = Join-TestByte @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x77, 0x08, 0x06, (0..27 | ForEach-Object { 0 }))

        # A pcapng file the way pktmon writes one: section header, interface
        # description, then one enhanced packet block per frame.
        function ConvertTo-TestPcapNg {
            param([object[]] $Frame)

            $stream = New-Object System.IO.MemoryStream
            $writer = New-Object System.IO.BinaryWriter($stream)

            $writer.Write([uint32] 0x0A0D0D0A); $writer.Write([uint32] 28); $writer.Write([uint32] 0x1A2B3C4D)
            $writer.Write([uint16] 1); $writer.Write([uint16] 0); $writer.Write([int64] -1); $writer.Write([uint32] 28)

            $writer.Write([uint32] 1); $writer.Write([uint32] 20); $writer.Write([uint16] 1); $writer.Write([uint16] 0)
            $writer.Write([uint32] 0); $writer.Write([uint32] 20)

            foreach ($data in $Frame) {
                $padded = [int] ([math]::Ceiling($data.Length / 4) * 4)
                $length = 32 + $padded
                $writer.Write([uint32] 6); $writer.Write([uint32] $length); $writer.Write([uint32] 0)
                $writer.Write([uint32] 0); $writer.Write([uint32] 0)
                $writer.Write([uint32] $data.Length); $writer.Write([uint32] $data.Length)
                $writer.Write([byte[]] $data); $writer.Write((New-Object byte[] ($padded - $data.Length)))
                $writer.Write([uint32] $length)
            }

            $writer.Flush()
            return , $stream.ToArray()
        }
    }

    It 'reads the switch, port, VLANs and management address from LLDP' {

        $neighbour = ConvertFrom-TkLldpFrame -Frame $script:LldpFrame

        $neighbour.SwitchName        | Should -Be 'SW-CORE-01'
        $neighbour.Port              | Should -Be 'Gi1/0/12'
        $neighbour.PortDescription   | Should -Be 'Office 2.14'
        $neighbour.Vlan              | Should -Be 20
        $neighbour.VoiceVlan         | Should -Be 30
        $neighbour.ManagementAddress | Should -Be '10.0.1.5'
        $neighbour.ChassisId         | Should -Be '00-AA-BB-CC-DD-EE'
        $neighbour.Capabilities      | Should -Be 'Bridge, Router'
        $neighbour.Platform          | Should -Be 'Aruba 2930F'
    }

    It 'reads LLDP behind an 802.1Q tag' {
        (ConvertFrom-TkLldpFrame -Frame $script:TaggedLldpFrame).SwitchName | Should -Be 'SW-CORE-01'
    }

    It 'reads the switch, port, VLANs and management address from CDP' {

        $neighbour = ConvertFrom-TkCdpFrame -Frame $script:CdpFrame

        $neighbour.SwitchName        | Should -Be 'SW-ACCESS-2'
        $neighbour.Port              | Should -Be 'GigabitEthernet0/5'
        $neighbour.Vlan              | Should -Be 40
        $neighbour.VoiceVlan         | Should -Be 50
        $neighbour.ManagementAddress | Should -Be '10.0.2.10'
        $neighbour.Platform          | Should -Be 'cisco WS-C2960'
    }

    It 'ignores any other frame' {

        ConvertFrom-TkLldpFrame -Frame $script:ArpFrame | Should -BeNullOrEmpty
        ConvertFrom-TkCdpFrame  -Frame $script:ArpFrame | Should -BeNullOrEmpty
        ConvertFrom-TkCdpFrame  -Frame $script:LldpFrame | Should -BeNullOrEmpty
        ConvertFrom-TkLldpFrame -Frame $script:CdpFrame | Should -BeNullOrEmpty
    }

    It 'extracts every frame from a pcapng capture' {

        $frames = @(ConvertFrom-TkPcapNg -Bytes (ConvertTo-TestPcapNg @($script:LldpFrame, $script:ArpFrame)))

        $frames.Count | Should -Be 2
        [Convert]::ToBase64String($frames[0].Data) | Should -Be ([Convert]::ToBase64String($script:LldpFrame))
    }

    It 'stops at a block cut short, without throwing' {

        # The comma keeps the frame one element: @() would unroll its bytes.
        $bytes = ConvertTo-TestPcapNg (, $script:LldpFrame)
        $cut   = New-Object byte[] ($bytes.Length - 10)
        [Array]::Copy($bytes, $cut, $cut.Length)

        { ConvertFrom-TkPcapNg -Bytes $cut } | Should -Not -Throw
        @(ConvertFrom-TkPcapNg -Bytes $cut).Count | Should -Be 0
    }

    It 'keeps one record per protocol, switch and port' {

        $frames = @(ConvertFrom-TkPcapNg -Bytes (ConvertTo-TestPcapNg @($script:LldpFrame, $script:LldpFrame, $script:CdpFrame, $script:ArpFrame)))

        $neighbours = @(Get-TkSwitchNeighbour -Frame $frames)

        $neighbours.Count | Should -Be 2
        @($neighbours | ForEach-Object { $_.Protocol }) | Should -Be @('LLDP', 'CDP')
    }

    It 'writes what was heard, and why nothing may have been' {

        $found = [pscustomobject] @{ Status = 'Found'; Seconds = 65; Frames = 3; Error = ''; Neighbours = @(ConvertFrom-TkLldpFrame -Frame $script:LldpFrame) }
        $text  = Format-TkSwitchDiscoveryText -Discovery $found

        $text | Should -Match 'SW-CORE-01'
        $text | Should -Match 'Gi1/0/12 \(Office 2.14\)'
        $text | Should -Match 'VLAN\s+: 20'

        Format-TkSwitchDiscoveryText -Discovery ([pscustomobject] @{ Status = 'Silent'; Seconds = 65; Frames = 0; Error = ''; Neighbours = @() }) |
            Should -Match 'Wi-Fi'
    }

    It 'does not start Packet Monitor without administrator rights' {

        Mock Assert-TkElevated { $false }
        Mock Start-TkOperation { throw 'must not be reached' }

        (Invoke-TkSwitchPortDiscovery -Seconds 5).Status | Should -Be 'NotElevated'
    }

    It 'reads a capture that heard nothing as no frame, not as a failure' {

        # The first run on a real machine: pktmon wrote a pcapng with its
        # headers and no packet, and the empty result became a null that failed
        # the whole discovery.
        $path = Join-Path $TestDrive 'silent.pcapng'
        [System.IO.File]::WriteAllBytes($path, (ConvertTo-TestPcapNg -Frame @()))

        $capture = Read-TkSwitchCapture -Path $path

        $capture.Frames            | Should -Be 0
        @($capture.Neighbours).Count | Should -Be 0
    }

    It 'reads a missing capture file as no frame' {
        (Read-TkSwitchCapture -Path (Join-Path $TestDrive 'never-written.pcapng')).Frames | Should -Be 0
    }

    It 'finds the neighbour in a capture file that has one' {

        $path = Join-Path $TestDrive 'heard.pcapng'
        [System.IO.File]::WriteAllBytes($path, (ConvertTo-TestPcapNg @($script:ArpFrame, $script:CdpFrame)))

        $capture = Read-TkSwitchCapture -Path $path

        $capture.Frames                  | Should -Be 2
        @($capture.Neighbours)[0].Port   | Should -Be 'GigabitEthernet0/5'
    }
}

Describe 'Logging from background workers' {

    AfterEach {
        $script:TkWorker = $null
    }

    It 'keeps worker lines out of the console window, which a selection would freeze' {

        Mock Write-Host { }

        $script:TkWorker = $true
        Write-TkLog -Level Information -Category 'Test' -Message 'From a worker'

        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'still writes to the console from the interface thread' {

        Mock Write-Host { }

        Write-TkLog -Level Information -Category 'Test' -Message 'From the interface'

        Should -Invoke Write-Host -Times 1 -Exactly
    }
}

Describe 'Performance' {

    It 'groups process instances by application and shares the processor time out' {

        $rows = @(
            [pscustomobject] @{ Name = 'brave';   PercentProcessorTime = 320; WorkingSetPrivate = 300MB; IODataBytesPersec = 2KB }
            [pscustomobject] @{ Name = 'brave#1'; PercentProcessorTime = 160; WorkingSetPrivate = 200MB; IODataBytesPersec = 1KB }
            [pscustomobject] @{ Name = 'Idle';    PercentProcessorTime = 2800; WorkingSetPrivate = 0; IODataBytesPersec = 0 }
            [pscustomobject] @{ Name = '_Total';  PercentProcessorTime = 3200; WorkingSetPrivate = 0; IODataBytesPersec = 0 }
        )

        $apps = @(Group-TkProcessUsage -Process $rows -LogicalProcessors 32)

        $apps.Count            | Should -Be 1
        $apps[0].Name          | Should -Be 'brave'
        $apps[0].Instances     | Should -Be 2
        $apps[0].CpuPercent    | Should -Be 15
        $apps[0].MemoryMB      | Should -Be 500
        $apps[0].IoKBps        | Should -Be 3
    }

    It 'finds where Task Manager records a startup entry for <Location>' -TestCases @(
        @{ Location = 'Startup';                                                               Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
        @{ Location = 'Common Startup';                                                        Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
        @{ Location = 'HKU\S-1-5-21-1-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
        @{ Location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                    Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
        @{ Location = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run';        Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
        @{ Location = 'Somewhere else';                                                        Key = '' }
    ) {
        param($Location, $Key)

        Get-TkStartupApprovalKey -Location $Location | Should -Be $Key
    }

    It 'reads the startup switch from the lowest bit, and an absent value as enabled' {

        Test-TkStartupApproved -Value $null                          | Should -BeTrue
        Test-TkStartupApproved -Value ([byte[]] (0x02, 0, 0, 0))     | Should -BeTrue
        Test-TkStartupApproved -Value ([byte[]] (0x06, 0, 0, 0))     | Should -BeTrue
        Test-TkStartupApproved -Value ([byte[]] (0x03, 0, 0, 0))     | Should -BeFalse
        Test-TkStartupApproved -Value ([byte[]] (0x07, 0, 0, 0))     | Should -BeFalse
    }

    It 'reads a start up and what slowed it from the Diagnostics-Performance events' {

        $boot = ConvertFrom-TkBootEvent -Id 100 -Data @{ BootTime = '95000'; MainPathBootTime = '70000'; BootPostBootTime = '25000'; BootIsDegradation = 'true' }

        $boot.MainPathMs | Should -Be 70000
        $boot.Degraded   | Should -BeTrue

        $driver = ConvertFrom-TkBootEvent -Id 102 -Data @{ Name = 'rtcore64.sys'; FriendlyName = 'MSI Afterburner driver'; TotalTime = '4200'; DegradationTime = '3100' }

        $driver.Kind          | Should -Be 'Driver'
        $driver.Name          | Should -Be 'MSI Afterburner driver'
        $driver.DegradationMs | Should -Be 3100

        ConvertFrom-TkBootEvent -Id 999 -Data @{} | Should -BeNullOrEmpty
    }

    Context 'Judgement' {

        BeforeAll {
            $script:Busy = [pscustomobject] @{
                CpuPercent = 92; MemoryUsedPercent = 98; MemoryTotalGB = 8; MemoryFreeGB = 0.2; CommitPercent = 95
                Applications = @(
                    [pscustomobject] @{ Name = 'Teams'; Instances = 6; CpuPercent = 40; MemoryMB = 2100; IoKBps = 10 }
                    [pscustomobject] @{ Name = 'chrome'; Instances = 20; CpuPercent = 25; MemoryMB = 3100; IoKBps = 50 }
                )
                Disks = @([pscustomobject] @{ Name = '0 C:'; BusyPercent = 96; Queue = 4.5; ReadKBps = 900; WriteKBps = 12000 })
            }
        }

        It 'flags a busy processor and names what uses it' {

            $cpu = Get-TkPerformanceFinding -Snapshot $script:Busy | Where-Object { $_.Heading -like 'Processor*' }

            $cpu.Severity | Should -Be 'Warning'
            $cpu.Detail   | Should -Match '^Teams 40%'
        }

        It 'writes decimals with a point whatever the display language' {

            $culture = [System.Threading.Thread]::CurrentThread.CurrentCulture

            try {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('fr-FR')

                $snapshot = $script:Busy.PSObject.Copy()
                $snapshot.Applications = @([pscustomobject] @{ Name = 'brave'; Instances = 16; CpuPercent = 2.3; MemoryMB = 1596; IoKBps = 0 })

                $findings = @(Get-TkPerformanceFinding -Snapshot $snapshot)

                ($findings | Where-Object { $_.Heading -like 'Processor*' }).Detail | Should -Be 'brave 2.3%'
                ($findings | Where-Object { $_.Heading -like 'Memory*' }).Detail    | Should -Match '^0\.2 GB free of 8 GB'
                ($findings | Where-Object { $_.Heading -like 'Disk*' }).Detail      | Should -Match '^Queue 4\.5,'
            }
            finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
            }
        }

        It 'fails memory nearly exhausted, and warns about a busy disk' {

            $findings = @(Get-TkPerformanceFinding -Snapshot $script:Busy)

            ($findings | Where-Object { $_.Heading -like 'Memory*' }).Severity | Should -Be 'Fail'
            ($findings | Where-Object { $_.Heading -like 'Disk 0 C:*' }).Severity | Should -Be 'Warning'
        }

        It 'counts only the startup programs that actually run' {

            $startup = @(1..17 | ForEach-Object { [pscustomobject] @{ Name = "App$_"; Enabled = $true } }) +
                       @(1..5  | ForEach-Object { [pscustomobject] @{ Name = "Off$_"; Enabled = $false } })

            $line = Get-TkPerformanceFinding -Startup $startup | Where-Object { $_.Heading -like '*start with Windows' }

            $line.Heading  | Should -Be '17 program(s) start with Windows'
            $line.Severity | Should -Be 'Warning'
        }

        It 'says start up time needs elevation instead of guessing' {

            $line = Get-TkPerformanceFinding -Boot ([pscustomobject] @{ Available = $false; Boots = @(); Slowdowns = @() })

            $line.Severity | Should -Be 'Info'
            $line.Detail   | Should -Be 'Needs administrator rights'
        }

        It 'judges start up on the time to the desktop, and lists what slowed it' {

            $boot = [pscustomobject] @{
                Available = $true
                Boots     = @(1..5 | ForEach-Object { [pscustomobject] @{ When = (Get-Date).AddDays(-$_); BootMs = 90000; MainPathMs = 75000; PostBootMs = 20000; Degraded = $false } })
                Slowdowns = @([pscustomobject] @{ Kind = 'Application'; Name = 'Steam'; Count = 3; AddedMs = 8000 })
            }

            $findings = @(Get-TkPerformanceFinding -Boot $boot)

            ($findings | Where-Object { $_.Heading -like 'Start up*' }).Severity | Should -Be 'Warning'
            ($findings | Where-Object { $_.Heading -eq 'Application: Steam' }).Detail | Should -Be 'Added 8 s, 3 time(s)'
        }
    }
}

Describe 'Wi-Fi and proxy' {

    BeforeAll {

        # Writes a little endian value into a byte array, the way the Wi-Fi
        # API lays out its structures.
        function Set-WlanTestByte {
            param([byte[]] $Bytes, [int] $Offset, $Value)

            [byte[]] $data = if ($Value -is [byte[]]) { $Value } else { [BitConverter]::GetBytes($Value) }
            [Array]::Copy($data, 0, $Bytes, $Offset, $data.Length)
        }

        function New-ProxyTestBlob {
            param([int] $Flags, [string[]] $Text = @())

            $list = New-Object System.Collections.Generic.List[byte]
            $list.AddRange([BitConverter]::GetBytes([int] 0x46))
            $list.AddRange([BitConverter]::GetBytes([int] 1))
            $list.AddRange([BitConverter]::GetBytes($Flags))

            foreach ($item in $Text) {
                $data = [Text.Encoding]::ASCII.GetBytes($item)
                $list.AddRange([BitConverter]::GetBytes([int] $data.Length))
                $list.AddRange($data)
            }

            return , $list.ToArray()
        }

        function New-WifiTestStatus {
            param($Connection, $AccessPoint, $Networks = @(), $Events = @(), $Radio, [switch] $LocationDenied, [int] $State = 1)

            [pscustomobject] @{
                Available      = $true
                ServiceRunning = $true
                Error          = ''
                Days           = 7
                Interfaces     = @([pscustomobject] @{
                    Guid = [guid]::Empty; Description = 'Wi-Fi'; State = $State; StateName = 'Connected'
                    Radio = $Radio; LocationDenied = [bool] $LocationDenied; Connection = $Connection
                    AccessPoint = $AccessPoint; Rssi = $null; Networks = @($Networks); Events = @($Events)
                })
            }
        }

        function New-WifiTestConnection {
            param([int] $Phy = 10, [int] $Auth = 7, [int] $Cipher = 4, [double] $Rx = 866.7, [double] $Tx = 648.5)

            [pscustomobject] @{
                Ssid = 'Office'; Bssid = 'AA-AA-AA-AA-AA-AA'; PhyType = $Phy; Standard = (Get-TkWlanName -Kind Phy -Value $Phy)
                SignalQuality = 90; RxMbps = $Rx; TxMbps = $Tx; SecurityEnabled = $true; OneXEnabled = $false
                AuthAlgorithm = $Auth; Authentication = (Get-TkWlanName -Kind Authentication -Value $Auth)
                CipherAlgorithm = $Cipher; Cipher = (Get-TkWlanName -Kind Cipher -Value $Cipher)
            }
        }

        function New-WifiTestNetwork {
            param([string] $Ssid = 'Office', [string] $Bssid = 'AA-AA-AA-AA-AA-AA', [int] $Rssi = -50, [int] $Frequency = 5180)

            $channel = Get-TkWifiChannel -FrequencyMHz $Frequency

            [pscustomobject] @{
                Ssid = $Ssid; Bssid = $Bssid; Rssi = $Rssi; Band = $channel.Band; Channel = $channel.Channel
                Standard = '802.11ax (Wi-Fi 6)'; FrequencyMHz = $Frequency
            }
        }
    }

    It 'names the band and channel of <Frequency> MHz' -TestCases @(
        @{ Frequency = 2412; Band = '2.4 GHz'; Channel = 1 }
        @{ Frequency = 2437; Band = '2.4 GHz'; Channel = 6 }
        @{ Frequency = 2484; Band = '2.4 GHz'; Channel = 14 }
        @{ Frequency = 5180; Band = '5 GHz';   Channel = 36 }
        @{ Frequency = 5825; Band = '5 GHz';   Channel = 165 }
        @{ Frequency = 5935; Band = '6 GHz';   Channel = 2 }
        @{ Frequency = 5955; Band = '6 GHz';   Channel = 1 }
        @{ Frequency = 6295; Band = '6 GHz';   Channel = 69 }
        @{ Frequency = 900;  Band = '';        Channel = 0 }
    ) {
        param($Frequency, $Band, $Channel)

        $result = Get-TkWifiChannel -FrequencyMHz $Frequency

        $result.Band    | Should -Be $Band
        $result.Channel | Should -Be $Channel
    }

    It 'decodes the adapters from a WLAN_INTERFACE_INFO_LIST' {

        $guid  = [guid] '835099d0-542e-48d4-bade-8b3bdec58d94'
        $bytes = New-Object byte[] (8 + 532)

        Set-WlanTestByte $bytes 0 1
        Set-WlanTestByte $bytes 8 $guid.ToByteArray()
        Set-WlanTestByte $bytes 24 ([Text.Encoding]::Unicode.GetBytes('Intel(R) Wi-Fi 6E AX210 160MHz'))
        Set-WlanTestByte $bytes 536 4

        $adapters = @(ConvertFrom-TkWlanInterfaceList -Bytes $bytes)

        $adapters.Count          | Should -Be 1
        $adapters[0].Guid        | Should -Be $guid
        $adapters[0].Description | Should -Be 'Intel(R) Wi-Fi 6E AX210 160MHz'
        $adapters[0].StateName   | Should -Be 'Disconnected'
    }

    It 'decodes the current connection, with rates in megabits and names for the security' {

        $bytes = New-Object byte[] 604

        Set-WlanTestByte $bytes 0   1
        Set-WlanTestByte $bytes 8   ([Text.Encoding]::Unicode.GetBytes('Office'))
        Set-WlanTestByte $bytes 520 ([uint32] 6)
        Set-WlanTestByte $bytes 524 ([Text.Encoding]::UTF8.GetBytes('Office'))
        Set-WlanTestByte $bytes 560 ([byte[]] (0x22, 0x66, 0xCF, 0x4E, 0x9C, 0x34))
        Set-WlanTestByte $bytes 568 10
        Set-WlanTestByte $bytes 576 ([uint32] 80)
        Set-WlanTestByte $bytes 580 ([uint32] 866700)
        Set-WlanTestByte $bytes 584 ([uint32] 648500)
        Set-WlanTestByte $bytes 588 1
        Set-WlanTestByte $bytes 596 7
        Set-WlanTestByte $bytes 600 4

        $connection = ConvertFrom-TkWlanConnection -Bytes $bytes

        $connection.StateName      | Should -Be 'Connected'
        $connection.ProfileName    | Should -Be 'Office'
        $connection.Ssid           | Should -Be 'Office'
        $connection.Bssid          | Should -Be '22-66-CF-4E-9C-34'
        $connection.Standard       | Should -Be '802.11ax (Wi-Fi 6)'
        $connection.SignalQuality  | Should -Be 80
        $connection.RxMbps         | Should -Be 866.7
        $connection.TxMbps         | Should -Be 648.5
        $connection.Authentication | Should -Be 'WPA2-Personal'
        $connection.Cipher         | Should -Be 'AES-CCMP'

        ConvertFrom-TkWlanConnection -Bytes (New-Object byte[] 100) | Should -BeNullOrEmpty
    }

    It 'decodes the access points, with a negative signal and the band from the frequency' {

        $bytes = New-Object byte[] (8 + 2 * 360)

        Set-WlanTestByte $bytes 0 ([uint32] $bytes.Length)
        Set-WlanTestByte $bytes 4 ([uint32] 2)

        Set-WlanTestByte $bytes 8   ([uint32] 7)
        Set-WlanTestByte $bytes 12  ([Text.Encoding]::UTF8.GetBytes('Freebox'))
        Set-WlanTestByte $bytes 48  ([byte[]] (0x68, 0xA3, 0x78, 0x76, 0xCD, 0xA0))
        Set-WlanTestByte $bytes 60  7
        Set-WlanTestByte $bytes 64  (-75)
        Set-WlanTestByte $bytes 96  ([uint16] 0x1411)
        Set-WlanTestByte $bytes 100 ([uint32] 2437000)

        Set-WlanTestByte $bytes 368 ([uint32] 12)
        Set-WlanTestByte $bytes 372 ([Text.Encoding]::UTF8.GetBytes('Freebox_6GHz'))
        Set-WlanTestByte $bytes 420 10
        Set-WlanTestByte $bytes 424 (-55)
        Set-WlanTestByte $bytes 460 ([uint32] 6295000)

        $networks = @(ConvertFrom-TkWlanBssList -Bytes $bytes)

        $networks.Count        | Should -Be 2
        $networks[0].Ssid      | Should -Be 'Freebox'
        $networks[0].Bssid     | Should -Be '68-A3-78-76-CD-A0'
        $networks[0].Rssi      | Should -Be -75
        $networks[0].Band      | Should -Be '2.4 GHz'
        $networks[0].Channel   | Should -Be 6
        $networks[0].Protected | Should -BeTrue
        $networks[1].Rssi      | Should -Be -55
        $networks[1].Band      | Should -Be '6 GHz'
        $networks[1].Channel   | Should -Be 69
        $networks[1].Protected | Should -BeFalse
    }

    It 'reads the radio as off only when every PHY is off' {

        $bytes = New-Object byte[] 28

        Set-WlanTestByte $bytes 0  2
        Set-WlanTestByte $bytes 8  1
        Set-WlanTestByte $bytes 12 1
        Set-WlanTestByte $bytes 16 1
        Set-WlanTestByte $bytes 20 1
        Set-WlanTestByte $bytes 24 1

        (ConvertFrom-TkWlanRadioState -Bytes $bytes).SoftwareOff | Should -BeFalse

        Set-WlanTestByte $bytes 8  2
        (ConvertFrom-TkWlanRadioState -Bytes $bytes).SoftwareOff | Should -BeFalse

        Set-WlanTestByte $bytes 20 2
        $radio = ConvertFrom-TkWlanRadioState -Bytes $bytes

        $radio.SoftwareOff | Should -BeTrue
        $radio.HardwareOff | Should -BeFalse
    }

    It 'tells a drop from a disconnection the user or a cable caused' {

        $cable = ConvertFrom-TkWlanEvent -Id 8003 -Data @{ SSID = 'Office'; ReasonCode = '5'; Reason = 'policy' }
        $lost  = ConvertFrom-TkWlanEvent -Id 8003 -Data @{ SSID = 'Office'; ReasonCode = '65539'; Reason = 'lost' }
        $fail  = ConvertFrom-TkWlanEvent -Id 8002 -Data @{ SSID = 'Office'; ReasonCode = '229396'; FailureReason = 'wrong key' }

        $cable.Kind     | Should -Be 'Disconnected'
        $cable.Expected | Should -BeTrue
        $lost.Expected  | Should -BeFalse
        $fail.Kind      | Should -Be 'Failed'
        $fail.Reason    | Should -Be 'wrong key'

        ConvertFrom-TkWlanEvent -Id 11000 -Data @{} | Should -BeNullOrEmpty
    }

    Context 'Wi-Fi judgement' {

        It 'judges a signal of <Rssi> dBm as <Severity>' -TestCases @(
            @{ Rssi = -55; Severity = 'Pass' }
            @{ Rssi = -72; Severity = 'Warning' }
            @{ Rssi = -85; Severity = 'Fail' }
        ) {
            param($Rssi, $Severity)

            $point    = New-WifiTestNetwork -Rssi $Rssi
            $findings = Get-TkWifiFinding -Status (New-WifiTestStatus -Connection (New-WifiTestConnection) -AccessPoint $point -Networks @($point))

            ($findings | Where-Object { $_.Heading -like 'Signal*' }).Severity | Should -Be $Severity
        }

        It 'warns on 2.4 GHz when the same network is offered on a faster band' {

            $point = New-WifiTestNetwork -Frequency 2437
            $fast  = New-WifiTestNetwork -Bssid 'BB-BB-BB-BB-BB-BB' -Frequency 5180

            $band = Get-TkWifiFinding -Status (New-WifiTestStatus -Connection (New-WifiTestConnection) -AccessPoint $point -Networks @($point, $fast)) |
                    Where-Object { $_.Heading -like 'On 2.4 GHz*' }

            $band.Severity | Should -Be 'Warning'
            $band.Heading  | Should -BeLike '*5 GHz*'
        }

        It 'counts overlapping 2.4 GHz channels as crowding, and not channels further away' {

            $point     = New-WifiTestNetwork -Frequency 2437
            $neighbours = @(1..8 | ForEach-Object { New-WifiTestNetwork -Ssid "N$_" -Bssid "0$_-00-00-00-00-00" -Frequency $(if ($_ % 2) { 2427 } else { 2447 }) })
            $far       = New-WifiTestNetwork -Ssid 'Far' -Bssid '09-00-00-00-00-00' -Frequency 2462

            $crowded = Get-TkWifiFinding -Status (New-WifiTestStatus -Connection (New-WifiTestConnection) -AccessPoint $point -Networks (@($point, $far) + $neighbours)) |
                       Where-Object { $_.Heading -like '*crowded*' }

            $crowded.Severity | Should -Be 'Warning'
            $crowded.Detail   | Should -BeLike '8 other*'
        }

        It 'judges the security of <Auth>/<Cipher> as <Severity>' -TestCases @(
            @{ Auth = 1; Cipher = 0; Severity = 'Fail' }
            @{ Auth = 2; Cipher = 1; Severity = 'Fail' }
            @{ Auth = 4; Cipher = 2; Severity = 'Warning' }
            @{ Auth = 7; Cipher = 4; Severity = 'Pass' }
            @{ Auth = 9; Cipher = 4; Severity = 'Pass' }
        ) {
            param($Auth, $Cipher, $Severity)

            $point    = New-WifiTestNetwork
            $security = Get-TkWifiFinding -Status (New-WifiTestStatus -Connection (New-WifiTestConnection -Auth $Auth -Cipher $Cipher) -AccessPoint $point -Networks @($point)) |
                        Where-Object { $_.Heading -match 'Open network|Protected|Enhanced Open' }

            $security.Severity | Should -Be $Severity
        }

        It 'warns on a slow link, with the rate written with a point on a French Windows' {

            $culture = [System.Threading.Thread]::CurrentThread.CurrentCulture

            try {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('fr-FR')

                $point    = New-WifiTestNetwork
                $findings = Get-TkWifiFinding -Status (New-WifiTestStatus -Connection (New-WifiTestConnection -Rx 6.5 -Tx 12) -AccessPoint $point -Networks @($point))
            }
            finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
            }

            $rate = $findings | Where-Object { $_.Heading -like 'Link rate*' }

            $rate.Severity | Should -Be 'Warning'
            $rate.Heading  | Should -BeLike '*6.5 Mbps received*'
        }

        It 'points to the location setting when Windows hides the connection' {

            $findings = Get-TkWifiFinding -Status (New-WifiTestStatus -LocationDenied)

            @($findings | Where-Object { $_.RemediationId -eq 'open-location-privacy' }).Count | Should -Be 1
        }

        It 'counts the drops nobody asked for' {

            $events = @(
                1..5 | ForEach-Object { [pscustomobject] @{ Kind = 'Disconnected'; Expected = $false; Reason = 'lost.'; Ssid = 'Office'; When = Get-Date } }
                1..3 | ForEach-Object { [pscustomobject] @{ Kind = 'Disconnected'; Expected = $true;  Reason = 'cable'; Ssid = 'Office'; When = Get-Date } }
            )

            $drops = Get-TkWifiFinding -Status (New-WifiTestStatus -State 4 -Events $events) | Where-Object { $_.Heading -like '*dropped*' }

            $drops.Severity | Should -Be 'Warning'
            $drops.Heading  | Should -BeLike '*5 time(s) in 7 days'
            $drops.Detail   | Should -Be '"Office"'
            $drops.Note     | Should -BeLike 'Most often: lost (5). Drops*'
        }

        It 'says when the radio is off, and when there is no Wi-Fi at all' {

            $off = Get-TkWifiFinding -Status (New-WifiTestStatus -Radio ([pscustomobject] @{ Phys = 1; SoftwareOff = $true; HardwareOff = $false }))

            $off[0].Heading       | Should -Be 'Wi-Fi is turned off'
            $off[0].RemediationId | Should -Be 'open-wifi-settings'

            (Get-TkWifiFinding -Status ([pscustomobject] @{ Available = $false })).Heading | Should -Be 'No Wi-Fi on this machine'
        }
    }

    It 'reads automatic detection from the bytes the Settings page writes' {

        # The value read on a real machine: version 0x46, counter 2, flags 9.
        $bytes = New-Object byte[] 56
        $bytes[0] = 0x46
        $bytes[4] = 2
        $bytes[8] = 9

        $setting = ConvertFrom-TkProxyBlob -Bytes $bytes

        $setting.Direct      | Should -BeTrue
        $setting.AutoDetect  | Should -BeTrue
        $setting.UseProxy    | Should -BeFalse
        $setting.ProxyServer | Should -Be ''
    }

    It 'reads the proxy, the bypass list and the script, and survives a value cut short' {

        $bytes   = New-ProxyTestBlob -Flags 7 -Text @('proxy.corp.local:3128', '<local>;*.corp.local', 'http://pac.corp.local/proxy.pac')
        $setting = ConvertFrom-TkProxyBlob -Bytes $bytes

        $setting.UseProxy      | Should -BeTrue
        $setting.UseScript     | Should -BeTrue
        $setting.AutoDetect    | Should -BeFalse
        $setting.ProxyServer   | Should -Be 'proxy.corp.local:3128'
        $setting.Bypass        | Should -Be '<local>;*.corp.local'
        $setting.AutoConfigUrl | Should -Be 'http://pac.corp.local/proxy.pac'

        $cut = ConvertFrom-TkProxyBlob -Bytes ([byte[]] $bytes[0..19])

        $cut.UseProxy    | Should -BeTrue
        $cut.ProxyServer | Should -Be ''

        (ConvertFrom-TkProxyBlob -Bytes (New-ProxyTestBlob -Flags 3 -Text @('http=10.0.0.1:8080', ''))).AutoConfigUrl | Should -Be ''
    }

    It 'splits proxy settings into addresses, and never keeps credentials' {

        $single = @(ConvertFrom-TkProxyServerList -Text 'proxy.corp.local:3128')
        $single[0].Host | Should -Be 'proxy.corp.local'
        $single[0].Port | Should -Be 3128

        $schemes = @(ConvertFrom-TkProxyServerList -Text 'http=a.corp:80;https=b.corp:443')
        $schemes.Count       | Should -Be 2
        $schemes[1].Scheme   | Should -Be 'https'
        $schemes[1].Address  | Should -Be 'b.corp:443'

        $url = @(ConvertFrom-TkProxyServerList -Text 'http://user:secret@corp-proxy:8080/')
        $url[0].Host    | Should -Be 'corp-proxy'
        $url[0].Port    | Should -Be 8080

        (@(ConvertFrom-TkProxyServerList -Text '[::1]:8888'))[0].Host | Should -Be '::1'
        (@(ConvertFrom-TkProxyServerList -Text 'proxy'))[0].Port       | Should -Be 80

        Hide-TkProxyCredential -Text 'http://user:secret@corp-proxy:8080' | Should -Be 'http://corp-proxy:8080'
        Hide-TkProxyCredential -Text 'user:secret@corp-proxy:8080'        | Should -Be 'corp-proxy:8080'
        Hide-TkProxyCredential -Text 'corp-proxy:8080'                    | Should -Be 'corp-proxy:8080'
    }

    It 'describes a setting in the order Windows tries it' {

        Format-TkProxyDescription -Setting $null | Should -Be 'Direct, never set'
        Format-TkProxyDescription -Setting (ConvertFrom-TkProxyBlob -Bytes (New-ProxyTestBlob -Flags 1)) | Should -Be 'Direct'
        Format-TkProxyDescription -Setting (ConvertFrom-TkProxyBlob -Bytes (New-ProxyTestBlob -Flags 11 -Text @('proxy:3128', '<local>'))) |
            Should -Be 'Automatic detection, then proxy proxy:3128, not for <local>'
    }

    Context 'Proxy judgement' {

        BeforeAll {

            function New-ProxyTestSetting {
                param($User, $Machine, $Environment = @())

                [pscustomobject] @{ Scope = 'this user'; MachineWide = $false; User = $User; Machine = $Machine; Environment = @($Environment) }
            }

            function New-ProxyTestValue {
                param([int] $Flags = 1, [string] $Server = '', [string] $Url = '')

                ConvertFrom-TkProxyBlob -Bytes (New-ProxyTestBlob -Flags $Flags -Text @($Server, '', $Url))
            }
        }

        It 'passes a machine where nothing uses a proxy' {

            $findings = @(Get-TkProxyFinding -Setting (New-ProxyTestSetting -User (New-ProxyTestValue -Flags 9) -Machine (New-ProxyTestValue)) `
                                             -Probe ([pscustomobject] @{ Targets = @(); WpadChecked = $true; WpadAddresses = @() }))

            $findings.Count       | Should -Be 1
            $findings[0].Severity | Should -Be 'Pass'
        }

        It 'warns when applications go through a program on the machine itself' {

            $finding = Get-TkProxyFinding -Setting (New-ProxyTestSetting -User (New-ProxyTestValue -Flags 3 -Server '127.0.0.1:8888')) |
                       Where-Object { $_.Heading -like 'Applications*' }

            $finding.Severity      | Should -Be 'Warning'
            $finding.Heading       | Should -BeLike '*program on this machine*'
            $finding.RemediationId | Should -Be 'open-proxy-settings'
        }

        It 'fails a proxy or a script that does not answer' {

            $probe = [pscustomobject] @{
                Targets       = @(
                    [pscustomobject] @{ Address = 'proxy.corp.local:3128'; Open = $false; ResponseMs = 2000 }
                    [pscustomobject] @{ Address = 'pac.corp.local:80';     Open = $false; ResponseMs = 2000 }
                )
                WpadChecked   = $false
                WpadAddresses = @()
            }

            $findings = @(Get-TkProxyFinding -Setting (New-ProxyTestSetting -User (New-ProxyTestValue -Flags 7 -Server 'proxy.corp.local:3128' -Url 'http://pac.corp.local/proxy.pac')) -Probe $probe)

            @($findings | Where-Object { $_.Severity -eq 'Fail' }).Count | Should -Be 2
            ($findings | Where-Object { $_.Heading -like 'Proxy proxy.corp.local*' }).RemediationId | Should -Be 'open-proxy-settings'
        }

        It 'warns when services go through a proxy that applications do not use' {

            $finding = Get-TkProxyFinding -Setting (New-ProxyTestSetting -User (New-ProxyTestValue) -Machine (New-ProxyTestValue -Flags 3 -Server 'old-proxy:8080')) |
                       Where-Object { $_.Heading -like 'Services*' }

            $finding.Severity | Should -Be 'Warning'
        }

        It 'notes that services go direct while applications use a proxy' {

            $finding = Get-TkProxyFinding -Setting (New-ProxyTestSetting -User (New-ProxyTestValue -Flags 3 -Server 'proxy:3128') -Machine (New-ProxyTestValue)) |
                       Where-Object { $_.Heading -eq 'Services go direct' }

            $finding.Severity | Should -Be 'Info'
        }
    }

    It 'opens only settings pages the remediation allow list accepts' {

        $table = Get-TkRemediationTable

        foreach ($id in @('open-wifi-settings', 'open-proxy-settings', 'open-location-privacy')) {
            $table.ContainsKey($id)                           | Should -BeTrue -Because $id
            Test-TkRemediationTarget -Target $table[$id].Target | Should -BeTrue -Because $id
        }
    }

    It 'wraps a long state in a bounded column instead of squeezing the title' {

        # A failure reason Windows wrote once took the whole width of a card
        # and folded its title one word per line.
        $state    = 'Sorry, we could not connect you because no connectable access point was visible, ' * 2
        $document = New-TkFlowDocument

        Add-TkFindingCard -Document $document -Severity 'Info' -Title '1 failed connection attempt(s) in 7 days' -State $state

        $found = New-Object System.Collections.Generic.List[object]
        $walk  = {
            param($node)

            foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($node)) {

                if ($child -is [System.Windows.Controls.TextBox] -and $child.Text -eq $state) {
                    $found.Add($child)
                }

                if ($child -is [System.Windows.DependencyObject]) {
                    & $walk $child
                }
            }
        }

        & $walk $document

        $found.Count           | Should -Be 1
        $found[0].TextWrapping | Should -Be ([System.Windows.TextWrapping]::Wrap)
        $found[0].MaxWidth     | Should -BeLessThan 400
    }
}

Describe 'Software lifecycle' {

    BeforeAll {
        $script:Lifecycle    = Import-TkCatalog -Name 'software-lifecycle'
        $script:LifecycleNow = [datetime]::new(2026, 9, 14)

        function New-LifecycleTestFact {
            param([int] $Build, [string] $EditionId, [string] $InstallationType = 'Client')
            [pscustomobject] @{ Caption = 'Windows'; EditionId = $EditionId; InstallationType = $InstallationType; DisplayVersion = ''; Build = $Build }
        }
    }

    Context 'Catalog' {

        It 'dates every cycle as yyyy-MM-dd, compiles every pattern and names each product once' {

            $dates    = New-Object System.Collections.Generic.List[object]
            $patterns = New-Object System.Collections.Generic.List[string]

            foreach ($product in @($script:Lifecycle.products)) {

                $product.id        | Should -Match '^[a-z0-9-]+$'
                $product.risk      | Should -BeIn @('High', 'Medium', 'Low')
                $product.reference | Should -Match '^https://'
                @($product.cycles).Count | Should -BeGreaterThan 0

                $patterns.Add($product.match)

                if ($product.PSObject.Properties['exclude']) { $patterns.Add($product.exclude) }

                foreach ($cycle in @($product.cycles)) {

                    $cycle.cycle | Should -Not -BeNullOrEmpty

                    foreach ($field in @('name', 'version')) {
                        if ($cycle.PSObject.Properties[$field]) { $patterns.Add($cycle.$field) }
                    }

                    if ($null -ne $cycle.end) { $dates.Add($cycle.end) }
                }
            }

            foreach ($entry in @($script:Lifecycle.windows)) {

                $entry.channel | Should -BeIn @('Client', 'Ltsc', 'Server')

                foreach ($property in $entry.ends.PSObject.Properties) {
                    $property.Name | Should -BeIn @('Consumer', 'Enterprise', 'Ltsc', 'IotLtsc', 'Server')
                    $dates.Add($property.Value)
                }
            }

            $dates.Count | Should -BeGreaterThan 100

            foreach ($date in $dates) {
                { ConvertTo-TkLifecycleDate -Value $date } | Should -Not -Throw -Because ([string] $date)
            }

            foreach ($pattern in $patterns) {
                { [void] [regex]::new($pattern) } | Should -Not -Throw -Because $pattern
            }

            @($script:Lifecycle.products | ForEach-Object { $_.id } | Sort-Object -Unique).Count | Should -Be @($script:Lifecycle.products).Count
        }
    }

    Context 'Judgement' {

        It 'warns within six months, fails a high risk product past its date, and only informs for a low risk one' {

            (Get-TkLifecycleState -End '2026-09-14' -Now $script:LifecycleNow).Status          | Should -Be 'Ending'
            (Get-TkLifecycleState -End '2026-09-14' -Now $script:LifecycleNow).DaysLeft        | Should -Be 0
            (Get-TkLifecycleState -End '2026-09-13' -Now $script:LifecycleNow).Severity        | Should -Be 'Fail'
            (Get-TkLifecycleState -End '2026-09-13' -Risk Medium -Now $script:LifecycleNow).Severity | Should -Be 'Warning'
            (Get-TkLifecycleState -End '2026-09-13' -Risk Low -Now $script:LifecycleNow).Severity    | Should -Be 'Info'
            (Get-TkLifecycleState -End '2027-09-14' -Now $script:LifecycleNow).Severity        | Should -Be 'Pass'
            (Get-TkLifecycleState -End $null -Now $script:LifecycleNow).Status                 | Should -Be 'Supported'
            (Get-TkLifecycleState -End ([datetime]::new(2026, 10, 13, 0, 0, 0)) -Now $script:LifecycleNow).DaysLeft | Should -Be 29
        }
    }

    Context 'Windows' {

        It 'follows the calendar of <EditionId> (<InstallationType>): <Audience>' -TestCases @(
            @{ EditionId = 'Professional';          InstallationType = 'Client';      Audience = 'Consumer' }
            @{ EditionId = 'Core';                  InstallationType = 'Client';      Audience = 'Consumer' }
            @{ EditionId = 'ProfessionalEducation'; InstallationType = 'Client';      Audience = 'Consumer' }
            @{ EditionId = 'Enterprise';            InstallationType = 'Client';      Audience = 'Enterprise' }
            @{ EditionId = 'Education';             InstallationType = 'Client';      Audience = 'Enterprise' }
            @{ EditionId = 'EnterpriseS';           InstallationType = 'Client';      Audience = 'Ltsc' }
            @{ EditionId = 'IoTEnterpriseS';        InstallationType = 'Client';      Audience = 'IotLtsc' }
            @{ EditionId = 'ServerStandard';        InstallationType = 'Server';      Audience = 'Server' }
            @{ EditionId = 'ServerDatacenter';      InstallationType = 'Server Core'; Audience = 'Server' }
        ) {
            param($EditionId, $InstallationType, $Audience)

            (Get-TkWindowsAudience -EditionId $EditionId -InstallationType $InstallationType).Audience | Should -Be $Audience
        }

        It 'judges build <Build> <EditionId> as <Status> until <Ends>' -TestCases @(
            @{ Build = 26200; EditionId = 'Professional';   InstallationType = 'Client'; Status = 'Supported'; Ends = '2027-10-12' }
            @{ Build = 26100; EditionId = 'Professional';   InstallationType = 'Client'; Status = 'Ending';    Ends = '2026-10-13' }
            @{ Build = 26100; EditionId = 'Enterprise';     InstallationType = 'Client'; Status = 'Supported'; Ends = '2027-10-12' }
            @{ Build = 26100; EditionId = 'EnterpriseS';    InstallationType = 'Client'; Status = 'Supported'; Ends = '2029-10-09' }
            @{ Build = 26100; EditionId = 'ServerStandard'; InstallationType = 'Server'; Status = 'Supported'; Ends = '2034-10-10' }
            @{ Build = 19045; EditionId = 'Professional';   InstallationType = 'Client'; Status = 'Ended';     Ends = '2025-10-14' }
            @{ Build = 19044; EditionId = 'EnterpriseS';    InstallationType = 'Client'; Status = 'Ending';    Ends = '2027-01-12' }
            @{ Build = 18363; EditionId = 'Enterprise';     InstallationType = 'Client'; Status = 'Ended';     Ends = '2022-05-10' }
            @{ Build = 14393; EditionId = 'ServerStandard'; InstallationType = 'Server'; Status = 'Ending';    Ends = '2027-01-12' }
            @{ Build = 99999; EditionId = 'Professional';   InstallationType = 'Client'; Status = 'Unknown';   Ends = '' }
        ) {
            param($Build, $EditionId, $InstallationType, $Status, $Ends)

            $row = Resolve-TkWindowsLifecycle -Fact (New-LifecycleTestFact -Build $Build -EditionId $EditionId -InstallationType $InstallationType) `
                                              -Catalog $script:Lifecycle -Now $script:LifecycleNow

            $row.Status | Should -Be $Status
            $row.Ends   | Should -Be $Ends
        }

        It 'turns the Windows row into an audit finding' {

            $ended   = Resolve-TkWindowsLifecycle -Fact (New-LifecycleTestFact -Build 19045 -EditionId 'Professional') -Catalog $script:Lifecycle -Now $script:LifecycleNow
            $current = Resolve-TkWindowsLifecycle -Fact (New-LifecycleTestFact -Build 26200 -EditionId 'Professional') -Catalog $script:Lifecycle -Now $script:LifecycleNow
            $unknown = Resolve-TkWindowsLifecycle -Fact (New-LifecycleTestFact -Build 99999 -EditionId 'Professional') -Catalog $script:Lifecycle -Now $script:LifecycleNow

            $finding = ConvertTo-TkWindowsSupportFinding -Lifecycle $ended

            $finding.Status         | Should -Be 'Fail'
            $finding.Detail         | Should -BeLike '*Extended Security Updates*'
            $finding.Recommendation | Should -Not -BeNullOrEmpty

            (ConvertTo-TkWindowsSupportFinding -Lifecycle $current).Status | Should -Be 'Pass'
            (ConvertTo-TkWindowsSupportFinding -Lifecycle $unknown).Status | Should -Be 'Info'
            $unknown.Note | Should -BeLike '*newer than every release*'
        }
    }

    Context 'Programs' {

        It 'keeps the programs Installed apps would show' {

            $rows = @(Select-TkInstalledProgram -Entry @(
                @{ DisplayName = 'Visible'; DisplayVersion = '1.0' }
                @{ DisplayName = 'Visible'; DisplayVersion = '1.0' }
                @{ DisplayName = 'Component'; SystemComponent = 1 }
                @{ DisplayName = 'KB5000000'; ParentKeyName = 'Office' }
                @{ DisplayName = 'Security Update for Something (KB1)' }
                @{ DisplayName = 'Patch'; ReleaseType = 'Hotfix' }
                @{ DisplayName = '' }
                @{ DisplayVersion = '2.0' }
            ))

            $rows.Count   | Should -Be 1
            $rows[0].Name | Should -Be 'Visible'
        }

        It 'recognises programs, groups their copies, and judges each by its risk' {

            $programs = @(
                [pscustomobject] @{ Name = 'Microsoft Office Professional Plus 2021 - fr-fr';               Version = '16.0.20326.20144' }
                [pscustomobject] @{ Name = 'Microsoft Office Proofing Tools 2016 - English';                Version = '16.0.4266.1001' }
                [pscustomobject] @{ Name = 'Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219';   Version = '10.0.40219' }
                [pscustomobject] @{ Name = 'Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219';   Version = '10.0.40219' }
                [pscustomobject] @{ Name = 'Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247'; Version = '14.51.36247.0' }
                [pscustomobject] @{ Name = 'Python 3.9.13 (64-bit)';                                        Version = '3.9.13150.0' }
                [pscustomobject] @{ Name = 'Python Launcher';                                               Version = '3.14.6150.0' }
                [pscustomobject] @{ Name = 'Microsoft Windows Desktop Runtime 10.0.12 (x64)';               Version = '10.0.12.50000' }
                [pscustomobject] @{ Name = 'Adobe Acrobat DC';                                              Version = '20.006.20042' }
                [pscustomobject] @{ Name = 'Adobe Flash Player 32 NPAPI';                                   Version = '32.0.0.465' }
                [pscustomobject] @{ Name = 'Notepad++ (64-bit x64)';                                        Version = '8.6' }
            )

            $rows = @(Resolve-TkProgramLifecycle -Program $programs -Catalog $script:Lifecycle -Now $script:LifecycleNow)
            $by   = @{}

            foreach ($row in $rows) {
                $by['{0} {1}' -f $row.ProductId, $row.Cycle] = $row
            }

            $rows.Count | Should -Be 7

            $by['office 2021'].Status   | Should -Be 'Ending'
            $by['office 2021'].DaysLeft | Should -Be 29

            $by['vcredist 2010'].Status              | Should -Be 'Ended'
            $by['vcredist 2010'].Severity            | Should -Be 'Info'
            @($by['vcredist 2010'].Installed).Count  | Should -Be 2
            $by['vcredist 2015 and later (v14)'].Severity | Should -Be 'Pass'

            $by['python 3.9'].Severity      | Should -Be 'Warning'
            $by['dotnet 10 (LTS)'].Ends     | Should -Be '2028-11-14'
            $by['acrobat continuous (DC)'].Status | Should -Be 'Outdated'
            $by['flash all versions'].Severity    | Should -Be 'Fail'

            $rows[0].Severity | Should -Be 'Fail'
        }

        It 'says a version is not in the catalog rather than guessing' {

            $row = @(Resolve-TkProgramLifecycle -Program @([pscustomobject] @{ Name = 'PowerShell 7.5.1.0-x64'; Version = '7.5.1.0' }) `
                                               -Catalog $script:Lifecycle -Now $script:LifecycleNow)[0]

            $row.Status   | Should -Be 'Unknown'
            $row.Severity | Should -Be 'Info'
            $row.Note     | Should -BeLike '*not in the catalog*'
        }
    }
}

Describe 'E-mail header analysis' {

    BeforeAll {
        $script:Headers = @'
Received: from AM0PR01MB1234.eurprd01.prod.outlook.com (2603:10a6:208:1::10) by
 AM9PR01MB5678.eurprd01.prod.outlook.com with HTTPS; Tue, 15 Sep 2026 10:05:40
 +0000
Authentication-Results: spf=softfail (sender IP is 198.51.100.23)
 smtp.mailfrom=mailer.example.net; dkim=none (message not signed)
 header.d=none;dmarc=fail action=quarantine header.from=contoso-bank.com;compauth=fail reason=000
Received: from mail.example.net (198.51.100.23) by
 AM0PR01MB1234.mail.protection.outlook.com (10.167.1.10) with Microsoft SMTP Server;
 Tue, 15 Sep 2026 10:05:38 +0000
Received: from [192.168.1.20] (unknown [203.0.113.77]) by mail.example.net
 (Postfix) with ESMTPSA id 4F2; Tue, 15 Sep 2026 08:01:02 +0000 (UTC)
From: "support@contoso-bank.com" <alerts@mailer.example.net>
Reply-To: <verify@secure-login.example.org>
Return-Path: bounce@mailer.example.net
To: jane.doe@fabrikam.com
Subject: Your account is locked
Date: Tue, 15 Sep 2026 10:00:59 +0200
Message-ID: <abc123@mailer.example.net>

Dear customer, click here.
'@
    }

    It 'unfolds continued lines and stops at the body' {

        $fields = @(ConvertFrom-TkMailHeader -Text $script:Headers)

        ($fields | Where-Object Name -eq 'Received').Count | Should -Be 3
        ($fields | Where-Object Name -eq 'Authentication-Results').Value | Should -Match 'dmarc=fail action=quarantine'
        @($fields | Where-Object { $_.Value -match 'click here' }).Count | Should -Be 0
    }

    It 'reads mail dates with their zone, comments and two digit years' {

        $date = ConvertTo-TkMailDate -Text 'Mon, 14 Sep 2026 10:11:12 +0200 (CEST)'
        $date.Offset.TotalHours | Should -Be 2
        $date.UtcDateTime       | Should -Be ([datetime]::new(2026, 9, 14, 8, 11, 12))

        (ConvertTo-TkMailDate -Text '1 Sep 26 08:00 GMT').UtcDateTime | Should -Be ([datetime]::new(2026, 9, 1, 8, 0, 0))
        ConvertTo-TkMailDate -Text 'yesterday' | Should -BeNullOrEmpty
    }

    It 'orders the route from the oldest hop, with the delay each server added' {

        $report = Get-TkMailHeaderReport -Text $script:Headers

        @($report.Hops).Count     | Should -Be 3
        $report.Hops[0].By        | Should -Be 'mail.example.net'
        $report.Hops[0].FromIp    | Should -Be '203.0.113.77'
        $report.Hops[1].Delay.TotalMinutes | Should -BeGreaterThan 120
        $report.Hops[2].Delay.TotalSeconds | Should -Be 2
        $report.OriginatingIp     | Should -Be '203.0.113.77'
    }

    It 'reads the verdict of the receiving system and names what looks like phishing' {

        $report = Get-TkMailHeaderReport -Text $script:Headers

        $report.Authentication.Spf      | Should -Be 'softfail'
        $report.Authentication.Dmarc    | Should -Be 'fail'
        $report.Authentication.MailFrom | Should -Be 'mailer.example.net'

        $warnings = $report.Warnings -join ' | '

        $warnings | Should -Match 'Replies go to verify@secure-login.example.org'
        $warnings | Should -Match 'display name shows support@contoso-bank.com'
        $warnings | Should -Match 'DMARC gave fail'
        $warnings | Should -Match 'held the message 2 h'

        (Format-TkMailHeaderReport -Report $report) -join "`n" | Should -Match 'Route, 3 hop\(s\), oldest first'
    }
}

Describe 'Mail DNS records' {

    BeforeAll {
        $script:Zone = @{
            'contoso.com|MX'                        = @('10 contoso-com.mail.protection.outlook.com')
            'contoso.com|TXT'                       = @('MS=ms12345', 'v=spf1 include:spf.protection.outlook.com include:_spf.mailer.example ip4:203.0.113.10 ~all')
            'spf.protection.outlook.com|TXT'        = @('v=spf1 include:spfa.protection.outlook.com -all')
            'spfa.protection.outlook.com|TXT'       = @('v=spf1 ip4:40.92.0.0/15 -all')
            '_spf.mailer.example|TXT'               = @('v=spf1 a mx include:_spf2.mailer.example ?all')
            '_spf2.mailer.example|TXT'              = @('v=spf1 ip4:198.51.100.0/24 -all')
            '_dmarc.contoso.com|TXT'                = @('v=DMARC1; p=none; rua=mailto:dmarc@contoso.com')
            'selector1._domainkey.contoso.com|TXT'  = @(('v=DKIM1; k=rsa; p={0}' -f [Convert]::ToBase64String([byte[]]::new(294))))
            'selector2._domainkey.contoso.com|TXT'  = @(('v=DKIM1; k=rsa; p={0}' -f [Convert]::ToBase64String([byte[]]::new(162))))
        }

        $script:FakeResolver = {
            param($name, $type)
            $key = '{0}|{1}' -f $name, $type
            if ($script:Zone.ContainsKey($key)) { $script:Zone[$key] } else { @() }
        }
    }

    It 'parses an SPF record and counts the lookups it costs by itself' {

        $spf = ConvertFrom-TkSpfRecord -Text 'v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com mx a:web.contoso.com/24 redirect=_spf.contoso.com -all'

        $spf.Valid        | Should -BeTrue
        $spf.All          | Should -Be '-'
        $spf.LocalLookups | Should -Be 4
        (@($spf.Includes) -join ',') | Should -Be 'spf.protection.outlook.com'
        $spf.Redirect     | Should -Be '_spf.contoso.com'
    }

    It 'counts lookups through nested includes, and flags a record over the limit' {

        (Measure-TkSpfLookup -Domain 'contoso.com' -Resolver $script:FakeResolver).Lookups | Should -Be 6

        $deep = @{}
        foreach ($level in 0..11) { $deep[('l{0}.example|TXT' -f $level)] = @(('v=spf1 include:l{0}.example -all' -f ($level + 1))) }
        $deepResolver = { param($name, $type) $key = '{0}|{1}' -f $name, $type; if ($deep.ContainsKey($key)) { $deep[$key] } else { @() } }.GetNewClosure()

        (Measure-TkSpfLookup -Domain 'l0.example' -Resolver $deepResolver).Lookups | Should -BeGreaterThan 10
    }

    It 'reads DMARC policies and estimates DKIM key sizes' {

        $dmarc = ConvertFrom-TkDmarcRecord -Text 'v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:r@contoso.com'

        $dmarc.Valid           | Should -BeTrue
        $dmarc.Policy          | Should -Be 'quarantine'
        $dmarc.SubdomainPolicy | Should -Be 'reject'
        $dmarc.Percent         | Should -Be 50

        (ConvertFrom-TkDkimRecord -Text ('v=DKIM1; k=rsa; p={0}' -f [Convert]::ToBase64String([byte[]]::new(294)))).KeyBits | Should -Be 2048
        (ConvertFrom-TkDkimRecord -Text 'v=DKIM1; p=').Revoked | Should -BeTrue
    }

    It 'judges the records of a domain' {

        $report   = Get-TkMailDnsReport -Domain 'Contoso.com.' -Resolver $script:FakeResolver
        $findings = ($report.Findings | ForEach-Object { '{0}: {1}' -f $_.Severity, $_.Text }) -join ' | '

        $report.Domain     | Should -Be 'contoso.com'
        $report.SpfLookups | Should -Be 6
        @($report.Dkim).Count | Should -Be 2

        $findings | Should -Match 'Pass: ~all'
        $findings | Should -Match 'Warning: DMARC policy none'
        $findings | Should -Match 'Warning: DKIM selector selector2 has a 1024-bit key'
        $findings | Should -Match 'Pass: The SPF record needs 6 of the 10'

        (Get-TkMailDnsReport -Domain 'not a domain' -Resolver $script:FakeResolver).Findings[0].Severity | Should -Be 'Fail'
        (Format-TkMailDnsReport -Report $report) -join "`n" | Should -Match 'DKIM     selector1: RSA, about 2048 bits'
    }
}

Describe 'Certificate decoding' {

    BeforeAll {
        $script:Now = [datetime]::new(2026, 9, 15, 12, 0, 0)

        $key     = [System.Security.Cryptography.RSA]::Create(2048)
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
            'CN=www.contoso.com, O=Contoso', $key,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        $names = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        $names.AddDnsName('www.contoso.com')
        $names.AddDnsName('contoso.com')
        $request.CertificateExtensions.Add($names.Build())

        $usages = New-Object System.Security.Cryptography.OidCollection
        [void] $usages.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.1')))
        $request.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($usages, $false)))

        $script:CertificateDer = $request.CreateSelfSigned([datetimeoffset]::new(2026, 9, 1, 0, 0, 0, [timespan]::Zero), [datetimeoffset]::new(2026, 12, 1, 0, 0, 0, [timespan]::Zero)).RawData
        $script:RequestDer     = $request.CreateSigningRequest()

        $script:Pem = {
            param($label, $bytes)
            "-----BEGIN $label-----`n" + ([Convert]::ToBase64String($bytes) -replace '(.{64})', "`$1`n") + "`n-----END $label-----"
        }
    }

    It 'finds every PEM block of a chain' {

        $text   = (& $script:Pem 'CERTIFICATE' $script:CertificateDer) + "`n" + (& $script:Pem 'CERTIFICATE' $script:CertificateDer)
        $blocks = @(Split-TkPemBlock -Text $text)

        $blocks.Count    | Should -Be 2
        $blocks[0].Label | Should -Be 'CERTIFICATE'
        $blocks[0].Bytes.Length | Should -Be $script:CertificateDer.Length
    }

    It 'describes a certificate: names, key, purposes, validity and fingerprints' {

        $info = @(Get-TkCertificateItem -Text (& $script:Pem 'CERTIFICATE' $script:CertificateDer) -Now $script:Now)[0]

        $info.Kind             | Should -Be 'Certificate'
        (@($info.SubjectAltNames) -join ',')  | Should -Be 'www.contoso.com,contoso.com'
        $info.KeyAlgorithm     | Should -Be 'RSA'
        $info.KeySize          | Should -Be 2048
        (@($info.EnhancedKeyUsage) -join ',') | Should -Be 'Server authentication'
        $info.DaysRemaining    | Should -Be 76
        $info.Status           | Should -Be 'Valid'
        $info.SelfSigned       | Should -BeTrue
        $info.Sha256           | Should -Match '^[0-9A-F]{64}$'

        (Get-TkCertificateItem -Text (& $script:Pem 'CERTIFICATE' $script:CertificateDer) -Now ([datetime]::new(2027, 1, 1)))[0].Status | Should -Be 'Expired'
    }

    It 'decodes a certificate request with the names it asks for' {

        $info = @(Get-TkCertificateItem -Text (& $script:Pem 'CERTIFICATE REQUEST' $script:RequestDer))[0]

        $info.Kind            | Should -Be 'Request'
        $info.Subject         | Should -Match 'CN=www.contoso.com'
        $info.KeySize         | Should -Be 2048
        (@($info.SubjectAltNames) -join ',') | Should -Be 'www.contoso.com,contoso.com'
    }

    It 'reads a DER file, and never decodes a private key' {

        @(Get-TkCertificateItem -Bytes $script:CertificateDer -Now $script:Now)[0].Kind | Should -Be 'Certificate'

        $key = @(Get-TkCertificateItem -Text "-----BEGIN PRIVATE KEY-----`nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC`n-----END PRIVATE KEY-----")[0]

        $key.Kind     | Should -Be 'PrivateKey'
        $key.Warnings | Should -Match 'not decoded'

        (Format-TkCertificateItem -Item @(Get-TkCertificateItem -Bytes $script:CertificateDer -Now $script:Now)) -join "`n" | Should -Match 'Names        www.contoso.com, contoso.com'
    }

    Context 'Format conversion' {

        BeforeAll {
            $script:Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $script:CertificateDer)
        }

        It 'encodes an object identifier as DER' {

            # rsaEncryption, 1.2.840.113549.1.1.1, is 06 09 2A 86 48 86 F7 0D 01 01 01.
            $bytes = ConvertTo-TkDerOid -Oid '1.2.840.113549.1.1.1'
            (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join '') | Should -Be '06092A864886F70D010101'
        }

        It 'encodes a DER length in short and long form' {

            # Under 128 the length is one byte; at 200 it is 0x81 0xC8.
            (New-TkDerTlv -Tag 0x04 -Content ([byte[]] (1..4)))[1]        | Should -Be 4
            $long = New-TkDerTlv -Tag 0x04 -Content ([byte[]] (1..200))
            $long[1] | Should -Be 0x81
            $long[2] | Should -Be 0xC8
        }

        It 'converts a certificate to PEM that reads back to the same certificate' {

            $pem   = ConvertTo-TkCertificateFormat -Certificate @($script:Cert) -Format 'Pem'
            $pem   | Should -Match '-----BEGIN CERTIFICATE-----'

            # Every Base64 line folds at 64 characters.
            @($pem -split "`n" | Where-Object { $_ -notmatch '-----' -and $_.Trim() -and $_.Length -gt 64 }).Count | Should -Be 0

            $back = @(Get-TkCertificateChain -Text $pem)
            $back[0].Thumbprint | Should -Be $script:Cert.Thumbprint
        }

        It 'converts a certificate to one Base64 DER line' {

            $der = ConvertTo-TkCertificateFormat -Certificate @($script:Cert) -Format 'DerBase64'
            $der | Should -Be ([Convert]::ToBase64String($script:Cert.RawData))
        }

        It 'extracts the public key as a SubjectPublicKeyInfo PEM' {

            $pem = ConvertTo-TkCertificateFormat -Certificate @($script:Cert) -Format 'PublicKey'
            $pem | Should -Match '-----BEGIN PUBLIC KEY-----'

            $body  = ($pem -replace '-----[^-]+-----', '') -replace '\s', ''
            $bytes = [Convert]::FromBase64String($body)

            $bytes[0] | Should -Be 0x30                        # a DER SEQUENCE
            (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join '') | Should -Match '2A864886F70D010101'  # rsaEncryption

            # Where the runtime can export it itself, the bytes must be identical.
            if ($script:Cert.PublicKey.PSObject.Methods['ExportSubjectPublicKeyInfo']) {
                [Convert]::ToBase64String($bytes) | Should -Be ([Convert]::ToBase64String($script:Cert.PublicKey.ExportSubjectPublicKeyInfo()))
            }
        }

        It 'splits a PKCS #7 chain into its certificates' {

            $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $collection.Add($script:Cert) | Out-Null
            $collection.Add($script:Cert) | Out-Null

            $pkcs7 = $collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)

            @(Get-TkCertificateChain -Bytes $pkcs7).Count | Should -Be 2
        }

        It 'reads a certificate from a chain and ignores a private key block' {

            $text = (& $script:Pem 'CERTIFICATE' $script:CertificateDer) +
                    "`n-----BEGIN PRIVATE KEY-----`nMIIEvQIBADANBgkqhkiG9w0BAQEF`n-----END PRIVATE KEY-----"

            $chain = @(Get-TkCertificateChain -Text $text)
            $chain.Count        | Should -Be 1
            $chain[0].Thumbprint | Should -Be $script:Cert.Thumbprint
        }
    }
}

Describe 'Hidden characters' {

    It 'raises nothing on ordinary text, accents included' {

        $text = 'A plain sentence.' + [char] 0x00E9 + [char] 0x00E0 + 'tre naive, coeur, ' + [char] 0x00FC + 'ber.'
        @(Get-TkHiddenCharacterFinding -Text $text).Count | Should -Be 0
    }

    It 'finds one of each kind, and names it' {

        # A Cyrillic a, a zero-width space, a no-break space, a right-to-left
        # override and a bell control, one after the other.
        $text = 'p' + [char] 0x0430 + 'ypal' + [char] 0x200B + 'x' + [char] 0x00A0 + 'y' + [char] 0x202E + 'z' + [char] 0x0007

        $findings = @(Get-TkHiddenCharacterFinding -Text $text)
        ($findings | ForEach-Object { $_.Category }) | Should -Be @('Confusable', 'Zero-width', 'Unusual space', 'Bidirectional', 'Control')

        $cyrillic = $findings | Where-Object { $_.Code -eq 'U+0430' }
        $cyrillic.Category   | Should -Be 'Confusable'
        $cyrillic.Confusable | Should -Be 'a'

        ($findings | Where-Object { $_.Code -eq 'U+202E' }).Name | Should -Be 'RIGHT-TO-LEFT OVERRIDE'
    }

    It 'reports the line and column of a character' {

        $text = "clean line" + "`n" + "hidden" + [char] 0x200B + "here"
        $finding = @(Get-TkHiddenCharacterFinding -Text $text)[0]

        $finding.Line   | Should -Be 2
        $finding.Column | Should -Be 7
    }

    It 'does not flag or break on an astral emoji' {

        # A surrogate pair is one code point over two chars; it must be stepped
        # over cleanly and, being ordinary, reported as nothing.
        $text = 'ok ' + [System.Char]::ConvertFromUtf32(0x1F600) + ' done'
        @(Get-TkHiddenCharacterFinding -Text $text).Count | Should -Be 0
    }

    It 'maps the common confusables' {

        $map = Get-TkConfusableMap
        $map[0x0430].Latin  | Should -Be 'a'          # Cyrillic small a
        $map[0x0430].Script | Should -Be 'Cyrillic'
        $map[0x039F].Latin  | Should -Be 'O'          # Greek capital omicron
        $map[0xFF21].Latin  | Should -Be 'A'          # full-width A
        $map.ContainsKey([int] [char] 'a') | Should -BeFalse   # a real ASCII a is not a confusable
    }

    Context 'Report' {

        It 'says so plainly when the text is clean' {
            (Format-TkHiddenCharacterReport -Text 'nothing to see here') -join "`n" |
                Should -Match 'No hidden or deceptive characters found'
        }

        It 'prompts when there is nothing pasted' {
            (Format-TkHiddenCharacterReport -Text '') -join "`n" | Should -Match 'Paste some text'
        }

        It 'marks each character in place, look-alikes with their ASCII letter' {

            $text   = 'p' + [char] 0x0430 + 'y' + [char] 0x200B + 'z'
            $report = (Format-TkHiddenCharacterReport -Text $text) -join "`n"

            $report | Should -Match '2 suspicious character'
            $report | Should -Match 'p\[U\+0430->a\]y\[U\+200B\]z'
        }
    }
}

Describe 'SID resolver' {

    It 'names a well-known SID and takes it apart' {
        $report = Get-TkSidReport -Text 'S-1-5-18'
        $report.Kind                    | Should -Be 'Sid'
        $report.Name                    | Should -Be 'Local System'
        $report.Structure.AuthorityName | Should -Be 'NT Authority'
    }

    It 'reads the domain and RID of a domain SID, and names the RID' {
        $report = Get-TkSidReport -Text 'S-1-5-21-1004336348-1177238915-682003330-512'
        $report.Name             | Should -Be 'Domain Admins'
        $report.Structure.Rid    | Should -Be '512'
        $report.Structure.Domain | Should -Be 'S-1-5-21-1004336348-1177238915-682003330'
    }

    It 'resolves the English well-known names offline, whatever the OS language' {
        (Get-TkSidReport -Text 'Everyone').Sid               | Should -Be 'S-1-1-0'
        (Get-TkSidReport -Text 'SYSTEM').Sid                 | Should -Be 'S-1-5-18'
        (Get-TkSidReport -Text 'BUILTIN\Administrators').Sid | Should -Be 'S-1-5-32-544'
        (ConvertTo-TkAccountSid -Account 'Authenticated Users') | Should -Be 'S-1-5-11'
    }

    It 'says so when an account cannot be resolved' {
        (Get-TkSidReport -Text 'CONTOSO\NoSuchUser987654321').Kind | Should -Be 'Unresolved'
    }

    It 'prompts when nothing is pasted' {
        (Format-TkSidReport -Text '') -join "`n" | Should -Match 'Paste a SID'
    }
}

Describe 'XML tool' {

    BeforeAll {
        $script:Xml = '<?xml version="1.0"?><catalog><book id="1"><title>PowerShell</title></book><book id="2"><title>XML</title></book></catalog>'
    }

    It 'formats an XML document, keeping its declaration' {
        $formatted = Invoke-TkXmlOperation -Text $script:Xml -Operation 'Format'
        $formatted | Should -Match '^<\?xml version="1.0"\?>'
        $formatted | Should -Match "`n  <book id=`"1`">"
    }

    It 'minifies away the insignificant whitespace' {
        Invoke-TkXmlOperation -Text "<a>  <b>1</b>  </a>" -Operation 'Minify' | Should -Be '<a><b>1</b></a>'
    }

    It 'passes a well-formed document and locates the fault in a bad one' {
        Invoke-TkXmlOperation -Text $script:Xml -Operation 'Validate' | Should -Be 'Well formed.'
        Invoke-TkXmlOperation -Text '<a><b></a>' -Operation 'Validate' | Should -Match 'Not well formed. Line 1, position 9'
    }

    It 'runs an XPath query, returning elements as markup and attributes as values' {
        $elements = Invoke-TkXmlOperation -Text $script:Xml -Operation 'XPath' -XPath '//title'
        $elements | Should -Match '2 match'
        $elements | Should -Match '<title>PowerShell</title>'

        Invoke-TkXmlOperation -Text $script:Xml -Operation 'XPath' -XPath '//book/@id' | Should -Match 'id="1"'
    }

    It 'reports no match and a bad expression without throwing' {
        Invoke-TkXmlOperation -Text $script:Xml -Operation 'XPath' -XPath '//author' | Should -Match 'No node matched'
        Invoke-TkXmlOperation -Text $script:Xml -Operation 'XPath' -XPath '//[bad'   | Should -Match 'not a valid XPath'
    }

    It 'prompts when nothing is pasted' {
        Invoke-TkXmlOperation -Text '' -Operation 'Format' | Should -Match 'Paste an XML document'
    }
}

Describe 'Text normalizer' {

    It 'converts mixed line endings to the chosen one and counts them' {
        $result = Get-TkTextNormalization -Text "a`r`nb`nc`rd" -LineEnding 'LF'
        $result.Text | Should -Be "a`nb`nc`nd"
        ($result.Summary -join ' ') | Should -Match '1 CRLF, 1 LF, 1 CR -> LF'
    }

    It 'gives CRLF when asked' {
        (Get-TkTextNormalization -Text "a`nb" -LineEnding 'CRLF').Text | Should -Be "a`r`nb"
    }

    It 'trims trailing spaces and tabs, and reports how many lines' {
        $result = Get-TkTextNormalization -Text "a   `nb`t`nc" -LineEnding 'LF' -TrimTrailing $true
        $result.Text | Should -Be "a`nb`nc"
        ($result.Summary -join ' ') | Should -Match 'Trimmed trailing whitespace on 2 line'
    }

    It 'turns tabs into spaces at the chosen width' {
        (Get-TkTextNormalization -Text "`ta" -Tabs 'ToSpaces' -TabWidth 4 -TrimTrailing $false).Text | Should -Be '    a'
    }

    It 'turns a leading run of spaces into a tab' {
        (Get-TkTextNormalization -Text '    a' -Tabs 'ToTabs' -TabWidth 4).Text | Should -Be "`ta"
    }

    It 'strips a leading byte order mark' {
        $bom    = [char] 0xFEFF
        $result = Get-TkTextNormalization -Text ($bom + 'hello') -StripBom $true
        $result.Text | Should -Be 'hello'
        ($result.Summary -join ' ') | Should -Match 'Byte order mark removed'
    }

    It 'leaves the byte order mark when asked to keep it' {
        $bom = [char] 0xFEFF
        (Get-TkTextNormalization -Text ($bom + 'hello') -StripBom $false).Text[0] | Should -Be $bom
    }
}

Describe 'User-Agent parser' {

    It 'reads <Browser> <Os> <Device> from the string' -TestCases @(
        @{ Ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'; Browser = 'Chrome'; Os = 'Windows'; Device = 'Desktop' }
        @{ Ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'; Browser = 'Edge'; Os = 'Windows'; Device = 'Desktop' }
        @{ Ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'; Browser = 'Safari'; Os = 'iOS'; Device = 'Mobile' }
        @{ Ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'; Browser = 'Firefox'; Os = 'Linux'; Device = 'Desktop' }
        @{ Ua = 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'; Browser = 'Chrome'; Os = 'Android'; Device = 'Mobile' }
    ) {
        param($Ua, $Browser, $Os, $Device)
        $info = Get-TkUserAgentInfo -Text $Ua
        $info.Browser | Should -Be $Browser
        $info.Os      | Should -Be $Os
        $info.Device  | Should -Be $Device
    }

    It 'names the engine, Blink for Chromium and Gecko for Firefox' {
        (Get-TkUserAgentInfo -Text 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36').Engine | Should -Be 'Blink'
        (Get-TkUserAgentInfo -Text 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0').Engine | Should -Be 'Gecko'
    }

    It 'reads the versions, translating the Windows number' {
        $info = Get-TkUserAgentInfo -Text 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        $info.BrowserVersion | Should -Be '120.0.0.0'
        $info.OsVersion      | Should -Be '10 or 11'
    }

    It 'tells a bot and a command line tool apart from a browser' {
        (Get-TkUserAgentInfo -Text 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)').Device | Should -Be 'Bot'
        $curl = Get-TkUserAgentInfo -Text 'curl/8.4.0'
        $curl.Browser | Should -Be 'curl'
        $curl.Device  | Should -Be 'Tool'
    }

    It 'prompts when nothing is pasted' {
        (Format-TkUserAgentReport -Text '') -join "`n" | Should -Match 'Paste a User-Agent'
    }
}

Describe 'Secret scanner' {

    BeforeAll {
        $script:SecretBlob = @'
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
github_token = ghp_16C7e42F292c6912E7710c838347Ae178B4a
DB_PASSWORD = SuperSecret123!
API_KEY = changeme
placeholder = ${env:TOKEN}
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEF
-----END RSA PRIVATE KEY-----
'@
    }

    It 'names the token and password kinds' {
        $types = @((Get-TkSecretFinding -Text $script:SecretBlob) | ForEach-Object { $_.Type })
        $types | Should -Contain 'AWS access key ID'
        $types | Should -Contain 'GitHub token'
        $types | Should -Contain 'Password or secret'
        $types | Should -Contain 'Private key block'
    }

    It 'skips obvious placeholders' {
        $findings = Get-TkSecretFinding -Text $script:SecretBlob
        @($findings | Where-Object { $_.Value -eq 'changeme' })     | Should -BeNullOrEmpty
        @($findings | Where-Object { $_.Value -match '\$\{' })      | Should -BeNullOrEmpty
    }

    It 'masks the secret so the report does not carry it' {
        $report = (Format-TkSecretReport -Text $script:SecretBlob) -join "`n"
        $report | Should -Not -Match 'AKIAIOSFODNN7EXAMPLE'
        $report | Should -Not -Match 'SuperSecret123'
        $report | Should -Match 'AKIA'   # the head is kept to recognise it
    }

    It 'keeps a passphrase-style value out of the report' {
        Protect-TkSecretValue -Value 'abcdefghijklmnop' | Should -Not -Match 'defghijklm'
    }

    It 'says so plainly on clean text, and prompts when empty' {
        (Format-TkSecretReport -Text 'just ordinary text, nothing to hide') -join "`n" | Should -Match 'No secret found'
        (Format-TkSecretReport -Text '') -join "`n" | Should -Match 'Paste a config'
    }
}

Describe 'INI and .env parser' {

    BeforeAll {
        $script:IniBlob = @'
; a comment
looseKey = above any section
[database]
Host = db.local
port : 5432
Password = S3cr3tP@ssw0rd123
Password = second-one
this line is broken
'@

        $script:EnvBlob = @'
export API_KEY="abcdef1234567890abcdef"
DB_PASSWORD=hunter2   # trailing comment
PLAIN=hello world
'@
    }

    It 'tells INI from .env by the section header' {
        Get-TkConfigFormat -Text $script:IniBlob | Should -Be 'Ini'
        Get-TkConfigFormat -Text $script:EnvBlob | Should -Be 'Env'
    }

    It 'reads both = and : as INI separators, and keeps the section' {
        $pairs = @(ConvertFrom-TkConfigText -Text $script:IniBlob -Format Ini | Where-Object { $_.Kind -eq 'Pair' })

        ($pairs | Where-Object { $_.Key -eq 'port' }).Value    | Should -Be '5432'
        ($pairs | Where-Object { $_.Key -eq 'Host' }).Section  | Should -Be 'database'
    }

    It 'drops the surrounding quotes and an unquoted inline comment (.env)' {
        $pairs = @(ConvertFrom-TkConfigText -Text $script:EnvBlob -Format Env | Where-Object { $_.Kind -eq 'Pair' })

        ($pairs | Where-Object { $_.Key -eq 'API_KEY' }).Value     | Should -Be 'abcdef1234567890abcdef'
        ($pairs | Where-Object { $_.Key -eq 'API_KEY' }).Exported  | Should -BeTrue
        ($pairs | Where-Object { $_.Key -eq 'DB_PASSWORD' }).Value | Should -Be 'hunter2'
        ($pairs | Where-Object { $_.Key -eq 'PLAIN' }).Value       | Should -Be 'hello world'
    }

    It 'masks the values whose key names a secret' {
        $report = (Format-TkConfigReport -Text $script:IniBlob) -join "`n"
        $report | Should -Not -Match 'S3cr3tP@ssw0rd123'
        $report | Should -Match 'host = db.local'   # a plain value is left alone
    }

    It 'reveals the secrets only when asked' {
        (Format-TkConfigReport -Text $script:EnvBlob -Reveal) -join "`n" | Should -Match 'hunter2'
        (Format-TkConfigReport -Text $script:EnvBlob) -join "`n"         | Should -Not -Match 'hunter2'
    }

    It 'flags a duplicate key, a key above the first section, and a broken line' {
        $report = (Format-TkConfigReport -Text $script:IniBlob) -join "`n"
        $report | Should -Match "duplicate key 'Password'"
        $report | Should -Match "key 'looseKey' sits above the first"
        $report | Should -Match 'this line is broken'
    }

    It 'writes .env as a flat JSON object, masked' {
        $json = ConvertTo-TkConfigJson -Text $script:EnvBlob | ConvertFrom-Json
        $json.PLAIN       | Should -Be 'hello world'
        $json.DB_PASSWORD | Should -Not -Be 'hunter2'
    }

    It 'writes INI as sections of keys, with the last duplicate winning' {
        $json = ConvertTo-TkConfigJson -Text $script:IniBlob -Reveal | ConvertFrom-Json
        $json.database.Host     | Should -Be 'db.local'
        $json.database.Password | Should -Be 'second-one'
    }

    It 'prompts on empty input' {
        (Format-TkConfigReport -Text '') -join "`n" | Should -Match 'Paste an INI or a .env'
        ConvertTo-TkConfigJson -Text ''             | Should -Be '{}'
    }
}

Describe 'LDAP filter builder' {

    It 'turns an attribute operator value line into a clause, escaping the value' {
        ConvertTo-TkLdapCondition -Line 'department = Sales'   | Should -Be '(department=Sales)'
        ConvertTo-TkLdapCondition -Line 'title = *manager*'    | Should -Be '(title=*manager*)'
        ConvertTo-TkLdapCondition -Line 'mail = *'             | Should -Be '(mail=*)'
        ConvertTo-TkLdapCondition -Line 'name != Guest'        | Should -Be '(!(name=Guest))'
        ConvertTo-TkLdapCondition -Line 'cn = Smith (IT)'      | Should -Be '(cn=Smith \28IT\29)'
    }

    It 'passes a raw clause through and ignores blanks and comments' {
        ConvertTo-TkLdapCondition -Line '(objectClass=user)' | Should -Be '(objectClass=user)'
        ConvertTo-TkLdapCondition -Line '   '                | Should -BeNullOrEmpty
        ConvertTo-TkLdapCondition -Line '# a note'           | Should -BeNullOrEmpty
        ConvertTo-TkLdapCondition -Line 'no operator here'   | Should -BeNullOrEmpty
    }

    It 'ANDs the object scope and the conditions, flattened' {
        $users = (@(Get-TkLdapObjectClass) | Where-Object { $_.Name -eq 'Users' }).Parts
        $filter = Build-TkLdapFilter -Conditions @('(department=Sales)', '(l=Paris)') -Match All -ObjectParts $users

        $filter | Should -Be '(&(objectCategory=person)(objectClass=user)(department=Sales)(l=Paris))'
    }

    It 'ORs the conditions but keeps the object scope an AND' {
        $groups = (@(Get-TkLdapObjectClass) | Where-Object { $_.Name -eq 'Groups' }).Parts
        $filter = Build-TkLdapFilter -Conditions @('(mail=*)', '(l=Paris)') -Match Any -ObjectParts $groups

        $filter | Should -Be '(&(objectCategory=group)(|(mail=*)(l=Paris)))'
    }

    It 'wraps the whole filter when negated' {
        Build-TkLdapFilter -Conditions @('(mail=*)') -Match All -ObjectParts @() -Negate | Should -Be '(!(mail=*))'
    }

    It 'falls back to a catch-all when nothing is given' {
        Build-TkLdapFilter -Conditions @() -Match All -ObjectParts @() | Should -Be '(objectClass=*)'
    }

    It 'writes the filter, the cmdlets and dsquery, and notes an ignored line' {
        $report = (Format-TkLdapReport -Conditions "department = Sales`nbroken line" -ObjectClass Users -Match All) -join "`n"

        $report | Should -Match 'Get-ADObject -LDAPFilter'
        $report | Should -Match 'Get-ADUser -LDAPFilter'
        $report | Should -Match 'dsquery \* -limit 0 -filter'
        $report | Should -Match 'Ignored lines:'
        $report | Should -Match 'broken line'
    }

    It 'carries the matching-rule OID in the userAccountControl presets' {
        $disabled = (@(Get-TkLdapPreset) | Where-Object { $_.Name -eq 'Disabled accounts' }).Clause
        $disabled | Should -Be '(userAccountControl:1.2.840.113556.1.4.803:=2)'
    }
}

Describe 'CSV cleaner' {

    BeforeAll {
        $script:CsvBlob = @'
name,role,city
 Alice , admin , Paris
Bob,"user, guest",Lyon
Bob,"user, guest",Lyon

Carol,dev,"Nice
Riviera"
'@
    }

    It 'detects the delimiter' {
        Get-TkCsvDelimiter -Text $script:CsvBlob | Should -Be ','
        Get-TkCsvDelimiter -Text "a;b;c`n1;2;3"  | Should -Be ';'
        Get-TkCsvDelimiter -Text "a`tb`tc`n1`t2`t3" | Should -Be "`t"
    }

    It 'parses a quoted field that holds the delimiter and a newline' {
        $rows = @(ConvertFrom-TkCsvText -Text $script:CsvBlob -Delimiter ',')

        $rows[2][1] | Should -Be 'user, guest'
        $rows[5][2] | Should -Be "Nice`nRiviera"
    }

    It 'trims, drops blank rows and drops duplicates' {
        $table = Get-TkCsvTable -Text $script:CsvBlob -Header -Trim -DropBlank -DropDuplicate

        $table.Rows.Count       | Should -Be 3
        $table.DroppedBlank     | Should -Be 1
        $table.DroppedDuplicate | Should -Be 1
        $table.Rows[0][0]       | Should -Be 'Alice'   # trimmed
        $table.ColumnCount      | Should -Be 3
    }

    It 'keeps the blanks and duplicates when not asked to clean' {
        $table = Get-TkCsvTable -Text $script:CsvBlob -Header
        $table.Rows.Count | Should -Be 5
    }

    It 'writes JSON keyed by the header' {
        $json = ConvertTo-TkCsvJson -Text $script:CsvBlob -Header -Trim -DropBlank -DropDuplicate | ConvertFrom-Json

        @($json).Count       | Should -Be 3
        $json[0].name        | Should -Be 'Alice'
        $json[1].role        | Should -Be 'user, guest'
    }

    It 'writes clean CSV back, quoting only what needs it' {
        $csv = ConvertTo-TkCsvText -Text $script:CsvBlob -Header -Trim -DropBlank -DropDuplicate

        $csv | Should -Match 'name,role,city'
        $csv | Should -Match '"user, guest"'
        $csv | Should -Not -Match 'Alice ,'   # the space was trimmed
    }

    It 'lays a table out with a summary, flattening an in-cell newline' {
        $report = (Format-TkCsvTable -Text $script:CsvBlob -Header -Trim -DropBlank -DropDuplicate) -join "`n"

        $report | Should -Match 'Delimiter: comma'
        $report | Should -Match '3 column\(s\), 3 row\(s\)'
        $report | Should -Not -Match "Nice`nRiviera"   # the newline is flattened
    }

    It 'prompts on empty input' {
        (Format-TkCsvTable -Text '') -join "`n" | Should -Match 'Paste a CSV'
        ConvertTo-TkCsvJson -Text ''            | Should -Be '[]'
    }
}

Describe 'Indicator extractor' {

    BeforeAll {
        $script:IocBlob = @'
Payload from hxxps://malware.evil[.]com/drop.php and http://1.2.3.4/x.
Contact bad.actor(at)proton[.]me. See CVE-2024-1234 and cve-2023-44487.
Do not run invoice.exe. Legit: microsoft.com. MD5 5f4dcc3b5aa765d61d8327deb882cf99
'@
    }

    Context 'Extraction' {

        It 'refangs then pulls each kind of indicator out' {
            $finding = Get-TkIocFinding -Text $script:IocBlob

            $finding.Urls    | Should -Contain 'https://malware.evil.com/drop.php'
            $finding.IPv4    | Should -Contain '1.2.3.4'
            $finding.Emails  | Should -Contain 'bad.actor@proton.me'
            $finding.Domains | Should -Contain 'microsoft.com'
            $finding.Md5     | Should -Contain '5f4dcc3b5aa765d61d8327deb882cf99'
            @($finding.Cve)  | Should -Contain 'CVE-2023-44487'
        }

        It 'trims sentence punctuation off a URL' {
            (Get-TkIocFinding -Text 'go to http://1.2.3.4/x.').Urls | Should -Contain 'http://1.2.3.4/x'
        }

        It 'leaves a file name that only looks like a domain out of the domains' {
            $finding = Get-TkIocFinding -Text 'The file invoice.exe and report.pdf are attached.'
            $finding.Domains | Should -Not -Contain 'invoice.exe'
            $finding.Domains | Should -Not -Contain 'report.pdf'
        }
    }

    Context 'Defang and refang' {

        It 'defangs URLs, e-mails and IPs, leaving prose alone' {
            $out = ConvertTo-TkDefanged -Text 'Visit https://evil.com/p and mail a@b.com or ping 8.8.8.8. Keep notes.txt.'
            $out | Should -Match 'hxxps://evil\[\.\]com'
            $out | Should -Match 'a\[at\]b\[\.\]com'
            $out | Should -Match '8\[\.\]8\[\.\]8\[\.\]8'
            $out | Should -Match 'notes\.txt'     # a file name is not defanged
        }

        It 'refangs the common notations back' {
            ConvertTo-TkRefanged -Text 'hxxps://bad[.]site[.]com and 10[.]0[.]0[.]1 and user[at]evil[.]com' |
                Should -Be 'https://bad.site.com and 10.0.0.1 and user@evil.com'
        }
    }

    Context 'Report' {

        It 'prompts when empty and says so when nothing matches' {
            (Format-TkIocReport -Text '') -join "`n" | Should -Match 'Paste an e-mail'
            (Format-TkIocReport -Text 'just some words with no indicators at all') -join "`n" | Should -Match 'No indicators found'
        }
    }
}

Describe 'Hash identifier' {

    It 'lists NTLM first for 32 hex characters, alongside MD5 and LM' {
        $names = @((Get-TkHashIdentity -Text '5f4dcc3b5aa765d61d8327deb882cf99').Candidate | ForEach-Object { $_.Name })
        $names[0]  | Should -Be 'NTLM'
        $names     | Should -Contain 'MD5'
        $names     | Should -Contain 'LM'
    }

    It 'identifies <Name> from its length' -TestCases @(
        @{ Hash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'; Name = 'SHA-1' }
        @{ Hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; Name = 'SHA-256' }
        @{ Hash = ('a' * 128); Name = 'SHA-512' }
    ) {
        param($Hash, $Name)
        @((Get-TkHashIdentity -Text $Hash).Candidate | ForEach-Object { $_.Name }) | Should -Contain $Name
    }

    It 'recognises the prefixed password formats' {
        (Get-TkHashIdentity -Text '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW').Candidate[0].Name | Should -Be 'bcrypt'
        (Get-TkHashIdentity -Text '$6$rounds=5000$abc$xxxxxxxx').Candidate[0].Name | Should -Be 'sha512crypt'
        (Get-TkHashIdentity -Text '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19').Candidate[0].Name | Should -Be 'MySQL 4.1+'
    }

    It 'reads an LM:NTLM pwdump pair' {
        (Get-TkHashIdentity -Text 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0').Candidate[0].Name |
            Should -Be 'LM:NTLM pair'
    }

    It 'treats Base64 as a raw digest and gives its byte size' {
        $candidate = (Get-TkHashIdentity -Text ([Convert]::ToBase64String((1..32)))).Candidate[0]
        $candidate.Name | Should -Match '32-byte'
        $candidate.Note | Should -Match 'SHA-256'
    }

    It 'says nothing matches an arbitrary string, and prompts when empty' {
        (Get-TkHashIdentity -Text 'hello world').Candidate.Count | Should -Be 0
        (Format-TkHashReport -Text '') -join "`n" | Should -Match 'Paste a hash'
    }
}

Describe 'TOTP authenticator' {

    BeforeAll {
        # RFC 6238 test secret: the ASCII "12345678901234567890".
        $script:TotpSecret = [System.Text.Encoding]::ASCII.GetBytes('12345678901234567890')
    }

    Context 'Base32' {

        It 'decodes to the expected bytes, ignoring spaces and padding' {
            $bytes = ConvertFrom-TkBase32 -Text 'GEZD GNBV GY3T QOJQ ==='
            [System.Text.Encoding]::ASCII.GetString($bytes) | Should -Be '1234567890'
        }

        It 'rejects a character outside the alphabet' {
            { ConvertFrom-TkBase32 -Text 'ABC!' } | Should -Throw
        }
    }

    Context 'RFC 6238 vectors' {

        It 'computes <Want> at T=<Time>' -TestCases @(
            @{ Time = 59;         Want = '94287082' }
            @{ Time = 1111111109; Want = '07081804' }
            @{ Time = 1234567890; Want = '89005924' }
            @{ Time = 2000000000; Want = '69279037' }
        ) {
            param($Time, $Want)
            Get-TkTotpCode -Secret $script:TotpSecret -UnixTime ([long] $Time) -Digits 8 -Algorithm 'SHA1' | Should -Be $Want
        }
    }

    Context 'otpauth URI' {

        It 'reads the issuer, account, secret and parameters' {
            $uri = ConvertFrom-TkOtpauthUri -Uri 'otpauth://totp/Contoso:alice%40contoso.com?secret=JBSWY3DPEHPK3PXP&issuer=Contoso&digits=8&period=60&algorithm=SHA256'

            $uri.Issuer    | Should -Be 'Contoso'
            $uri.Account   | Should -Be 'alice@contoso.com'
            $uri.Secret    | Should -Be 'JBSWY3DPEHPK3PXP'
            $uri.Digits    | Should -Be 8
            $uri.Period    | Should -Be 60
            $uri.Algorithm | Should -Be 'SHA256'
        }

        It 'is null for anything that is not an otpauth URI' {
            ConvertFrom-TkOtpauthUri -Uri 'https://contoso.com' | Should -BeNullOrEmpty
        }
    }

    Context 'Report' {

        It 'gives a six digit code and a live window from a bare secret' {
            $now    = [System.DateTimeOffset]::FromUnixTimeSeconds(1234567890).UtcDateTime
            $report = Get-TkTotpReport -Text 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' -Now $now

            $report.Error            | Should -Be ''
            $report.Code             | Should -Be '005924'   # the low six of the eight digit vector
            $report.SecondsRemaining | Should -BeGreaterThan 0
            $report.SecondsRemaining | Should -BeLessOrEqual 30
        }

        It 'takes its parameters from an otpauth URI' {
            $report = Get-TkTotpReport -Text 'otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&issuer=Acme'
            $report.Digits | Should -Be 8
            $report.Issuer | Should -Be 'Acme'
        }

        It 'reports an empty or invalid secret rather than throwing' {
            (Get-TkTotpReport -Text 'not base 32 !!!').Error | Should -Match 'not valid Base32'
        }

        It 'never echoes the secret, and prompts when empty' {
            ((Format-TkTotpReport -Text 'JBSWY3DPEHPK3PXP') -join ' ') | Should -Not -Match 'JBSWY3DPEHPK3PXP'
            ((Format-TkTotpReport -Text '') -join ' ') | Should -Match 'Base32 secret'
        }
    }
}

Describe 'Connection string' {

    Context 'Parsing' {

        It 'reads plain key=value pairs' {
            $pairs = @(ConvertFrom-TkConnectionString -Text 'Server=srv;Database=db;User Id=me')
            $pairs.Count       | Should -Be 3
            $pairs[0].Key      | Should -Be 'Server'
            $pairs[0].Value    | Should -Be 'srv'
            $pairs[2].Key      | Should -Be 'User Id'
        }

        It 'keeps a semicolon inside a quoted value' {
            $pairs = @(ConvertFrom-TkConnectionString -Text "Server=s;Password='P@ss;word';Database=d")
            ($pairs | Where-Object { $_.Key -eq 'Password' }).Value | Should -Be 'P@ss;word'
            $pairs.Count | Should -Be 3
        }

        It 'reads a braced value, doubled brace and all' {
            $pairs = @(ConvertFrom-TkConnectionString -Text 'Driver={ODBC Driver 17 for SQL Server};Server=s')
            $pairs[0].Value | Should -Be 'ODBC Driver 17 for SQL Server'

            $braced = @(ConvertFrom-TkConnectionString -Text 'Key={a}}b};Next=1')
            $braced[0].Value | Should -Be 'a}b'
        }
    }

    Context 'Report' {

        It 'names the kind and normalises the fields' {
            $report = Get-TkConnectionStringReport -Text 'Data Source=SRV;Initial Catalog=DB;User ID=sa;Password=x;Encrypt=true'
            $report.Kind            | Should -Be 'SQL Server'
            $report.Field['Server'] | Should -Be 'SRV'
            $report.Field['Database'] | Should -Be 'DB'
            $report.Field['User']   | Should -Be 'sa'
        }

        It 'detects PostgreSQL, MySQL and ODBC' {
            (Get-TkConnectionStringReport -Text 'Host=h;Database=d;Username=u;Ssl Mode=Require').Kind | Should -Be 'PostgreSQL'
            (Get-TkConnectionStringReport -Text 'Server=s;Database=d;Uid=u;Pwd=p;SslMode=None').Kind | Should -Be 'MySQL or MariaDB'
            (Get-TkConnectionStringReport -Text 'Driver={x};Server=s').Kind | Should -Be 'ODBC'
        }

        It 'warns on a clear password, no encryption and a trusted certificate' {
            $report = Get-TkConnectionStringReport -Text 'Server=s;Database=d;User Id=u;Password=p;Encrypt=false;TrustServerCertificate=true'
            $warnings = @($report.Finding | Where-Object { $_.Severity -eq 'Warning' })

            ($warnings.Text -join ' ') | Should -Match 'password is stored in clear'
            ($warnings.Text -join ' ') | Should -Match 'Encrypt is off'
            ($warnings.Text -join ' ') | Should -Match 'certificate is not checked'
        }

        It 'treats integrated authentication as carrying no password' {
            $report = Get-TkConnectionStringReport -Text 'Server=s;Database=d;Integrated Security=SSPI'
            ($report.Finding.Text -join ' ') | Should -Match 'integrated authentication'
            ($report.Finding | Where-Object { $_.Text -match 'password is stored in clear' }) | Should -BeNullOrEmpty
        }
    }

    Context 'Formatting' {

        It 'masks the password in both the fields and the parameters' {
            $text = (Format-TkConnectionStringReport -Text 'Server=s;Database=d;User Id=u;Password=SuperSecret') -join "`n"
            $text | Should -Not -Match 'SuperSecret'
            $text | Should -Match 'hidden'
        }

        It 'prompts on empty input and explains unrecognised input' {
            (Format-TkConnectionStringReport -Text '')  -join "`n" | Should -Match 'Paste a connection string'
        }
    }
}

Describe 'Administration decoders' {

    Context 'SDDL' {

        It 'reads the owner, group and DACL of a descriptor, with rights named for a file' {

            $descriptor = ConvertFrom-TkSddl -Text 'O:BAG:BAD:(A;;FA;;;SY)(A;;FR;;;BU)' -Context File

            $descriptor.Owner.Name | Should -Be 'Administrators'
            $descriptor.Group.Name | Should -Be 'Administrators'
            @($descriptor.Dacl).Count | Should -Be 2

            $descriptor.Dacl[0].Type            | Should -Be 'Allow'
            $descriptor.Dacl[0].Trustee.Name    | Should -Be 'Local System'
            (@($descriptor.Dacl[0].Rights) -join ',') | Should -Be 'Full control'

            $descriptor.Dacl[1].Trustee.Name    | Should -Be 'Users'
            (@($descriptor.Dacl[1].Rights) -join ',') | Should -Be 'Read'
        }

        It 'names the inheritance and audit flags of an entry' {

            $descriptor = ConvertFrom-TkSddl -Text 'D:AI(A;OICIID;FA;;;BA)S:(AU;SAFA;FA;;;WD)' -Context File

            (@($descriptor.Control) -join ',')        | Should -Match 'DACL auto-inherited'
            (@($descriptor.Dacl[0].Flags) -join ',')  | Should -Be 'Object inherit,Container inherit,Inherited'
            $descriptor.Sacl[0].Type                  | Should -Be 'Audit'
            (@($descriptor.Sacl[0].Flags) -join ',')  | Should -Be 'Audit success,Audit failure'
        }

        It 'reads a service descriptor and a directory descriptor with the right rights' {

            $service = ConvertFrom-TkSddl -Text 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' -Context Service
            (@($service.Dacl[0].Rights) -join ',')    | Should -Match 'Full control'

            $directory = ConvertFrom-TkSddl -Text 'D:(A;;RPWP;;;WD)' -Context Directory
            (@($directory.Dacl[0].Rights) -join ',')  | Should -Be 'Read property,Write property'
        }

        It 'names a domain relative SID by its RID' {
            Get-TkSidFriendlyName -Sid 'S-1-5-21-1-2-3-512' | Should -Be 'Domain Admins'
            Get-TkSidFriendlyName -Sid 'S-1-5-18'           | Should -Be 'Local System'
        }
    }

    Context 'Active Directory account flags' {

        It 'reads a disabled normal user from userAccountControl 514' {

            $report = ConvertFrom-TkAdFlags -Attribute userAccountControl -Value 514

            @($report.Flags | Where-Object Set | ForEach-Object { $_.Name }) | Should -Be @('ACCOUNTDISABLE', 'NORMAL_ACCOUNT')
            (@($report.Notes) -join ' ') | Should -Match 'disabled'
        }

        It 'reads a password that never expires from 66048' {
            @(ConvertFrom-TkAdFlags -Attribute userAccountControl -Value 66048).Flags | Where-Object Set | ForEach-Object { $_.Name } |
                Should -Contain 'DONT_EXPIRE_PASSWORD'
        }

        It 'reads a security group with global scope from groupType' {

            $report = ConvertFrom-TkAdFlags -Attribute groupType -Value 2147483650

            @($report.Flags | Where-Object Set | ForEach-Object { $_.Name }) | Should -Contain 'SECURITY_ENABLED'
            (@($report.Notes) -join ' ') | Should -Match 'security group with global scope'
        }

        It 'reads AES-only and warns on a zero encryption type' {

            $aes = ConvertFrom-TkAdFlags -Attribute supportedEncryptionTypes -Value 24
            @($aes.Flags | Where-Object Set | ForEach-Object { $_.Name }) | Should -Be @('AES128_CTS_HMAC_SHA1_96', 'AES256_CTS_HMAC_SHA1_96')
            (@($aes.Notes) -join ' ') | Should -Match 'AES only'

            (@((ConvertFrom-TkAdFlags -Attribute supportedEncryptionTypes -Value 0).Notes) -join ' ') | Should -Match 'RC4'
        }
    }

    Context 'Numbers and bitmasks' {

        It 'reads a number from any base' {
            ConvertFrom-TkNumberText -Text '0xFF'         | Should -Be 255
            ConvertFrom-TkNumberText -Text '0b1010'       | Should -Be 10
            ConvertFrom-TkNumberText -Text '0o755'        | Should -Be 493
            ConvertFrom-TkNumberText -Text '755' -Base 8  | Should -Be 493
            ConvertFrom-TkNumberText -Text '1_000'        | Should -Be 1000
        }

        It 'throws on a digit that does not belong to the base' {
            { ConvertFrom-TkNumberText -Text '0b1012' } | Should -Throw
        }

        It 'shows every base and the bits that are set' {

            $report = Get-TkNumberReport -Value ([System.Numerics.BigInteger] 493)

            $report.Hex   | Should -Be '0x1ED'
            $report.Octal | Should -Be '0o755'
            (@($report.Bits) -join ',') | Should -Be '0,2,3,5,6,7,8'
        }
    }

    Context 'Data sizes and transfer times' {

        It 'reads decimal and binary units, and tells bits from bytes' {
            (ConvertFrom-TkDataSizeText -Text '1 KB').Bytes  | Should -Be 1000
            (ConvertFrom-TkDataSizeText -Text '1 KiB').Bytes | Should -Be 1024
            (ConvertFrom-TkDataSizeText -Text '8 b').Bytes   | Should -Be 1
            (ConvertFrom-TkDataSizeText -Text '100 Mbps').Bits | Should -Be 100000000
        }

        It 'works out a transfer time from a size and a rate' {

            $report = Get-TkTransferReport -SizeText '1 GB' -RateText '100 Mbps'

            $report.Seconds | Should -Be 80
            (Format-TkTransferReport -Report $report) -join "`n" | Should -Match 'At the full rate      1 min 20 s'
        }
    }

    Context 'Robocopy' {

        It 'builds a command, with mirror winning over a plain subfolder copy' {
            Build-TkRobocopyCommand -Source 'C:\Data Files' -Destination '\\srv\bk' -Options @{ Mirror = $true; EmptyDirectories = $true; Threads = 16; Retries = 2; Wait = 5 } |
                Should -Be 'robocopy "C:\Data Files" \\srv\bk /MIR /MT:16 /R:2 /W:5'
        }

        It 'adds a log file, excluded files and no progress' {
            Build-TkRobocopyCommand -Source 'C:\A' -Destination 'D:\B' -Options @{ EmptyDirectories = $true; ExcludeFiles = @('*.tmp'); NoProgress = $true; Log = 'C:\Logs\b.log' } |
                Should -Be 'robocopy C:\A D:\B /E /XF *.tmp /LOG:C:\Logs\b.log /TEE /NP'
        }

        It 'reads an exit code as a bitmask, not a rank' {

            $three = ConvertFrom-TkRobocopyExitCode -Code 3
            $three.Success | Should -BeTrue
            @($three.Meanings).Count | Should -Be 2

            $sixteen = ConvertFrom-TkRobocopyExitCode -Code 16
            $sixteen.Success | Should -BeFalse
            (@($sixteen.Meanings) -join ' ') | Should -Match 'fatal'
        }
    }

    Context 'dsacls delegation' {

        It 'builds a fixed task, one entry per ace' {
            $link = @(Get-TkDsaclsAction) | Where-Object Label -eq 'Link and unlink GPOs'
            Build-TkDsaclsAces -ObjectDn 'OU=Sites,DC=contoso,DC=com' -Trustee 'CONTOSO\GPO' -Inheritance 'T' -Ace $link.Aces |
                Should -Be 'dsacls "OU=Sites,DC=contoso,DC=com" /I:T /G "CONTOSO\GPO:WP;gPLink;organizationalUnit" /G "CONTOSO\GPO:WP;gPOptions;organizationalUnit"'
        }

        It 'substitutes the object type into a create-and-delete task' {
            $create = @(Get-TkDsaclsAction) | Where-Object Label -eq 'Create and delete child objects'
            $ace    = @($create.Aces | ForEach-Object { $_ -f 'computer' })
            Build-TkDsaclsAces -ObjectDn 'OU=W,DC=contoso,DC=com' -Trustee 'CONTOSO\PC' -Ace $ace |
                Should -Be 'dsacls "OU=W,DC=contoso,DC=com" /G "CONTOSO\PC:CCDC;computer"'
        }

        It 'writes one entry per property for a specific-properties task' {
            $aces = Get-TkDsaclsPropertyAce -Access 'Write' -ObjectType 'user' -Property @('telephoneNumber', 'mobile')
            Build-TkDsaclsAces -ObjectDn 'OU=Staff,DC=contoso,DC=com' -Trustee 'CONTOSO\HD' -Inheritance 'S' -Ace $aces |
                Should -Be 'dsacls "OU=Staff,DC=contoso,DC=com" /I:S /G "CONTOSO\HD:WP;telephoneNumber;user" /G "CONTOSO\HD:WP;mobile;user"'
        }

        It 'uses RPWP for read-and-write access' {
            @(Get-TkDsaclsPropertyAce -Access 'ReadWrite' -ObjectType 'group' -Property @('member'))[0] | Should -Be 'RPWP;member;group'
        }

        It 'builds the two commands of a move: delete in the source, create in the target' {
            $move = Build-TkDsaclsMove -SourceDn 'OU=Staging,DC=contoso,DC=com' -TargetDn 'OU=WS,DC=contoso,DC=com' -Trustee 'CONTOSO\HD' -ObjectType 'computer'
            $move[0] | Should -Be 'dsacls "OU=Staging,DC=contoso,DC=com" /G "CONTOSO\HD:DC;computer"'
            $move[1] | Should -Be 'dsacls "OU=WS,DC=contoso,DC=com" /G "CONTOSO\HD:CC;computer"'
        }

        It 'denies with /D instead of /G' {
            Build-TkDsaclsAces -ObjectDn 'OU=Staff,DC=contoso,DC=com' -Trustee 'CONTOSO\HR' -Inheritance 'S' -Deny -Ace @('RPWP;;user') |
                Should -Match '/D "CONTOSO\\HR:RPWP;;user"'
        }

        It 'offers the object classes with their attributes and the join-domain task' {
            $classes = @(Get-TkDsaclsObjectClass | ForEach-Object { $_.Class })
            $classes | Should -Contain 'printQueue'
            $classes | Should -Contain 'volume'
            (@(Get-TkDsaclsObjectClass) | Where-Object Class -eq 'user').Attributes.Count | Should -BeGreaterThan 20
            (@(Get-TkDsaclsAction)      | Where-Object Label -like 'Join*').Aces           | Should -Contain 'CC;computer'
        }
    }

    Context 'icacls' {

        It 'grants a right with inheritance flags, quoted and recursed' {
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Grant' -Trustee 'CONTOSO\Sales' -Permission 'M' -Inheritance '(OI)(CI)' -Recurse |
                Should -Be 'icacls "C:\Data" /grant "CONTOSO\Sales:(OI)(CI)M" /T'
        }

        It 'denies with /deny' {
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Deny' -Trustee 'Guests' -Permission 'F' |
                Should -Be 'icacls "C:\Data" /deny "Guests:F"'
        }

        It 'removes a trustee and resets a path' {
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Remove' -Trustee 'CONTOSO\Temp' -Recurse -Quiet |
                Should -Be 'icacls "C:\Data" /remove "CONTOSO\Temp" /T /Q'

            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Reset' -Recurse -ContinueOnError |
                Should -Be 'icacls "C:\Data" /reset /T /C'
        }

        It 'combines the ticked permissions, respecting the hierarchy' {
            Resolve-TkIcaclsPermission -Selected @('Read', 'Write')            | Should -Be '(R,W)'
            Resolve-TkIcaclsPermission -Selected @('Read & execute', 'Write')  | Should -Be '(RX,W)'
            Resolve-TkIcaclsPermission -Selected @('Read & execute', 'Read')   | Should -Be 'RX'   # Read is redundant
            Resolve-TkIcaclsPermission -Selected @('Modify', 'Read')           | Should -Be 'M'    # Modify wins
            Resolve-TkIcaclsPermission -Selected @('Full control', 'Write')    | Should -Be 'F'    # Full wins
            Resolve-TkIcaclsPermission -Selected @('Read')                     | Should -Be 'R'
            Resolve-TkIcaclsPermission -Selected @()                           | Should -Be ''
        }

        It 'sets the owner, turns inheritance on and off, and saves and restores' {
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'SetOwner' -Trustee 'CONTOSO\Admin' | Should -Be 'icacls "C:\Data" /setowner "CONTOSO\Admin"'
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'InheritDisable'                    | Should -Be 'icacls "C:\Data" /inheritance:d'
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'InheritRemove' -Recurse            | Should -Be 'icacls "C:\Data" /inheritance:r /T'
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Save' -File 'C:\acl.txt' -Recurse  | Should -Be 'icacls "C:\Data" /save "C:\acl.txt" /T'
            Build-TkIcaclsCommand -Path 'C:\Data' -Action 'Restore' -File 'C:\acl.txt'        | Should -Be 'icacls "C:\Data" /restore "C:\acl.txt"'
        }

        It 'adds the symlink flag' {
            Build-TkIcaclsCommand -Path 'C:\Link' -Action 'Grant' -Trustee 'U' -Permission 'F' -Symlink |
                Should -Be 'icacls "C:\Link" /grant "U:F" /L'
        }
    }

    Context 'Scheduled tasks' {

        It 'adds only the fields a schedule uses' {

            $weekly = Build-TkSchtasksCommand -Name 'Nightly backup' -Run 'C:\s\b.cmd' -Schedule WEEKLY -Options @{ Day = 'mon'; StartTime = '02:00'; HighestPrivileges = $true; Force = $true }
            $weekly | Should -Be 'schtasks /create /tn "Nightly backup" /tr "C:\s\b.cmd" /sc WEEKLY /d MON /st 02:00 /rl HIGHEST /f'

            $onstart = Build-TkSchtasksCommand -Name 'Boot' -Run 'x.exe' -Schedule ONSTART -Options @{ Day = 'MON'; StartTime = '02:00' }
            $onstart | Should -Be 'schtasks /create /tn "Boot" /tr "x.exe" /sc ONSTART'
        }
    }

    Context 'JSON and YAML' {

        It 'minifies and validates JSON' {
            Compress-TkJsonText -Json "{ `"a`": 1, `"b`": [1, 2] }" | Should -Be '{"a":1,"b":[1,2]}'
            (Test-TkJsonText -Json '{bad}').Valid | Should -BeFalse
            (Test-TkJsonText -Json '{"a":1}').Valid | Should -BeTrue
        }

        It 'turns JSON into YAML' {
            $yaml = Convert-TkJson -Json '{"name":"web","ports":[80,443],"env":{"TZ":"Europe/Paris"}}' -Operation Yaml
            $yaml | Should -Match 'name: web'
            $yaml | Should -Match '  - 80'
            $yaml | Should -Match '  TZ: Europe/Paris'
        }

        It 'turns an array of flat objects into CSV, and refuses anything else' {
            $csv = Convert-TkJson -Json '[{"name":"a","id":1},{"name":"b","id":2}]' -Operation Csv
            $csv | Should -Match '"name","id"'
            $csv | Should -Match '"a","1"'

            Convert-TkJson -Json '[1,2,3]' -Operation Csv | Should -Match 'array of flat objects'
        }
    }
}

Describe 'Disk space' {

    BeforeAll {
        $script:DiskRoot = Join-Path $TestDrive 'tree'
        New-Item -ItemType Directory -Path (Join-Path $script:DiskRoot 'big\sub') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:DiskRoot 'small') -Force | Out-Null

        [System.IO.File]::WriteAllBytes((Join-Path $script:DiskRoot 'big\huge.bin'),     (New-Object byte[] (300KB)))
        [System.IO.File]::WriteAllBytes((Join-Path $script:DiskRoot 'big\sub\mid.bin'),  (New-Object byte[] (100KB)))
        [System.IO.File]::WriteAllBytes((Join-Path $script:DiskRoot 'small\tiny.bin'),   (New-Object byte[] (20KB)))
        [System.IO.File]::WriteAllBytes((Join-Path $script:DiskRoot 'loose.bin'),        (New-Object byte[] (10KB)))
    }

    It 'adds up a tree and returns zero for a missing path' {
        Measure-TkPathSize -Path $script:DiskRoot | Should -BeGreaterThan (420KB - 1)
        Measure-TkPathSize -Path (Join-Path $script:DiskRoot 'does-not-exist') | Should -Be 0
    }

    It 'finds the biggest folder and file, and attributes loose files to the root' {

        $scan = Get-TkDiskUsageScan -Path $script:DiskRoot -TopFolders 5 -TopFiles 3

        $scan.Folders[0].Name  | Should -Be 'big'
        $scan.Folders[0].Bytes | Should -Be (400KB)
        $scan.Files[0].Path    | Should -Match 'huge\.bin'
        @($scan.Folders | Where-Object { $_.Name -eq '(files in the root)' }).Count | Should -Be 1
        @($scan.Files).Count   | Should -Be 3
    }

    It 'lists cleanup candidates with their sizes, from injected base folders' {

        $candidates = Get-TkCleanupCandidate -LocalAppData $script:DiskRoot -WindowsDir $script:DiskRoot `
            -ProgramData $script:DiskRoot -SystemDrive $script:DiskRoot -Temp (Join-Path $script:DiskRoot 'big')

        (@($candidates | Where-Object { $_.Name -eq 'Your temporary files' })[0]).Bytes  | Should -Be (400KB)
        (@($candidates | Where-Object { $_.Name -eq 'Windows.old' })[0]).Exists           | Should -BeFalse
    }

    It 'reports the fixed drives with a total and a valid severity' {

        $drives = @(Get-TkDriveSpace)

        $drives.Count             | Should -BeGreaterThan 0
        $drives[0].TotalBytes     | Should -BeGreaterThan 0
        $drives[0].Severity       | Should -BeIn @('Pass', 'Warning', 'Fail')
    }
}

Describe 'Threat hunting history' {

    Context 'USB and FILETIME' {

        It 'reads the vendor, product and revision from a USBSTOR key name' {
            $id = ConvertFrom-TkUsbStorId -KeyName 'Disk&Ven_SanDisk&Prod_Ultra_USB_3.0&Rev_1.00'
            $id.Vendor   | Should -Be 'SanDisk'
            $id.Product  | Should -Be 'Ultra USB 3.0'
            $id.Revision | Should -Be '1.00'
        }

        It 'round-trips a FILETIME and rejects empty or zero bytes' {
            $when  = [datetime]::new(2026, 9, 16, 12, 0, 0, [System.DateTimeKind]::Utc)
            $bytes = [System.BitConverter]::GetBytes($when.ToFileTimeUtc())
            (ConvertFrom-TkFileTimeBytes -Bytes $bytes) | Should -Be $when
            ConvertFrom-TkFileTimeBytes -Bytes $null | Should -BeNullOrEmpty
            ConvertFrom-TkFileTimeBytes -Bytes (New-Object byte[] 8) | Should -BeNullOrEmpty
        }
    }

    Context 'Remote Desktop' {

        It 'reads user, domain and source address from a 1149 event' {
            $event = [pscustomobject] @{
                TimeCreated = [datetime]::new(2026, 9, 16, 14, 30, 0)
                Properties  = @([pscustomobject] @{ Value = 'alice' }, [pscustomobject] @{ Value = 'CONTOSO' }, [pscustomobject] @{ Value = '203.0.113.5' })
            }
            $record = ConvertFrom-TkRdpLogonEvent -LogEvent $event
            $record.User     | Should -Be 'alice'
            $record.Domain   | Should -Be 'CONTOSO'
            $record.SourceIp | Should -Be '203.0.113.5'
        }
    }

    Context 'Browser extensions' {

        It 'flags the far-reaching permissions and ignores the harmless ones' {
            $risk = @(Get-TkExtensionPermissionRisk -Permissions @('storage', 'alarms', 'tabs', '<all_urls>', 'nativeMessaging'))
            ($risk -join '|') | Should -Match 'reads the pages you open'
            ($risk -join '|') | Should -Match 'every website'
            ($risk -join '|') | Should -Match 'talks to a program'
            @(Get-TkExtensionPermissionRisk -Permissions @('storage', 'alarms')).Count | Should -Be 0
        }

        It 'resolves a __MSG__ name and merges the permission lists of a Chrome manifest' {
            $manifest = '{"name":"__MSG_appName__","version":"2.1","default_locale":"en","permissions":["tabs"],"host_permissions":["<all_urls>"]}' | ConvertFrom-Json
            $messages = '{"appName":{"message":"Ad Blocker Pro"}}' | ConvertFrom-Json
            $info = ConvertFrom-TkChromeExtensionManifest -Manifest $manifest -LocaleMessages $messages
            $info.Name | Should -Be 'Ad Blocker Pro'
            (@($info.Permissions) -join ',') | Should -Be 'tabs,<all_urls>'
        }

        It 'reads a Firefox add-on and skips a built-in one' {
            $addon = '{"type":"extension","id":"e@x","version":"3.0","location":"app-profile","userDisabled":false,"defaultLocale":{"name":"Cookie Manager"},"userPermissions":{"permissions":["cookies"],"origins":["*://*/*"]}}' | ConvertFrom-Json
            $info = ConvertFrom-TkFirefoxExtension -Addon $addon
            $info.Name    | Should -Be 'Cookie Manager'
            $info.Enabled | Should -BeTrue
            ConvertFrom-TkFirefoxExtension -Addon ('{"type":"extension","location":"app-builtin","id":"b"}' | ConvertFrom-Json) | Should -BeNullOrEmpty
        }

        It 'reads the extensions from a sample browser tree' {
            $base = Join-Path $TestDrive 'browsers'
            $chrome = Join-Path $base 'Google\Chrome\User Data\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\2.1_0'
            New-Item -ItemType Directory -Path (Join-Path $chrome '_locales\en') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $chrome 'manifest.json') -Value '{"name":"__MSG_appName__","version":"2.1","default_locale":"en","permissions":["tabs"],"host_permissions":["<all_urls>"]}'
            Set-Content -LiteralPath (Join-Path $chrome '_locales\en\messages.json') -Value '{"appName":{"message":"Ad Blocker Pro"}}'

            $extensions = @(Get-TkBrowserExtension -LocalAppData $base -AppData $base)
            $extensions.Count | Should -Be 1
            $extensions[0].Browser          | Should -Be 'Chrome'
            $extensions[0].Name             | Should -Be 'Ad Blocker Pro'
            $extensions[0].Readable         | Should -BeTrue
            @($extensions[0].RiskyPermissions).Count | Should -BeGreaterThan 0
        }

        It 'still lists an extension whose manifest cannot be read, named from its id' {
            # A version folder with no readable manifest stands in for a profile a
            # security product refuses to let us read.
            $base = Join-Path $TestDrive 'locked'
            $dir  = Join-Path $base 'BraveSoftware\Brave-Browser\User Data\Default\Extensions\nngceckbapebfimnlniiiahkandclblb\2026.8.0_0'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null

            $extensions = @(Get-TkBrowserExtension -LocalAppData $base -AppData $base)
            $extensions.Count | Should -Be 1
            $extensions[0].Name     | Should -Be 'Bitwarden'
            $extensions[0].Version  | Should -Be '2026.8.0'
            $extensions[0].Readable | Should -BeFalse
        }

        It 'names a well-known extension id and leaves an unknown one empty' {
            Get-TkKnownExtensionName -Id 'cjpalhdlnbpafiamejdnhcphjbkeiagm' | Should -Be 'uBlock Origin'
            Get-TkKnownExtensionName -Id 'neebplgakaahbhdphmkckjjcegoiijjo' | Should -Be 'Keepa'
            Get-TkKnownExtensionName -Id 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' | Should -Be ''
        }
    }

    Context 'Defender detections' {

        It 'names the severity of a threat' {
            (Get-TkDefenderSeverityName -Value 5).Name     | Should -Be 'Severe'
            (Get-TkDefenderSeverityName -Value 5).Severity | Should -Be 'Fail'
            (Get-TkDefenderSeverityName -Value 1).Name     | Should -Be 'Low'
        }

        It 'names a detection from the catalog and cleans the resource paths' {
            $detection = [pscustomobject] @{ ThreatID = '2147'; InitialDetectionTime = [datetime]::new(2026, 9, 10, 9, 0, 0); Resources = @('file:_C:\temp\evil.exe', 'containerfile:_C:\temp\a.zip'); CleaningActionID = 2; ActionSuccess = $true }
            $catalog   = @{ '2147' = [pscustomobject] @{ ThreatName = 'Trojan:Win32/Test'; SeverityID = 5 } }

            $record = ConvertFrom-TkDefenderDetection -Detection $detection -Catalog $catalog
            $record.ThreatName | Should -Be 'Trojan:Win32/Test'
            $record.Severity   | Should -Be 'Fail'
            $record.Action     | Should -Be 'Quarantine'
            (@($record.Resources) -join ';') | Should -Be 'C:\temp\evil.exe;C:\temp\a.zip'
        }
    }
}

Describe 'Updates, accounts and policy' {

    Context 'Local accounts' {

        It 'judges the accounts the way a review does' {

            $users = @(
                [pscustomobject] @{ Name = 'Guest';  Enabled = $false; PasswordRequired = $false; PasswordExpires = $null;        LastLogon = $null; IsBuiltinAdministrator = $false; IsBuiltinGuest = $true }
                [pscustomobject] @{ Name = 'Admin';  Enabled = $true;  PasswordRequired = $true;  PasswordExpires = (Get-Date);   LastLogon = (Get-Date); IsBuiltinAdministrator = $true;  IsBuiltinGuest = $false }
                [pscustomobject] @{ Name = 'Kiosk';  Enabled = $true;  PasswordRequired = $false; PasswordExpires = $null;        LastLogon = (Get-Date).AddDays(-200); IsBuiltinAdministrator = $false; IsBuiltinGuest = $false }
            )
            $admins = @(
                [pscustomobject] @{ Name = 'A'; ObjectClass = 'User' }
                [pscustomobject] @{ Name = 'B'; ObjectClass = 'User' }
                [pscustomobject] @{ Name = 'C'; ObjectClass = 'User' }
                [pscustomobject] @{ Name = 'D'; ObjectClass = 'User' }
            )

            $findings = @(Get-TkLocalAccountFinding -Users $users -AdminMembers $admins -Now (Get-Date))
            $joined   = ($findings | ForEach-Object { '{0}:{1}' -f $_.Severity, $_.Heading }) -join '|'

            $joined | Should -Match 'Pass:The Guest account'
            $joined | Should -Match 'Info:The built-in Administrator'
            $joined | Should -Match 'Warning:4 local administrator'
            $joined | Should -Match 'Warning:"Kiosk" needs no password'
            $joined | Should -Match 'Info:"Kiosk" has not signed in'
        }
    }

    Context 'Group Policy' {

        It 'reads applied and filtered policies and the security groups' {

            [xml] $xml = @'
<Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
  <ReadTime>2026-09-17T06:01:00Z</ReadTime>
  <ComputerResults>
    <Name>CONTOSO\PC01$</Name>
    <GPO><Name>Default Domain Policy</Name><Enabled>true</Enabled><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied><Link>DC=contoso</Link></GPO>
    <GPO><Name>Blocked Policy</Name><Enabled>true</Enabled><FilterAllowed>false</FilterAllowed><AccessDenied>false</AccessDenied></GPO>
    <SecurityGroup><Name>BUILTIN\Administrators</Name></SecurityGroup>
  </ComputerResults>
  <UserResults>
    <Name>CONTOSO\jane</Name>
    <GPO><Name>User Base</Name><Enabled>true</Enabled><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied></GPO>
  </UserResults>
</Rsop>
'@

            $report = ConvertFrom-TkGpResultXml -Document $xml

            $report.ReadTime         | Should -Be '2026-09-17T06:01:00Z'
            $report.Computer.Name    | Should -Be 'CONTOSO\PC01$'
            @($report.Computer.Gpos).Count | Should -Be 2
            $report.Computer.Gpos[0].Applied | Should -BeTrue
            $report.Computer.Gpos[1].Applied | Should -BeFalse
            $report.Computer.Gpos[1].Reason  | Should -Match 'filtered'
            (@($report.Computer.SecurityGroups) -join ',') | Should -Match 'Administrators'
            $report.User.Gpos[0].Name | Should -Be 'User Base'
        }
    }

    Context 'Windows Update' {

        It 'maps severity and formats an implausible size as not reported' {
            (Get-TkUpdateSeverity -Severity 'Critical').Severity  | Should -Be 'Fail'
            (Get-TkUpdateSeverity -Severity 'Important').Severity | Should -Be 'Warning'
            (Get-TkUpdateSeverity -Severity '').Label             | Should -Be 'Unrated'

            Format-TkUpdateSize -Bytes 734003200 | Should -Match 'MB'
            Format-TkUpdateSize -Bytes 0         | Should -Be 'size not reported'
            Format-TkUpdateSize -Bytes 96888104301 | Should -Be 'size not reported'
        }

        It 'reduces an update object to a record' {

            $update = [pscustomobject] @{
                Title = '2026-09 Cumulative Update (KB5012345)'
                KBArticleIDs = @('5012345')
                MaxDownloadSize = 734003200
                MsrcSeverity = 'Critical'
                IsDownloaded = $false
                InstallationBehavior = [pscustomobject] @{ RebootBehavior = 1 }
                Categories = @([pscustomobject] @{ Name = 'Security Updates' })
                Identity = [pscustomobject] @{ UpdateID = 'abc-123' }
            }

            $record = ConvertFrom-TkUpdateCom -Update $update
            $record.KB             | Should -Be 'KB5012345'
            $record.Severity       | Should -Be 'Fail'
            $record.RequiresReboot | Should -BeTrue
            $record.SizeText       | Should -Match 'MB'
            $record.UpdateId       | Should -Be 'abc-123'
        }
    }
}

Describe 'Playbooks' {

    BeforeAll {
        $script:Playbooks  = @(Get-TkPlaybook)
        $script:PbMarkup   = Get-TkMainWindowXaml
        $script:DiagTitles = @(Get-TkDiagnosticReport | ForEach-Object { $_.Title })
        $script:HuntTitles = @('Event log triage', 'Autostart and persistence', 'Network exposure', 'Certificate inventory', 'USB history', 'Remote Desktop history', 'Browser extensions', 'Defender detections')
        $script:PageNames  = @(Get-TkPageName)
    }

    It 'has unique ids and at least one step each' {
        $ids = @($script:Playbooks | ForEach-Object { $_.Id })
        @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        foreach ($playbook in $script:Playbooks) {
            @($playbook.Steps).Count | Should -BeGreaterThan 0
        }
    }

    It 'points every step at a page that exists' {
        foreach ($playbook in $script:Playbooks) {
            foreach ($step in $playbook.Steps) {
                if ($step.Page) {
                    $script:PageNames | Should -Contain $step.Page
                }
            }
        }
    }

    It 'points every report and hunt step at a chooser entry that exists' {
        foreach ($playbook in $script:Playbooks) {
            foreach ($step in $playbook.Steps) {
                if ($step.List -eq 'DiagnosticChoices') {
                    $script:DiagTitles | Should -Contain $step.Choice
                }
                elseif ($step.List -eq 'HuntChoices') {
                    $script:HuntTitles | Should -Contain $step.Choice
                }
            }
        }
    }

    It 'lists the playbooks in the markup in the same order as the data' {
        $start = $script:PbMarkup.IndexOf('x:Name="PlaybookChoices"')
        $end   = $script:PbMarkup.IndexOf('</ListBox>', $start)
        $slice = $script:PbMarkup.Substring($start, $end - $start)
        $actual = @([regex]::Matches($slice, 'Text="(?<t>[^"]+)"') | ForEach-Object { $_.Groups['t'].Value })
        ($actual -join '|') | Should -Be ((@($script:Playbooks | ForEach-Object { $_.Title })) -join '|')
    }
}

Describe 'Event log query builder' {

    It 'builds the XPath, hashtable and command forms from the parts' {

        $query = Build-TkEventQuery -Log 'System' -Id 1000, 1001 -Level 2 -Provider 'Application Error' -SinceHours 24 -Contains 'foo' -MaxEvents 20

        $query.PlainXPath | Should -Match '\(EventID=1000 or EventID=1001\)'
        $query.PlainXPath | Should -Match 'Level=2'
        $query.PlainXPath | Should -Match "Provider\[@Name='Application Error'\]"
        $query.PlainXPath | Should -Match 'timediff\(@SystemTime\) <= 86400000'
        $query.PlainXPath | Should -Match "contains\(\.,'foo'\)"
        $query.XPath      | Should -Match '&lt;='   # escaped for the Event Viewer XML box
        $query.FilterHashtable | Should -Match "LogName = 'System'"
        $query.FilterHashtable | Should -Match 'Id      = 1000, 1001'
        $query.Wevtutil   | Should -Match '^wevtutil qe "System"'
        $query.PowerShellHashtable | Should -Match "Where-Object"
    }

    It 'produces a bare log query when nothing else is given' {
        (Build-TkEventQuery -Log 'Application' -MaxEvents 50).PlainXPath | Should -Be '*[System]'
    }
}

Describe 'HTTP security headers' {

    BeforeAll {
        $script:Sample = @"
HTTP/1.1 200 OK
Server: nginx/1.25.3
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Powered-By: PHP/8.1.2
Set-Cookie: session=abc; Path=/; HttpOnly
Set-Cookie: theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax
"@
    }

    It 'parses the headers and skips the status line' {
        $headers = @(ConvertFrom-TkHttpHeaderText -Text $script:Sample)
        $headers.Count | Should -Be 7
        @($headers | Where-Object { $_.Name -eq 'Set-Cookie' }).Count | Should -Be 2
        ($headers | Where-Object { $_.Name -eq 'Server' }).Value | Should -Be 'nginx/1.25.3'
    }

    It 'grades the security headers' {
        $report = Get-TkHttpHeaderReport -Text $script:Sample
        $find   = { param($h) @($report.Findings | Where-Object { $_.Header -eq $h } | Select-Object -First 1) }

        (& $find 'Strict-Transport-Security')[0].Severity | Should -Be 'Pass'
        (& $find 'Content-Security-Policy')[0].Severity   | Should -Be 'Warning'   # unsafe-inline
        (& $find 'Framing')[0].Severity                   | Should -Be 'Warning'   # none set
        (& $find 'Server')[0].Severity                    | Should -Be 'Info'
        (@($report.Findings | Where-Object { $_.Header -match 'session' })[0]).Note | Should -Match 'Secure'
    }

    It 'fails a response with no HSTS' {
        $report = Get-TkHttpHeaderReport -Text "HTTP/1.1 200 OK`nX-Content-Type-Options: nosniff"
        (@($report.Findings | Where-Object { $_.Header -eq 'Strict-Transport-Security' })[0]).Severity | Should -Be 'Fail'
    }
}

Describe 'Services and drivers' {

    Context 'Services' {

        It 'normalises a service and tells a named account from a built-in one' {
            $builtin = ConvertFrom-TkServiceCim -Service ([pscustomobject] @{ Name = 'Spooler'; DisplayName = 'Print Spooler'; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = 'C:\Windows\System32\spoolsv.exe' })
            $builtin.NamedAccount | Should -BeFalse
            $builtin.Running      | Should -BeTrue

            $named = ConvertFrom-TkServiceCim -Service ([pscustomobject] @{ Name = 'App'; DisplayName = 'My App'; State = 'Stopped'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'CONTOSO\svc-app'; PathName = 'C:\App\app.exe' })
            $named.NamedAccount | Should -BeTrue
        }

        It 'flags an automatic service that is stopped and notes named accounts' {
            $services = @(
                ConvertFrom-TkServiceCim -Service ([pscustomobject] @{ Name = 'A'; DisplayName = 'Stopped Auto'; State = 'Stopped'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = 'x' })
                ConvertFrom-TkServiceCim -Service ([pscustomobject] @{ Name = 'B'; DisplayName = 'Named';       State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'CONTOSO\svc'; PathName = 'y' })
            )
            $joined = (Get-TkServiceFinding -Services $services | ForEach-Object { '{0}:{1}' -f $_.Severity, $_.Heading }) -join '|'
            $joined | Should -Match 'Warning:"Stopped Auto" is set to start automatically but is stopped'
            $joined | Should -Match 'Info:1 service'
        }

        It 'passes when every automatic service is running' {
            $ok = @(ConvertFrom-TkServiceCim -Service ([pscustomobject] @{ Name = 'A'; DisplayName = 'Ok'; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = 'x' }))
            @(Get-TkServiceFinding -Services $ok)[0].Severity | Should -Be 'Pass'
        }
    }

    Context 'Drivers' {

        It 'reads a WMI datetime and rejects an empty one' {
            (ConvertFrom-TkCimDate -Value '20240115000000.000000-000') | Should -Be ([datetime]::new(2024, 1, 15))
            ConvertFrom-TkCimDate -Value '' | Should -BeNullOrEmpty
        }

        It 'normalises a signed driver with its date' {
            $rec = ConvertFrom-TkDriverCim -Driver ([pscustomobject] @{ DeviceName = 'GPU'; DriverProviderName = 'NVIDIA'; DriverVersion = '31.0.15'; DriverDate = '20240115000000.000000-000'; IsSigned = $true; DeviceClass = 'Display'; InfName = 'oem12.inf' })
            $rec.Device   | Should -Be 'GPU'
            $rec.Provider | Should -Be 'NVIDIA'
            $rec.Signed   | Should -BeTrue
            $rec.Date     | Should -Be ([datetime]::new(2024, 1, 15))
        }
    }
}

Describe 'Local privilege escalation' {

    It 'flags an unquoted service path with a space and skips the safe ones' {
        $services = @(
            [pscustomobject] @{ Name = 'Quoted';  DisplayName = 'Quoted';   Path = '"C:\Program Files\X\x.exe" -run' }
            [pscustomobject] @{ Name = 'Vuln';    DisplayName = 'Unquoted'; Path = 'C:\Program Files\Encrypto\Encrypto.Service.exe' }
            [pscustomobject] @{ Name = 'Svchost'; DisplayName = 'Svchost';  Path = 'C:\Windows\system32\svchost.exe -k netsvcs' }
            [pscustomobject] @{ Name = 'NoSpace'; DisplayName = 'No space'; Path = 'C:\App\app.exe' }
        )
        $flagged = @(Get-TkUnquotedServicePath -Services $services)
        $flagged.Count       | Should -Be 1
        $flagged[0].Name     | Should -Be 'Vuln'
    }

    It 'parses cmdkey output by its locale-independent target token' {
        $text = "    Cible : Domain:target=CONTOSO\dc01`n    Type : Domaine`n    Cible : LegacyGeneric:target=Office16`n"
        $creds = @(ConvertFrom-TkCmdkeyOutput -Text $text)
        $creds.Count | Should -Be 2
        $creds[0].Type   | Should -Be 'Domain'
        $creds[0].Target | Should -Be 'CONTOSO\dc01'
        @($creds | Where-Object { $_.Type -match 'Domain' }).Count | Should -Be 1
    }
}

Describe 'Tools page' {

    BeforeAll {
        $script:ToolMarkup = Get-TkMainWindowXaml
    }

    It 'lists every tool of the table under its category heading, in the same order' {

        $start = $script:ToolMarkup.IndexOf('x:Name="ToolChoices"')
        $end   = $script:ToolMarkup.IndexOf('</ListBox>', $start)
        $slice = $script:ToolMarkup.Substring($start, $end - $start)

        $actual = @([regex]::Matches($slice, 'Style="\{StaticResource (?<style>ChoiceGroup|ReportChoice)\}"[\s\S]*?\sText="(?<title>[^"]+)"') |
                    ForEach-Object { '{0}:{1}' -f $(if ($_.Groups['style'].Value -eq 'ChoiceGroup') { 'group' } else { 'tool' }), $_.Groups['title'].Value })

        $expected = @()
        $category = ''

        foreach ($entry in (Get-TkToolEntry)) {

            if ($entry.Category -ne $category) {
                $category  = $entry.Category
                $expected += 'group:{0}' -f $category.ToUpperInvariant()
            }

            $expected += 'tool:{0}' -f $entry.Title
        }

        ($actual -join '|') | Should -Be ($expected -join '|')
    }

    It 'gives every tool a panel of its own' {

        $panels = @(Get-TkToolEntry | ForEach-Object { $_.Panel })

        @($panels | Sort-Object -Unique).Count | Should -Be $panels.Count

        foreach ($panel in $panels) {
            $script:ToolMarkup | Should -Match ('x:Name="{0}"' -f $panel)
        }

        $script:ToolMarkup | Should -Not -Match 'SecurityToolsTabs'
    }
}

Describe 'Text tools' {

    Context 'UUIDs' {

        It 'generates distinct version 4 UUIDs with the version and variant bits set' {

            $uuids = @(New-TkUuid -Version 4 -Count 50)

            $uuids.Count                          | Should -Be 50
            @($uuids | Sort-Object -Unique).Count | Should -Be 50

            foreach ($uuid in $uuids) {
                $uuid | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            }
        }

        It 'writes the time into a version 7 UUID, and reads it back' {

            $now  = [datetime]::new(2026, 9, 14, 8, 30, 15, 250, [DateTimeKind]::Utc)
            $uuid = @(New-TkUuid -Version 7 -Now $now)[0]

            $uuid | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab]'

            $info = ConvertFrom-TkUuid -Text ('{' + $uuid.ToUpperInvariant() + '}')

            $info.Version | Should -Be 7
            $info.Time    | Should -Be $now
            $info.Variant | Should -Be 'RFC 9562'
        }

        It 'reads the time and node of a version 1 UUID, and names the nil UUID' {

            $info = ConvertFrom-TkUuid -Text 'urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8'

            $info.Version   | Should -Be 1
            $info.Time.Year | Should -Be 1998
            $info.Node      | Should -Be '00:C0:4F:D4:30:C8'

            (ConvertFrom-TkUuid -Text '00000000-0000-0000-0000-000000000000').VersionName | Should -BeLike '*nil*'
            (ConvertFrom-TkUuid -Text 'not-a-uuid').Valid | Should -BeFalse
        }

        It 'writes a UUID in each of its forms' {

            $uuid = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'

            Format-TkUuid -Uuid $uuid -Format Braces  | Should -BeExactly '{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}'
            Format-TkUuid -Uuid $uuid -Format Compact | Should -BeExactly '6ba7b8109dad11d180b400c04fd430c8'
            Format-TkUuid -Uuid $uuid -Format Urn     | Should -BeExactly 'urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8'
        }
    }

    Context 'NATO alphabet' {

        It 'spells letters, capitals, digits, symbols and accented letters' {

            $rows = @(ConvertTo-TkNatoAlphabet -Text ('Ab1-' + [char] 0xE9) -MarkCase)

            ($rows | ForEach-Object { $_.Spoken }) -join '|' | Should -Be 'Capital Alfa|Bravo|One|Dash|Echo (with an accent)'
            @(ConvertTo-TkNatoAlphabet -Text 'A')[0].Spoken   | Should -Be 'Alfa'
        }
    }

    Context 'URL parser' {

        It 'decodes every part of a URL' {

            $part = Get-TkUrlPart -Url 'https://admin:secret@Example.com:8443/a%20b/c+d?x=1&y=hello+world&y=2&flag#top%20part'

            $part.Scheme      | Should -Be 'https'
            $part.User        | Should -Be 'admin'
            $part.HasPassword | Should -BeTrue
            $part.AsciiHost   | Should -Be 'example.com'
            $part.Port        | Should -Be 8443
            $part.Path        | Should -Be '/a b/c+d'
            $part.Fragment    | Should -Be 'top part'
            @($part.Query).Count | Should -Be 4

            (@($part.Query | Where-Object { $_.Name -eq 'y' }) | ForEach-Object { $_.Value }) -join '|' | Should -Be 'hello world|2'
            (@($part.Query | Where-Object { $_.Name -eq 'flag' })[0]).Value | Should -BeNullOrEmpty
        }

        It 'names the tricks phishing links use' {

            $trick = Get-TkUrlPart -Url 'https://login.microsoftonline.com@203.0.113.7/reset'

            $trick.AsciiHost               | Should -Be '203.0.113.7'
            ($trick.Warnings -join ' ')    | Should -Match 'not the site'
            ($trick.Warnings -join ' ')    | Should -Match 'IP address'

            $lookalike = Get-TkUrlPart -Url 'http://xn--pple-43d.com/'

            ($lookalike.Warnings -join ' ') | Should -Match 'non-Latin'
            ($lookalike.Warnings -join ' ') | Should -Match 'Not encrypted'

            (Get-TkUrlPart -Url 'www.contoso.com/docs').SchemeAssumed | Should -BeTrue
        }
    }

    Context 'Safe Links' {

        BeforeAll {
            $script:SafeLink = 'https://eur02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.contoso.com%2Freset%3Fid%3D42%26lang%3Dfr&data=05%7C02%7Cjane.doe%40fabrikam.com%7C1b2c%7C72f988bf%7C0%7C0%7C638620000000000000%7CUnknown&sdata=abc%3D&reserved=0'
        }

        It 'finds the destination and the recipient of a Safe Link' {

            $row = @(ConvertFrom-TkSafeLink -Text $script:SafeLink)[0]

            $row.Destination | Should -Be 'https://www.contoso.com/reset?id=42&lang=fr'
            $row.Host        | Should -Be 'www.contoso.com'
            $row.Recipient   | Should -Be 'jane.doe@fabrikam.com'
            $row.Layers      | Should -Be 1
        }

        It 'decodes every link of a pasted e-mail, and unwraps a forwarded one' {

            $wrapped = 'https://nam12.safelinks.protection.outlook.com/?url={0}&data=05%7C02%7C&reserved=0' -f [Uri]::EscapeDataString($script:SafeLink)
            $mail    = "Hello,`r`nplease reset here: $($script:SafeLink).`r`nOr there ($wrapped)`r`nThanks"

            $rows = @(ConvertFrom-TkSafeLink -Text $mail)

            $rows.Count          | Should -Be 2
            $rows[0].Layers      | Should -Be 1
            $rows[1].Layers      | Should -Be 2
            $rows[1].Destination | Should -Be 'https://www.contoso.com/reset?id=42&lang=fr'
            $rows[1].Recipient   | Should -Be 'jane.doe@fabrikam.com'

            @(ConvertFrom-TkSafeLink -Text 'https://www.contoso.com/').Count | Should -Be 0
        }
    }

    Context 'Text diff' {

        It 'finds the lines removed and added, in order' {

            $result = Compare-TkText -Before "alpha`nbravo`ncharlie`ndelta" -After "alpha`nBravo`ncharlie`ndelta`necho"

            $result.Removed | Should -Be 1
            $result.Added   | Should -Be 2

            ($result.Rows | ForEach-Object { '{0}:{1}' -f $_.Kind, $_.Text }) -join '|' |
                Should -Be 'Same:alpha|Removed:bravo|Added:Bravo|Same:charlie|Same:delta|Added:echo'
        }

        It 'handles an empty side' {

            $result = Compare-TkText -Before '' -After "one`ntwo"

            ($result.Rows | ForEach-Object { '{0}:{1}' -f $_.Kind, $_.Text }) -join '|' | Should -Be 'Added:one|Added:two'
            (Compare-TkText -Before '' -After '').Identical | Should -BeTrue
        }

        It 'ignores case and spaces when asked, and keeps three lines around a change' {

            (Compare-TkText -Before 'Hello  World' -After 'hello world' -IgnoreCase -IgnoreWhitespace).Identical | Should -BeTrue

            $before = (1..20 | ForEach-Object { "line $_" }) -join "`n"
            $after  = $before -replace 'line 10', 'line ten'
            $view   = @(Get-TkDiffView -Rows (Compare-TkText -Before $before -After $after).Rows -Context 3)

            $view[0].Kind | Should -Be 'Gap'
            $view[0].Text | Should -Be '6 unchanged line(s)'
            $view[-1].Text | Should -Be '7 unchanged line(s)'
            @($view | Where-Object { $_.Kind -eq 'Same' }).Count | Should -Be 6

            Format-TkDiffText -View $view | Should -Match '(?m)^\+ line ten\r?$'
        }
    }

    Context 'Phone numbers' {

        It 'writes <Text> as <International>' -TestCases @(
            @{ Text = '06 12 34 56 78';       Country = 'FR'; International = '+33 6 12 34 56 78'; National = '06 12 34 56 78'; E164 = '+33612345678' }
            @{ Text = '+33 (0)1 23 45 67 89'; Country = 'FR'; International = '+33 1 23 45 67 89'; National = '01 23 45 67 89'; E164 = '+33123456789' }
            @{ Text = '0044 20 7946 0958';    Country = 'FR'; International = '+44 20 7946 0958';  National = '020 7946 0958';  E164 = '+442079460958' }
            @{ Text = '+1 (415) 555-2671';    Country = 'FR'; International = '+1 415 555 2671';   National = '(415) 555-2671'; E164 = '+14155552671' }
            @{ Text = '079 123 45 67';        Country = 'CH'; International = '+41 79 123 45 67';  National = '079 123 45 67';  E164 = '+41791234567' }
            @{ Text = '+32 470 12 34 56';     Country = 'FR'; International = '+32 470 12 34 56';  National = '0470 12 34 56';  E164 = '+32470123456' }
        ) {
            param($Text, $Country, $International, $National, $E164)

            $number = ConvertFrom-TkPhoneNumber -Text $Text -DefaultCountry $Country

            $number.Valid         | Should -BeTrue
            $number.International | Should -Be $International
            $number.National      | Should -Be $National
            $number.E164          | Should -Be $E164
        }

        It 'says what is wrong with a number, and what kind of French number it is' {

            (ConvertFrom-TkPhoneNumber -Text '06 12 34').Note                        | Should -Match 'has 9 digits'
            (ConvertFrom-TkPhoneNumber -Text '06 12 34 56 78').Type                  | Should -Be 'Mobile'
            (ConvertFrom-TkPhoneNumber -Text '+33 6 12 34 56 78 poste 204').Extension | Should -Be '204'
            (ConvertFrom-TkPhoneNumber -Text 'call me').Valid                         | Should -BeFalse
        }
    }
}

Describe 'DevOps tools' {

    Context 'Crontab' {

        It 'describes <Expression> as <Description>' -TestCases @(
            @{ Expression = '*/15 * * * *';      Description = 'Every 15 minutes' }
            @{ Expression = '30 2 * * 1-5';      Description = 'At 02:30 on Monday to Friday' }
            @{ Expression = '0 8,18 * * *';      Description = 'At 08:00 and 18:00' }
            @{ Expression = '0 0 1 */3 *';       Description = 'At 00:00 on day 1 of the month, every 3 months' }
            @{ Expression = '@weekly';           Description = 'At 00:00 on Sunday' }
            @{ Expression = '0 9 * JAN,JUL MON'; Description = 'At 09:00 on Monday, in January and July' }
            @{ Expression = '0 0 13 * 5';        Description = 'At 00:00 on day 13 of the month or on Friday' }
        ) {
            param($Expression, $Description)

            (ConvertFrom-TkCronExpression -Expression $Expression).Description | Should -Be $Description
        }

        It 'lists the next runs, running on either day when both are set' {

            $from      = [datetime]::new(2026, 9, 14, 3, 0, 0)
            $invariant = [Globalization.CultureInfo]::InvariantCulture

            $weekdays = @(Get-TkCronNextRun -Schedule (ConvertFrom-TkCronExpression -Expression '30 2 * * 1-5') -From $from -Count 3)
            ($weekdays | ForEach-Object { $_.ToString('yyyy-MM-dd HH:mm', $invariant) }) -join ',' | Should -Be '2026-09-15 02:30,2026-09-16 02:30,2026-09-17 02:30'

            $either = @(Get-TkCronNextRun -Schedule (ConvertFrom-TkCronExpression -Expression '0 0 13 * 5') -From $from -Count 5)
            ($either | ForEach-Object { $_.ToString('yyyy-MM-dd', $invariant) }) -join ',' | Should -Be '2026-09-18,2026-09-25,2026-10-02,2026-10-09,2026-10-13'

            @(Get-TkCronNextRun -Schedule (ConvertFrom-TkCronExpression -Expression '0 0 29 2 *') -From $from -Count 1)[0].ToString('yyyy-MM-dd', $invariant) | Should -Be '2028-02-29'
        }

        It 'says what is wrong with an expression' {

            (ConvertFrom-TkCronExpression -Expression '61 * * * *').Error      | Should -Match 'minute field: 61 is outside 0 to 59'
            (ConvertFrom-TkCronExpression -Expression '* * *').Error           | Should -Match 'five fields'
            (ConvertFrom-TkCronExpression -Expression '0 */5 * * * *').Error   | Should -Match 'Quartz'
            (ConvertFrom-TkCronExpression -Expression '0 0 * * FUNDAY').Error  | Should -Match 'day of the week'
            (ConvertFrom-TkCronExpression -Expression '@reboot').Reboot        | Should -BeTrue
        }
    }

    Context 'docker run to Compose' {

        It 'splits a command line the way a shell does' {

            (Split-TkShellWord -Text "a `"b c`" d\ e 'f g' h\`n  i") -join '|' | Should -Be 'a|b c|d e|f g|h|i'
            { Split-TkShellWord -Text 'echo "open' } | Should -Throw
        }

        It 'writes the Compose service a docker run command describes' {

            $command = @'
docker run -d --name web --restart unless-stopped \
  -p 8080:80 -p 127.0.0.1:8443:443 \
  -v nginx-data:/usr/share/nginx/html:ro -v ./conf:/etc/nginx/conf.d \
  -e TZ=Europe/Paris -e "GREETING=hello world" \
  --network proxy --health-cmd "curl -f http://localhost/ || exit 1" --health-interval 30s \
  nginx:1.27 nginx -g "daemon off;"
'@

            $expected = @(
                'services:'
                '  web:'
                '    image: nginx:1.27'
                '    container_name: web'
                '    restart: unless-stopped'
                '    command: ["nginx", "-g", "daemon off;"]'
                '    ports:'
                '      - "8080:80"'
                '      - "127.0.0.1:8443:443"'
                '    volumes:'
                '      - nginx-data:/usr/share/nginx/html:ro'
                '      - ./conf:/etc/nginx/conf.d'
                '    environment:'
                '      - TZ=Europe/Paris'
                '      - GREETING=hello world'
                '    networks:'
                '      - proxy'
                '    healthcheck:'
                '      test: ["CMD-SHELL", "curl -f http://localhost/ || exit 1"]'
                '      interval: 30s'
                'volumes:'
                '  nginx-data:'
                'networks:'
                '  proxy:'
                '    external: true'
            ) -join "`n"

            $result = ConvertFrom-TkDockerRun -Command $command

            ($result.Yaml -replace "`r", '') | Should -Be $expected
            ($result.Notes -join ' ')        | Should -Match 'compose up -d'
        }

        It 'reads grouped short options and attached values, and notes what it leaves out' {

            $result = ConvertFrom-TkDockerRun -Command 'sudo docker run -dit -p8080:80 --rm --privileged --gpus all --mount type=volume,src=pgdata,dst=/var/lib/postgresql/data postgres:17'
            $yaml   = $result.Yaml -replace "`r", ''

            $result.ServiceName | Should -Be 'postgres'
            $yaml | Should -Match '(?m)^    stdin_open: true$'
            $yaml | Should -Match '(?m)^    tty: true$'
            $yaml | Should -Match '(?m)^    privileged: true$'
            $yaml | Should -Match '(?m)^      - "8080:80"$'
            $yaml | Should -Match '(?m)^      - pgdata:/var/lib/postgresql/data$'
            $yaml | Should -Match '(?m)^  pgdata:$'

            ($result.Notes -join ' ') | Should -Match '--rm'
            ($result.Notes -join ' ') | Should -Match '--gpus'

            { ConvertFrom-TkDockerRun -Command 'docker build .' } | Should -Throw
            { ConvertFrom-TkDockerRun -Command 'docker run -p' }  | Should -Throw
        }

        It 'quotes a YAML value only when YAML would misread it' {

            ConvertTo-TkYamlScalar -Value 'nginx:1.27' | Should -Be 'nginx:1.27'
            ConvertTo-TkYamlScalar -Value 'yes'        | Should -Be '"yes"'
            ConvertTo-TkYamlScalar -Value '22:22'      | Should -Be '"22:22"'
            ConvertTo-TkYamlScalar -Value '0755'       | Should -Be '"0755"'
            ConvertTo-TkYamlScalar -Value 'a: b'       | Should -Be '"a: b"'
            ConvertTo-TkYamlScalar -Value '*.log'      | Should -Be '"*.log"'
        }
    }
}

Describe 'HTML documents' {

    It 'reads HTML into the model and writes it back clean' {

        $html = '<html><head><title>x</title></head><body><h1>Title</h1><p onclick="steal()">Hello <strong>bold</strong> and <a href="https://contoso.com">a <em>link</em></a>.<br>Next<script>alert(1)</script></p><ul><li>One</li> <li><u>Two</u></li></ul><p><a href="javascript:alert(1)">bad</a></p><!-- note --></body></html>'

        $expected = @(
            '<h1>Title</h1>'
            '<p>Hello <strong>bold</strong> and <a href="https://contoso.com">a <em>link</em></a>.<br>Next</p>'
            '<ul>'
            '  <li>One</li>'
            '  <li><u>Two</u></li>'
            '</ul>'
            '<p>bad</p>'
        ) -join "`n"

        ((ConvertTo-TkHtmlDocument -Block @(ConvertFrom-TkHtmlDocument -Html $html)) -replace "`r", '') | Should -Be $expected
    }

    It 'merges neighbouring runs with the same formatting and escapes text and links' {

        $runs = @(
            (New-TkEditorInline -Text 'one ' -Bold $true)
            (New-TkEditorInline -Text 'two' -Bold $true -Italic $true)
            (New-TkEditorInline -Text ' & <three>' -Link 'https://contoso.com/?a=1&b=2')
        )

        ConvertTo-TkHtmlInline -Inline $runs | Should -Be '<strong>one <em>two</em></strong><a href="https://contoso.com/?a=1&amp;b=2"> &amp; &lt;three&gt;</a>'
    }
}

Describe 'QR codes' {

    BeforeAll {
        Initialize-TkQrCodeType
    }

    It 'holds exactly the data capacity of the standard, for every version and level' {

        # Data codewords from ISO/IEC 18004 table 7, written down separately
        # from the block tables the encoder computes them from.
        $capacity = @{
            0 = @(19, 34, 55, 80, 108, 136, 156, 194, 232, 274, 324, 370, 428, 461, 523, 589, 647, 721, 795, 861, 932, 1006, 1094, 1174, 1276, 1370, 1468, 1531, 1631, 1735, 1843, 1955, 2071, 2191, 2306, 2434, 2566, 2702, 2812, 2956)
            1 = @(16, 28, 44, 64, 86, 108, 124, 154, 182, 216, 254, 290, 334, 365, 415, 453, 507, 563, 627, 669, 714, 782, 860, 914, 1000, 1062, 1128, 1193, 1267, 1373, 1455, 1541, 1631, 1725, 1812, 1914, 1992, 2102, 2216, 2334)
            2 = @(13, 22, 34, 48, 62, 76, 88, 110, 132, 154, 180, 206, 244, 261, 295, 325, 367, 397, 445, 485, 512, 568, 614, 664, 718, 754, 808, 871, 911, 985, 1033, 1115, 1171, 1231, 1286, 1354, 1426, 1502, 1582, 1666)
            3 = @(9, 16, 26, 36, 46, 60, 66, 86, 100, 122, 140, 158, 180, 197, 223, 253, 283, 313, 341, 385, 406, 442, 464, 514, 538, 596, 628, 661, 701, 745, 793, 845, 901, 961, 986, 1054, 1096, 1142, 1222, 1276)
        }

        foreach ($level in 0..3) {
            for ($version = 1; $version -le 40; $version++) {
                [TkQrCode]::GetDataCodewords($version, $level) | Should -Be $capacity[$level][$version - 1] -Because ('version {0}, level {1}' -f $version, $level)
            }
        }
    }

    It 'computes the Reed-Solomon codewords of the standard example' {

        # HELLO WORLD at version 1-M, the worked example of the standard's tutorials.
        $data = [byte[]] @(32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17)

        ([TkQrCode]::ReedSolomonRemainder($data, [TkQrCode]::ReedSolomonDivisor(10))) -join ',' | Should -Be '196,35,39,119,235,215,231,226,93,23'
    }

    It 'writes the format and version bits of the standard' {

        [Convert]::ToString([TkQrCode]::GetFormatBits(0, 0), 2).PadLeft(15, '0') | Should -Be '111011111000100'
        [Convert]::ToString([TkQrCode]::GetFormatBits(0, 7), 2).PadLeft(15, '0') | Should -Be '110100101110110'
        [Convert]::ToString([TkQrCode]::GetFormatBits(1, 5), 2).PadLeft(15, '0') | Should -Be '100000011001110'
        [Convert]::ToString([TkQrCode]::GetFormatBits(2, 0), 2).PadLeft(15, '0') | Should -Be '011010101011111'
        [Convert]::ToString([TkQrCode]::GetFormatBits(3, 0), 2).PadLeft(15, '0') | Should -Be '001011010001001'

        [Convert]::ToString([TkQrCode]::GetVersionBits(7), 2).PadLeft(18, '0') | Should -Be '000111110010010100'
        [Convert]::ToString([TkQrCode]::GetVersionBits(8), 2).PadLeft(18, '0') | Should -Be '001000010110111100'
    }

    It 'picks the smallest version and draws the fixed patterns' {

        $code = New-TkQrCode -Text 'https://github.com/KyllianFF/Tool-kit' -ErrorCorrection M

        $code.Version | Should -Be 3
        $code.Size    | Should -Be 29

        $modules = $code.Modules

        # Finder corners: dark outer ring, light ring, dark core.
        foreach ($corner in @(@(0, 0), @(0, 22), @(22, 0))) {
            $modules[($corner[0]), ($corner[1])]         | Should -BeTrue
            $modules[($corner[0] + 1), ($corner[1] + 1)] | Should -BeFalse
            $modules[($corner[0] + 3), ($corner[1] + 3)] | Should -BeTrue
        }

        # Timing pattern and the dark module beside the bottom left finder.
        for ($index = 8; $index -lt 21; $index++) {
            $modules[6, $index] | Should -Be ($index % 2 -eq 0)
        }

        $modules[21, 8] | Should -BeTrue

        (New-TkQrCode -Text ('x' * 2953) -ErrorCorrection L).Version | Should -Be 40
        { New-TkQrCode -Text ('x' * 2954) -ErrorCorrection L } | Should -Throw
        { New-TkQrCode -Text '' } | Should -Throw
    }

    It 'writes a Wi-Fi code phones read, and refuses a key the network would not take' {

        ConvertTo-TkWifiQrText -Ssid 'Cafe;Guest' -Key 'p@ss:word"1' -Security WPA | Should -BeExactly 'WIFI:T:WPA;S:Cafe\;Guest;P:p@ss\:word\"1;;'
        ConvertTo-TkWifiQrText -Ssid 'Lobby' -Security nopass -Hidden          | Should -BeExactly 'WIFI:T:nopass;S:Lobby;H:true;;'
        ConvertTo-TkWifiQrText -Ssid 'Lab' -Key 'DEADBEEF' -Security SAE       | Should -BeExactly 'WIFI:T:SAE;S:Lab;P:"DEADBEEF";;'

        { ConvertTo-TkWifiQrText -Ssid 'Office' -Key 'short' -Security WPA }   | Should -Throw
        { ConvertTo-TkWifiQrText -Ssid 'Office' -Key 'secret' -Security nopass } | Should -Throw
        { ConvertTo-TkWifiQrText -Ssid '' -Key 'longenough' }                  | Should -Throw
    }
}

Describe 'Password strength' {

    It 'rates <Text> as very weak, whatever its disguise' -TestCases @(
        @{ Text = 'password' }
        @{ Text = 'P@ssw0rd' }
        @{ Text = 'azerty123' }
        @{ Text = 'Motdepasse' }
        @{ Text = 'drowssap' }
    ) {
        param($Text)

        $strength = Measure-TkPasswordStrength -Text $Text

        $strength.Score | Should -Be 0
        @($strength.Weaknesses | Where-Object { $_.Kind -eq 'Common password' }).Count | Should -BeGreaterThan 0
    }

    It 'finds <Kind> in <Text>' -TestCases @(
        @{ Text = 'qsdfgh2024'; Kind = 'Keyboard' }
        @{ Text = 'qsdfgh2024'; Kind = 'Year' }
        @{ Text = 'Zmnopqr7';   Kind = 'Sequence' }
        @{ Text = 'Kzzzzzzz9';  Kind = 'Repeat' }
        @{ Text = 'Kev14071989'; Kind = 'Date' }
    ) {
        param($Text, $Kind)

        $strength = Measure-TkPasswordStrength -Text $Text -Now ([datetime]::new(2026, 9, 14))

        @($strength.Weaknesses | ForEach-Object { $_.Kind }) | Should -Contain $Kind
        $strength.GuessesLog10 | Should -BeLessThan $strength.BruteForceLog10
    }

    It 'rates a long random password as very strong, beyond any brute force' {

        $strength = Measure-TkPasswordStrength -Text 'q7#Rv9!mK2$wZp4&Lx8Tn5^Jb'

        $strength.Score                | Should -Be 4
        @($strength.Weaknesses).Count  | Should -Be 0
        @($strength.CrackTimes).Count  | Should -Be 4
        $strength.CrackTimes[3].BruteForce | Should -Be 'longer than the age of the universe'
    }

    It 'estimates a generated secret from the entropy of its generator' {

        $strength = Measure-TkPasswordStrength -Text 'abcd-soleil-2024' -KnownEntropyBits 64

        $strength.GuessesLog10          | Should -Be 19.27
        $strength.EstimateLabel         | Should -Be 'Knowing how it was generated'
        @($strength.Weaknesses).Count   | Should -Be 0
    }

    It 'orders the attacks from the slowest to the fastest' {

        $strength = Measure-TkPasswordStrength -Text 'Summer2026'

        $strength.CrackTimes[0].Scenario | Should -BeLike 'Online, throttled*'
        $strength.CrackTimes[3].Scenario | Should -BeLike 'Offline, fast hash*'
        $strength.Advice.Count           | Should -BeGreaterThan 0
    }

    It 'writes <Log10> as <Expected>' -TestCases @(
        @{ Log10 = -1;                                  Expected = 'less than a second' }
        @{ Log10 = 1.5;                                 Expected = '32 seconds' }
        @{ Log10 = [math]::Log10(7200);                 Expected = '2 hours' }
        @{ Log10 = [math]::Log10(86400);                Expected = '1 day' }
        @{ Log10 = [math]::Log10(3 * 31557600);         Expected = '3 years' }
        @{ Log10 = [math]::Log10(5e6 * 31557600);       Expected = '5 million years' }
        @{ Log10 = 20;                                  Expected = 'longer than the age of the universe' }
    ) {
        param($Log10, $Expected)

        Format-TkCrackDuration -Log10Seconds $Log10 | Should -Be $Expected
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

Describe 'HTML report' {

    Context 'Encoding' {

        It 'escapes the five markup characters, ampersand first' {
            ConvertTo-TkHtmlEncoded -Text 'a<b>&"c''' | Should -Be 'a&lt;b&gt;&amp;&quot;c&#39;'
        }

        It 'returns an empty string for empty or null input' {
            ConvertTo-TkHtmlEncoded -Text ''    | Should -Be ''
            ConvertTo-TkHtmlEncoded -Text $null | Should -Be ''
        }
    }

    Context 'Document shell' {

        It 'wraps a body in a complete, self contained document' {
            $html = New-TkHtmlReport -Title 'T' -Subtitle 'S' -Body '<p>hi</p>' `
                -Meta ([ordered] @{ Computer = 'PC1' }) -Note 'N'

            $html          | Should -Match '^<!DOCTYPE html>'
            $html          | Should -Match '<title>T</title>'
            $html          | Should -Match '<style>'         # the stylesheet is inline
            $html          | Should -Not -Match 'https?://'   # nothing is fetched
            $html          | Should -Match '<p>hi</p>'
            $html          | Should -Match '<th>Computer</th><td>PC1</td>'
        }

        It 'escapes values that reach the metadata table and the title' {
            $html = New-TkHtmlReport -Title '<x>' -Body '' -Meta ([ordered] @{ Host = 'a & b' })
            $html | Should -Match '<title>&lt;x&gt;</title>'
            $html | Should -Match '<td>a &amp; b</td>'
        }
    }

    Context 'Security audit report' {

        BeforeAll {
            $script:HtmlFindings = @(
                New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' -Status 'Pass' `
                    -Measured 'ESET Security' -Detail 'Running.' -Weight 10
                New-TkAuditFinding -Id 'FW-001' -Name 'Firewall' -Category 'Network' -Status 'Fail' `
                    -Measured 'Off' -Detail 'The firewall is off.' -Recommendation 'Turn it on.' -Weight 9
                New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2' -Category 'Endpoint' -Status 'NotAssessed' `
                    -Measured 'Not readable' -Detail 'Needs elevation.' -Weight 5
            )
            $script:HtmlReport = ConvertTo-TkSecurityAuditHtml -Finding $script:HtmlFindings -Computer 'PC42'
        }

        It 'is well formed and self contained' {
            { [xml] $script:HtmlReport } | Should -Not -Throw
            $script:HtmlReport | Should -Match '<!DOCTYPE html>'
        }

        It 'renders one card per finding, in its severity class' {
            ([regex]::Matches($script:HtmlReport, '<div class="card ')).Count | Should -Be 3
            $script:HtmlReport | Should -Match 'card sev-pass'
            $script:HtmlReport | Should -Match 'card sev-fail'
            $script:HtmlReport | Should -Match 'card sev-notassessed'
        }

        It 'groups by category once each, in first seen order' {
            # Endpoint appears before Network, and only as a section heading once.
            ([regex]::Matches($script:HtmlReport, '<h2 class="section">Endpoint</h2>')).Count | Should -Be 1
            $script:HtmlReport.IndexOf('>Endpoint<') | Should -BeLessThan $script:HtmlReport.IndexOf('>Network<')
        }

        It 'shows the recommendation only where there is one' {
            $script:HtmlReport | Should -Match 'Turn it on\.'
            # The passing finding carries no recommendation, so exactly one appears.
            ([regex]::Matches($script:HtmlReport, 'class="reco"')).Count | Should -Be 1
        }

        It 'carries the same score the page shows, out of one hundred' {
            $score = Get-TkAuditScore -Finding $script:HtmlFindings
            $script:HtmlReport | Should -Match ('<div class="value">{0}<span>/100</span>' -f [int] $score.Score)
        }

        It 'names the machine it describes' {
            $script:HtmlReport | Should -Match 'PC42'
        }
    }

    Context 'Export by extension' {

        It 'writes HTML for a .html path and JSON otherwise' {
            $findings = @(
                New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' -Status 'Pass' -Detail 'ok' -Weight 10
            )

            $htmlPath = Join-Path ([System.IO.Path]::GetTempPath()) ('tk-{0}.html' -f [guid]::NewGuid())
            $jsonPath = Join-Path ([System.IO.Path]::GetTempPath()) ('tk-{0}.json' -f [guid]::NewGuid())

            try {
                Export-TkSecurityAuditReport -Path $htmlPath -Findings $findings -Confirm:$false | Should -Be $htmlPath
                Export-TkSecurityAuditReport -Path $jsonPath -Findings $findings -Confirm:$false | Should -Be $jsonPath

                (Get-Content -LiteralPath $htmlPath -Raw) | Should -Match '<!DOCTYPE html>'

                $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
                $json.Summary.Pass | Should -Be 1
            }
            finally {
                Remove-Item -LiteralPath $htmlPath, $jsonPath -Force -ErrorAction SilentlyContinue
            }
        }
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

            foreach ($file in @('SecurityAudit.ps1', 'HardeningCheck.ps1', 'AttackSurface.ps1')) {

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

            foreach ($file in @('SecurityAudit.ps1', 'HardeningCheck.ps1', 'AttackSurface.ps1')) {

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

    Context 'Attack surface' {

        It 'reads the driver blocklist switch, and memory integrity enforcing it anyway' {

            (ConvertTo-TkDriverBlocklistFinding -Value 1).Status                                  | Should -Be 'Pass'
            (ConvertTo-TkDriverBlocklistFinding -Value 0).Status                                  | Should -Be 'Fail'
            (ConvertTo-TkDriverBlocklistFinding -Value 0 -MemoryIntegrityRunning $true).Status    | Should -Be 'Pass'
            (ConvertTo-TkDriverBlocklistFinding -Value $null -Build 26100).Measured               | Should -Be 'Not recorded'
            (ConvertTo-TkDriverBlocklistFinding -Value $null -Build 19045).Status                 | Should -Be 'Warning'
        }

        It 'judges memory integrity, and does not ask for it where the hardware cannot run it' {

            $state = { param($running, $configured, $hypervisor) [pscustomobject] @{ MemoryIntegrityRunning = $running; MemoryIntegrityConfigured = $configured; HypervisorAvailable = $hypervisor } }

            (ConvertTo-TkMemoryIntegrityFinding -State (& $state $true $true $true)).Status        | Should -Be 'Pass'
            (ConvertTo-TkMemoryIntegrityFinding -State (& $state $false $false $true)).Measured    | Should -Be 'Off'
            (ConvertTo-TkMemoryIntegrityFinding -State (& $state $false $true $true)).Measured     | Should -BeLike '*not running yet'

            $unsupported = ConvertTo-TkMemoryIntegrityFinding -State (& $state $false $false $false)
            $unsupported.Status     | Should -Be 'Info'
            $unsupported.Applicable | Should -BeFalse

            (ConvertTo-TkMemoryIntegrityFinding -State $null).Status                               | Should -Be 'NotAssessed'
        }

        It 'flags <Value> as a broad <Kind> exclusion' -TestCases @(
            @{ Kind = 'Path';      Value = 'C:\' }
            @{ Kind = 'Path';      Value = 'D:\*' }
            @{ Kind = 'Path';      Value = 'C:\Users\alice\AppData\Local\Temp' }
            @{ Kind = 'Path';      Value = 'C:\Users\alice\Downloads\' }
            @{ Kind = 'Path';      Value = 'C:\Users\alice\AppData\Roaming' }
            @{ Kind = 'Path';      Value = 'C:\Users' }
            @{ Kind = 'Path';      Value = 'C:\ProgramData' }
            @{ Kind = 'Path';      Value = '\\fileserver\share' }
            @{ Kind = 'Process';   Value = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
            @{ Kind = 'Process';   Value = 'mshta.exe' }
            @{ Kind = 'Extension'; Value = '.ps1' }
            @{ Kind = 'Extension'; Value = 'exe' }
        ) {
            param($Kind, $Value)

            $arguments = @{ $Kind = @($Value) }

            $broad = @(Get-TkBroadDefenderExclusion @arguments)

            $broad.Count   | Should -Be 1
            $broad[0].Kind | Should -Be $Kind
        }

        It 'leaves precise exclusions alone' {

            @(Get-TkBroadDefenderExclusion -Path @('C:\Program Files\Veeam\Backup\VeeamAgent', 'D:\SQL\Data\*.mdf') `
                                           -Process @('C:\Program Files\Contoso\agent.exe') `
                                           -Extension @('.mdf', 'ldf')).Count | Should -Be 0
        }

        It 'fails a whole drive or a script host, warns on a download folder, and passes precise exclusions' {

            (ConvertTo-TkDefenderExclusionFinding -Path @('C:\')).Status               | Should -Be 'Fail'
            (ConvertTo-TkDefenderExclusionFinding -Process @('powershell.exe')).Status | Should -Be 'Fail'

            $downloads = ConvertTo-TkDefenderExclusionFinding -Path @('C:\Users\alice\Downloads', 'C:\Tools\scanner')

            $downloads.Status   | Should -Be 'Warning'
            $downloads.Measured | Should -Be '1 of 2 too broad'
            $downloads.Detail   | Should -BeLike '*C:\Users\alice\Downloads*'

            (ConvertTo-TkDefenderExclusionFinding -Path @('C:\Tools\scanner')).Status  | Should -Be 'Pass'
            (ConvertTo-TkDefenderExclusionFinding).Measured                            | Should -Be 'None'
        }

        It 'does not judge exclusions it cannot see, or those of a Defender standing aside' {

            (ConvertTo-TkDefenderExclusionFinding -Readable $false).Status | Should -Be 'NotAssessed'

            $passive = ConvertTo-TkDefenderExclusionFinding -DefenderActive $false -Mode 'Passive Mode' -Path @('C:\')

            $passive.Status     | Should -Be 'Pass'
            $passive.Applicable | Should -BeFalse
        }

        It 'warns about a spooler running for virtual printers only' {

            $virtual = @(
                [pscustomobject] @{ DriverName = 'Microsoft Print To PDF';              PortName = 'PORTPROMPT:' }
                [pscustomobject] @{ DriverName = 'Microsoft XPS Document Writer v4';    PortName = 'PORTPROMPT:' }
                [pscustomobject] @{ DriverName = 'Send to Microsoft OneNote 16 Driver'; PortName = 'nul:' }
            )
            $device = [pscustomobject] @{ DriverName = 'HP OfficeJet Pro 9010 series PCL-3'; PortName = 'WSD-6f1c2a' }

            $idle = ConvertTo-TkSpoolerFinding -Running $true -StartType 'Automatic' -Printer $virtual

            $idle.Status   | Should -Be 'Warning'
            $idle.Measured | Should -Be 'Running, 3 virtual printer(s) only'

            (ConvertTo-TkSpoolerFinding -Running $true -StartType 'Automatic' -Printer (@($virtual) + $device)).Status | Should -Be 'Pass'
            (ConvertTo-TkSpoolerFinding -Running $false -StartType 'Disabled').Status                               | Should -Be 'Pass'
            (ConvertTo-TkSpoolerFinding -Running $true -PrintersRead $false).Status                                  | Should -Be 'NotAssessed'
        }

        It 'requires NTLMv2 session security and 128-bit encryption on both sides' {

            (ConvertTo-TkNtlmSessionFinding -Client 537395200 -Server 537395200).Status | Should -Be 'Pass'
            (ConvertTo-TkNtlmSessionFinding -Client 537395200 -Server 536870912).Status | Should -Be 'Warning'

            $default = ConvertTo-TkNtlmSessionFinding -Client $null -Server $null

            $default.Status   | Should -Be 'Warning'
            $default.Measured | Should -Be 'client: 128-bit required; server: 128-bit required'
        }

        It 'reads the LAN Manager level the way Windows applies it' {

            $unset = ConvertTo-TkLmCompatibilityFinding -Level $null

            $unset.Status        | Should -Be 'Warning'
            $unset.Measured      | Should -BeLike '*level 3*'
            $unset.RemediationId | Should -Be 'set-lm-level'

            (ConvertTo-TkLmCompatibilityFinding -Level 2).Status               | Should -Be 'Fail'
            (ConvertTo-TkLmCompatibilityFinding -Level 5).Status               | Should -Be 'Pass'
            (ConvertTo-TkLmCompatibilityFinding -Level 5).RemediationId        | Should -Be ''
        }

        It 'judges cached sign-ins on a domain member only' {

            (ConvertTo-TkCachedLogonFinding -Count '10' -DomainJoined $false).Applicable | Should -BeFalse
            (ConvertTo-TkCachedLogonFinding -Count '10' -DomainJoined $true).Status      | Should -Be 'Warning'
            (ConvertTo-TkCachedLogonFinding -Count $null -DomainJoined $true).Measured   | Should -Be '10 cached, the Windows default'
            (ConvertTo-TkCachedLogonFinding -Count ' 2 ' -DomainJoined $true).Status     | Should -Be 'Pass'
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
                SignIn     = @(
                    [pscustomobject] @{ Severity = 'Info';    Kind = 'Join';           Value = 'Microsoft Entra hybrid joined' }
                    [pscustomobject] @{ Severity = 'Warning'; Kind = 'Single sign-on'; Value = 'Token not renewed for 30 hours' }
                )
            }

            $script:Tiles = @(ConvertTo-TkDashboardHealth -Snapshot $script:Snapshot `
                                                          -Now ([datetime] '2026-09-13') -SystemDrive 'C:')
        }

        It 'draws one tile per question' {

            $script:Tiles.Count | Should -Be 8
        }

        It 'names the join type and the first sign-in problem' {

            $tile = $script:Tiles | Where-Object { $_.Title -eq 'Sign-in' }

            $tile.Value    | Should -Be 'Hybrid joined'
            $tile.Severity | Should -Be 'Warning'
            $tile.Detail   | Should -Be 'Single sign-on: Token not renewed for 30 hours'
            $tile.Choice   | Should -Be 'Sign-in and management'
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

            foreach ($title in @('Devices', 'Blue screens', 'Sign-in')) {
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
