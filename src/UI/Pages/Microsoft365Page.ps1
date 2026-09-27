<#
    Toolkit - UI / Microsoft 365 page

    Wires the page: the connectivity test, the apps and accounts reader, and
    the fixes and the report that go with them. Both readers run in the
    background and draw a document in the output, like the reports.
#>

<#
.SYNOPSIS
    Wires the Microsoft 365 page.
#>
function Initialize-TkMicrosoft365Page {
    [CmdletBinding()]
    param()

    $tenant = Get-TkControl -Name 'M365Tenant'

    if ($tenant) {
        $tenant.Text = [string] (Get-TkContext).Settings['M365Tenant']
    }

    Register-TkClick -Name 'BtnM365Connectivity' -Action { Invoke-TkM365ConnectivityFromUi }
    Register-TkClick -Name 'BtnM365Clients'      -Action { Invoke-TkM365ClientFromUi }

    # The fixes ask first and check their rights, as they do on the Fixes page.
    Register-TkClick -Name 'BtnM365FixOffice'   -Action { Invoke-TkFixFromUi -FixId 'reset-office-activation' }
    Register-TkClick -Name 'BtnM365FixTeams'    -Action { Invoke-TkFixFromUi -FixId 'clear-teams-cache' }
    Register-TkClick -Name 'BtnM365FixOneDrive' -Action { Invoke-TkFixFromUi -FixId 'reset-onedrive' }

    Register-TkClick -Name 'BtnM365Identity' -Action {
        Show-TkPage -Name 'Diagnostics'
        [void] (Select-TkTab -TabControlName 'DiagnosticsTabs' -Header 'Reports')
        [void] (Select-TkListChoice -ListName 'DiagnosticChoices' -Title 'Sign-in and management')
    }
}

<#
.SYNOPSIS
    Tests the connection to Microsoft 365 and draws what it finds.
#>
function Invoke-TkM365ConnectivityFromUi {
    [CmdletBinding()]
    param()

    $tenant = ([string] (Get-TkControl -Name 'M365Tenant').Text).Trim()

    if (-not (Test-TkM365TenantName -Tenant $tenant)) {
        Set-TkStatus -Text 'The tenant name is the first part of contoso.sharepoint.com: letters, digits and hyphens.'
        return
    }

    # Remembered, since it is the same tenant every time on a given site.
    $settings = (Get-TkContext).Settings
    if ([string] $settings['M365Tenant'] -ne $tenant) {
        $settings['M365Tenant'] = $tenant
        Save-TkSettings
    }

    Invoke-TkBackgroundAction -StatusText 'Testing the connection to Microsoft 365...' `
        -ParameterList @{ tenant = $tenant } `
        -ScriptBlock {
            param($tenant)
            Test-TkM365Connectivity -Tenant $tenant
        } `
        -OnComplete {
            param($result)

            $test = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Verdicts'] } | Select-Object -Last 1

            if (-not $test) {
                return
            }

            $document = New-TkFlowDocument
            Add-TkHeading   -Document $document -Text 'Connection to Microsoft 365' -Level 1
            Add-TkParagraph -Document $document -Muted -Text $(if ($test.Tenant) {
                'Each endpoint Microsoft publishes for a workload, resolved and opened on its port, from this machine. Tenant: {0}.' -f $test.Tenant
            } else {
                'Each endpoint Microsoft publishes for a workload, resolved and opened on its port, from this machine. Type the tenant name to test SharePoint and OneDrive too.'
            })

            foreach ($verdict in @($test.Verdicts)) {
                Add-TkSeverityLine -Document $document -Severity $verdict.Severity -Heading $verdict.Heading -Detail $verdict.Detail -Note $verdict.Note
            }

            Add-TkSeverityLine -Document $document -Severity $test.Tls.Severity -Heading $test.Tls.Heading -Detail $test.Tls.Detail -Note $test.Tls.Note

            if ($test.Teams.Answered) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Teams calls can use UDP' -Detail ('{0} ms' -f $test.Teams.Milliseconds) `
                    -Note 'A Teams relay answered on UDP 3478, the path Teams prefers for audio and video.'
            }
            else {
                Add-TkSeverityLine -Document $document -Severity 'Warning' -Heading 'Teams calls cannot use UDP' `
                    -Note 'No Teams relay answered on UDP 3478. Calls then fall back to TCP or HTTPS, where audio and video stutter and freeze. Allow UDP 3478 to 3481 outbound to Microsoft 365.'
            }

            if ($test.ProxySet) {
                Add-TkParagraph -Document $document -Muted -Text 'A proxy is set on this machine. Microsoft asks for its Optimize endpoints (Exchange, SharePoint, Teams) to go direct, bypassing the proxy.'
            }

            Add-TkHeading -Document $document -Text 'Endpoints' -Level 2
            Add-TkTable -Document $document -Column @('Workload', 'Endpoint', 'Resolved', 'Connected', 'Time') -Weight @(1.6, 2.4, 0.7, 0.8, 0.6) `
                -Row @($test.Results | ForEach-Object {
                    , @($_.Name, ('{0}:{1}' -f $_.Host, $_.Port), $(if ($_.Resolved) { 'yes' } else { 'no' }), $(if ($_.Connected) { 'yes' } else { 'no' }),
                        $(if ($_.Connected) { '{0} ms' -f $_.Milliseconds } else { '' }))
                })

            Set-TkDocument -ControlName 'M365Output' -Document $document

            $failed = @($test.Verdicts | Where-Object { $_.Severity -ne 'Pass' }).Count
            Set-TkStatus -Text $(if ($failed -eq 0) { 'Every Microsoft 365 workload is reachable.' } else { '{0} workload(s) not fully reachable.' -f $failed })
        }
}

<#
.SYNOPSIS
    Reads the Microsoft 365 apps and accounts and draws what it finds.
#>
function Invoke-TkM365ClientFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the Microsoft 365 apps and accounts...' `
        -ScriptBlock { Get-TkM365ClientReport } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Findings'] } | Select-Object -Last 1

            if (-not $report) {
                return
            }

            $document = New-TkFlowDocument
            Add-TkHeading   -Document $document -Text 'Apps and accounts' -Level 1
            Add-TkParagraph -Document $document -Muted -Text 'Office, OneDrive, Teams and Outlook as they are set up for this Windows account. Read only; the related fixes above change things, and ask first.'

            foreach ($finding in @($report.Findings)) {
                Add-TkSeverityLine -Document $document -Severity $finding.Severity -Heading $finding.Heading -Detail $finding.Detail -Note $finding.Note
            }

            Set-TkDocument -ControlName 'M365Output' -Document $document
            Set-TkStatus -Text 'Microsoft 365 apps and accounts read.'
        }
}
