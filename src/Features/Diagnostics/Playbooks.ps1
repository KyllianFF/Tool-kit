<#
    Toolkit - Features / Diagnostics / Troubleshooting playbooks

    Guided sequences for the problems a support call is actually about. A
    playbook does not do anything new: it puts the reports, checks and fixes the
    toolkit already has into the order a technician would work through them, so a
    "the machine is slow" call has a first step rather than a blank page.

    Each step names where it goes (a page, a tab, a report in a chooser) so the
    interface can take the operator there and run it. The targets are data, so a
    test can check that every page and report a step points at exists; a step
    aimed at a renamed report would otherwise open the right page and quietly
    run nothing.
#>

<#
.SYNOPSIS
    The troubleshooting playbooks, each an ordered list of steps.

.DESCRIPTION
    A step has a Title and a Detail, a Kind for its label (Report, Check, Fix or
    Manual), and a destination: a Page, optionally a TabControl and Tab, and
    optionally a List and the Choice to select in it. A Manual step has no
    destination and is guidance only.

.OUTPUTS
    PSCustomObject[] with Id, Title, Symptom and Steps.
#>
function Get-TkPlaybook {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    # Helpers so the definitions below read as a table rather than a wall of
    # repeated property names.
    $report = {
        param($title, $choice, $detail)
        [pscustomobject] @{ Kind = 'Report'; Title = $title; Detail = $detail; Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = $choice }
    }
    $hunt = {
        param($title, $choice, $detail)
        [pscustomobject] @{ Kind = 'Check'; Title = $title; Detail = $detail; Page = 'Security'; TabControl = 'SecurityTabs'; Tab = 'Threat hunting'; List = 'HuntChoices'; Choice = $choice }
    }
    $page = {
        param($kind, $title, $pageName, $tabControl, $tab, $detail)
        [pscustomobject] @{ Kind = $kind; Title = $title; Detail = $detail; Page = $pageName; TabControl = $tabControl; Tab = $tab; List = ''; Choice = '' }
    }
    $manual = {
        param($title, $detail)
        [pscustomobject] @{ Kind = 'Manual'; Title = $title; Detail = $detail; Page = ''; TabControl = ''; Tab = ''; List = ''; Choice = '' }
    }

    return @(
        [pscustomobject] @{
            Id      = 'slow-machine'
            Title   = 'The machine is slow'
            Symptom = 'Everything takes too long: applications, start-up, or the whole desktop.'
            Steps   = @(
                (& $report 'Performance'   'Performance'   'See what is using the processor, memory and disks right now, and what starts with Windows.')
                (& $report 'Disk space'    'Disk space'    'A nearly full system drive slows everything. Check how full it is and what fills it.')
                (& $report 'Storage health' 'Storage health' 'A failing or worn disk shows up as reallocated sectors or SSD wear.')
                (& $hunt   'Autostart and persistence' 'Autostart and persistence' 'Too much starting with Windows is a common cause; this also catches something unwanted.')
                (& $manual 'Trim what runs at start-up' 'From the Performance report, disable the start-up entries that are not needed, or uninstall the applications behind them on the Software page.')
            )
        }

        [pscustomobject] @{
            Id      = 'no-network'
            Title   = 'No internet or a network problem'
            Symptom = 'No connectivity, an intermittent connection, or a site that will not load.'
            Steps   = @(
                (& $page 'Check' 'Run the network diagnostics' 'Network' 'NetworkTabs' 'Diagnostics' 'The connectivity chain, port checks, a subnet sweep and DNS lookups, in one place.')
                (& $report 'Proxy' 'Proxy' 'A wrong or stale proxy is a frequent cause of "no internet" when the link itself is fine.')
                (& $page 'Check' 'Look at the adapters' 'Network' 'NetworkTabs' 'Adapters' 'Confirm the active adapter has an address, a gateway and DNS servers.')
                (& $manual 'Reset the proxy if it is wrong' 'If the Proxy report shows a proxy that should not be there, the Fixes page has a one-click proxy reset.')
            )
        }

        [pscustomobject] @{
            Id      = 'cannot-sign-in'
            Title   = 'Cannot sign in to the domain or Microsoft 365'
            Symptom = 'A sign-in that is refused, a single sign-on that keeps prompting, or a device that lost its trust.'
            Steps   = @(
                (& $report 'Sign-in and management' 'Sign-in and management' 'The join type, the single sign-on token, the domain controller, the secure channel and the clock against Kerberos.')
                (& $report 'Group Policy' 'Group Policy' 'Which policies applied, in case one is blocking sign-in or a script.')
                (& $report 'Local accounts' 'Local accounts' 'Rule out a locked, disabled or expired local account.')
                (& $manual 'Fix the clock or the trust' 'A clock more than five minutes off breaks Kerberos; the Fixes page can resync it and repair the secure channel.')
            )
        }

        [pscustomobject] @{
            Id      = 'disk-full'
            Title   = 'The disk is full'
            Symptom = 'Low disk space warnings, or a drive with no room left.'
            Steps   = @(
                (& $report 'Disk space' 'Disk space' 'The biggest folders and files, and the caches safe to empty, each with its size.')
                (& $report 'Storage health' 'Storage health' 'Confirm the drive is healthy while you are here.')
                (& $manual 'Empty the safe caches' 'The Disk space report lists what Storage Sense and Disk Cleanup remove. The Fixes page can clear the OneDrive and Teams caches.')
            )
        }

        [pscustomobject] @{
            Id      = 'suspected-malware'
            Title   = 'Suspected malware or compromise'
            Symptom = 'Odd behaviour, a security alert, or a machine you have reason to distrust.'
            Steps   = @(
                (& $page 'Check' 'Run the security audit' 'Security' 'SecurityTabs' 'Security audit' 'Where the machine stands against the baseline, and what an attacker on it reaches next.')
                (& $hunt 'Defender detections' 'Defender detections' 'What the antivirus has already caught.')
                (& $hunt 'Autostart and persistence' 'Autostart and persistence' 'Where something unwanted would arrange to run again.')
                (& $hunt 'Network exposure' 'Network exposure' 'What is listening and reachable from the network.')
                (& $hunt 'Event log triage' 'Event log triage' 'Failed logons, cleared logs and new services in the last week (needs administrator rights).')
                (& $hunt 'USB history' 'USB history' 'What was plugged in, in case data left that way.')
                (& $manual 'Preserve the evidence' 'Do not power the machine off if you may need memory or volatile state. Isolate it from the network instead.')
            )
        }

        [pscustomobject] @{
            Id      = 'crashes'
            Title   = 'Blue screens or crashes'
            Symptom = 'The machine restarts on its own, freezes, or shows a stop error.'
            Steps   = @(
                (& $report 'Crashes' 'Crashes' 'Each blue screen with its stop code explained and the drivers loaded before it.')
                (& $report 'Devices' 'Devices' 'A device with a problem code, often a driver, is a common cause.')
                (& $report 'Storage health' 'Storage health' 'A failing disk causes crashes that look like anything.')
                (& $report 'Performance' 'Performance' 'Overheating or an overloaded machine can crash under load.')
            )
        }

        [pscustomobject] @{
            Id      = 'printer'
            Title   = 'Printing does not work'
            Symptom = 'Nothing prints, the queue is stuck, or a printer has vanished.'
            Steps   = @(
                (& $report 'Printing' 'Printing' 'The spooler, the printers, their ports, drivers and queues.')
                (& $manual 'Restart the spooler' 'If the queue is stuck, the Fixes page can restart the print spooler and clear the queue.')
            )
        }

        [pscustomobject] @{
            Id      = 'update-stuck'
            Title   = 'Windows Update is stuck or failing'
            Symptom = 'An update that will not install, keeps failing, or hangs.'
            Steps   = @(
                (& $report 'Update history' 'Update history' 'Which update failed and with what code.')
                (& $report 'Pending reboot' 'Pending reboot' 'A pending restart blocks further updates until it is done.')
                (& $page 'Check' 'Check Windows Update' 'Software' 'SoftwareTabs' 'Windows Update' 'See what is offered now and install it once the machine is in a clean state.')
                (& $manual 'Repair Windows Update' 'If updates keep failing, the Fixes page can repair the Windows Update components.')
            )
        }
    )
}
