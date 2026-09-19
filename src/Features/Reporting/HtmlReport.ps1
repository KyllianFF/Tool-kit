<#
    Toolkit - Features / Reporting / HTML report

    A printable, self contained HTML rendering of a report, meant to be saved
    next to a ticket and opened by anyone without the toolkit. Everything is
    inline: one file, no stylesheet to lose, no font to fetch, no script. It
    prints to a page a manager or an auditor can read, which the JSON export
    beside it does not.

    The document is deliberately light and neutral rather than themed. A report
    is read on paper and in a browser that is not ours, where the palette of the
    application means nothing and a dark background wastes toner.
#>

<#
.SYNOPSIS
    Escapes the five characters that would otherwise be read as HTML markup.

.DESCRIPTION
    Every value that reaches the page is machine data, a computer name, a path,
    a measured setting, and any of it may contain a bracket or an ampersand.
    Left raw it would break the page or, worse, be read as markup. The ampersand
    is replaced first, or the entities that follow would be escaped a second time.

.PARAMETER Text
    The text to escape.

.OUTPUTS
    System.String
#>
function ConvertTo-TkHtmlEncoded {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return ''
    }

    return $Text.
        Replace('&', '&amp;').
        Replace('<', '&lt;').
        Replace('>', '&gt;').
        Replace('"', '&quot;').
        Replace("'", '&#39;')
}

<#
.SYNOPSIS
    The inline stylesheet shared by every HTML report.

.DESCRIPTION
    Held in one function so the shell and the tests read the same rules, and so
    the severity classes an adapter uses are guaranteed to be defined. The print
    block flattens the tints to ink friendly borders and stops a card from being
    split across two pages.

.OUTPUTS
    System.String
#>
function Get-TkHtmlReportStyle {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        padding: 32px 16px;
        background: #f4f5f7;
        color: #1b1f24;
        font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
    }
    .page { max-width: 900px; margin: 0 auto; }
    header.report { border-bottom: 2px solid #d0d7de; padding-bottom: 16px; margin-bottom: 24px; }
    header.report h1 { margin: 0 0 4px; font-size: 26px; }
    header.report .subtitle { color: #57606a; font-size: 15px; }
    table.meta { border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    table.meta th { text-align: left; color: #57606a; font-weight: 600; padding: 2px 16px 2px 0; vertical-align: top; white-space: nowrap; }
    table.meta td { padding: 2px 0; }
    .note { margin-top: 12px; color: #57606a; font-size: 12px; font-style: italic; }
    h2.section { font-size: 18px; margin: 28px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #e1e4e8; }
    .score { display: flex; align-items: center; gap: 20px; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; padding: 20px 24px; }
    .score .value { font-size: 44px; font-weight: 700; line-height: 1; }
    .score .value span { font-size: 20px; color: #57606a; font-weight: 400; }
    .score .counts { display: flex; flex-wrap: wrap; gap: 8px; }
    .pill { display: inline-block; border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 600; border: 1px solid transparent; }
    .card { background: #fff; border: 1px solid #d0d7de; border-left-width: 4px; border-radius: 8px; padding: 12px 16px; margin: 10px 0; }
    .card .head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
    .card .code { font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px; color: #57606a; }
    .card .name { font-weight: 600; font-size: 15px; }
    .card .measured { margin-left: auto; color: #57606a; font-size: 13px; }
    .card .detail { margin: 6px 0 0; }
    .card .reco { margin: 6px 0 0; color: #1b1f24; }
    .card .reco strong { color: #57606a; font-weight: 600; }
    .sev-pass        { border-left-color: #1a7f37; }
    .sev-pass .pill,        .pill.sev-pass        { background: #eaf6ec; color: #1a7f37; border-color: #a7d6b3; }
    .sev-warning     { border-left-color: #d29922; }
    .sev-warning .pill,     .pill.sev-warning     { background: #fff7e6; color: #9a6700; border-color: #e8cc8a; }
    .sev-fail        { border-left-color: #cf222e; }
    .sev-fail .pill,        .pill.sev-fail        { background: #fdecea; color: #b32424; border-color: #f0b4b4; }
    .sev-info        { border-left-color: #0969da; }
    .sev-info .pill,        .pill.sev-info        { background: #eaf2fb; color: #0b5cad; border-color: #b3d1f2; }
    .sev-notassessed { border-left-color: #8c959f; }
    .sev-notassessed .pill, .pill.sev-notassessed { background: #f3f4f6; color: #57606a; border-color: #d0d7de; }
    footer.report { margin-top: 32px; padding-top: 12px; border-top: 1px solid #e1e4e8; color: #8c959f; font-size: 12px; }
    @media print {
        body { background: #fff; padding: 0; }
        .card, .score { break-inside: avoid; }
        .card { border-left-width: 4px; }
    }
'@
}

<#
.SYNOPSIS
    Wraps a body in a complete, standalone HTML document.

.DESCRIPTION
    Returns the whole file: doctype, head with the inline style, a header made
    of the title, subtitle and a metadata table, then the body, then a footer.
    Nothing is fetched from the network, so the file opens the same on a machine
    that has never heard of the toolkit.

.PARAMETER Title
    The report title, shown in the tab and as the heading.

.PARAMETER Subtitle
    A line under the title, such as the machine and the date.

.PARAMETER Meta
    An ordered dictionary of label to value, rendered as the metadata table.

.PARAMETER Body
    The HTML of the body, already built and escaped by the caller.

.PARAMETER Note
    A cautionary line under the metadata, such as the scope of the check.

.OUTPUTS
    System.String
#>
function New-TkHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Subtitle = '',

        [Parameter()]
        [System.Collections.IDictionary] $Meta = @{},

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Body,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Note = ''
    )

    $metaRows = ''
    foreach ($key in $Meta.Keys) {
        $metaRows += '<tr><th>{0}</th><td>{1}</td></tr>' -f `
            (ConvertTo-TkHtmlEncoded $key), (ConvertTo-TkHtmlEncoded ([string] $Meta[$key]))
    }

    $metaTable = if ($metaRows) { '<table class="meta">{0}</table>' -f $metaRows } else { '' }
    $noteHtml  = if ($Note)     { '<p class="note">{0}</p>' -f (ConvertTo-TkHtmlEncoded $Note) } else { '' }
    $subHtml   = if ($Subtitle) { '<div class="subtitle">{0}</div>' -f (ConvertTo-TkHtmlEncoded $Subtitle) } else { '' }

    $builder = New-Object System.Text.StringBuilder
    [void] $builder.AppendLine('<!DOCTYPE html>')
    [void] $builder.AppendLine('<html lang="en">')
    [void] $builder.AppendLine('<head>')
    [void] $builder.AppendLine('<meta charset="utf-8" />')
    [void] $builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
    [void] $builder.AppendLine(('<title>{0}</title>' -f (ConvertTo-TkHtmlEncoded $Title)))
    [void] $builder.AppendLine('<style>')
    [void] $builder.AppendLine((Get-TkHtmlReportStyle))
    [void] $builder.AppendLine('</style>')
    [void] $builder.AppendLine('</head>')
    [void] $builder.AppendLine('<body>')
    [void] $builder.AppendLine('<div class="page">')
    [void] $builder.AppendLine('<header class="report">')
    [void] $builder.AppendLine(('<h1>{0}</h1>' -f (ConvertTo-TkHtmlEncoded $Title)))
    [void] $builder.AppendLine($subHtml)
    [void] $builder.AppendLine($metaTable)
    [void] $builder.AppendLine($noteHtml)
    [void] $builder.AppendLine('</header>')
    [void] $builder.AppendLine($Body)
    [void] $builder.AppendLine('<footer class="report">Generated by the toolkit. This file is self contained and can be attached to a ticket.</footer>')
    [void] $builder.AppendLine('</div>')
    [void] $builder.AppendLine('</body>')
    [void] $builder.AppendLine('</html>')

    return $builder.ToString()
}

<#
.SYNOPSIS
    The statuses a finding can carry, mapped to a label and a CSS class.

.DESCRIPTION
    Ordered as a summary reads best, what failed first. A function rather than a
    file scope variable so a worker never has to have it seeded, and so the CSS
    classes it names stay next to the stylesheet that defines them.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function Get-TkHtmlSeverityMap {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    return [ordered] @{
        Fail        = @{ Label = 'Fail';         Class = 'sev-fail' }
        Warning     = @{ Label = 'Warning';      Class = 'sev-warning' }
        Pass        = @{ Label = 'Pass';         Class = 'sev-pass' }
        Info        = @{ Label = 'Info';         Class = 'sev-info' }
        NotAssessed = @{ Label = 'Not assessed'; Class = 'sev-notassessed' }
    }
}

<#
.SYNOPSIS
    Renders a security audit, its findings and its score, as an HTML document.

.DESCRIPTION
    Groups the findings by category in the order they were run, one card each
    with its status, identifier, measured value, explanation and, where there
    is one, its recommendation. The score and the count of each outcome sit at
    the top, the same numbers the screen shows.

.PARAMETER Finding
    The findings from Invoke-TkSecurityAudit.

.PARAMETER Score
    The score object from Get-TkAuditScore. Read from the findings when omitted.

.PARAMETER Computer
    The machine the audit describes. Defaults to this one.

.OUTPUTS
    System.String
#>
function ConvertTo-TkSecurityAuditHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding,

        [Parameter()]
        [pscustomobject] $Score,

        [Parameter()]
        [string] $Computer = $env:COMPUTERNAME
    )

    if (-not $Score) {
        $Score = Get-TkAuditScore -Finding @($Finding)
    }

    $severity  = Get-TkHtmlSeverityMap
    $infoCount = @($Finding | Where-Object { $_.Status -eq 'Info' }).Count

    # --- Score and counts -------------------------------------------------
    $counts = [ordered] @{
        Fail        = $Score.Failed
        Warning     = $Score.Warnings
        Pass        = $Score.Passed
        Info        = $infoCount
        NotAssessed = $Score.NotAssessed
    }

    $pills = ''
    foreach ($status in $counts.Keys) {
        $meta   = $severity[$status]
        $pills += '<span class="pill {0}">{1}: {2}</span>' -f `
            $meta.Class, (ConvertTo-TkHtmlEncoded $meta.Label), ([int] $counts[$status])
    }

    $body = New-Object System.Text.StringBuilder
    [void] $body.AppendLine('<h2 class="section">Summary</h2>')
    [void] $body.AppendLine('<div class="score">')
    [void] $body.AppendLine(('<div class="value">{0}<span>/100</span></div>' -f [int] $Score.Score))
    [void] $body.AppendLine(('<div class="counts">{0}</div>' -f $pills))
    [void] $body.AppendLine('</div>')

    # --- Findings by category, first seen order ---------------------------
    $categories = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Finding) {
        if (-not $categories.Contains([string] $item.Category)) {
            $categories.Add([string] $item.Category)
        }
    }

    foreach ($category in $categories) {

        [void] $body.AppendLine(('<h2 class="section">{0}</h2>' -f (ConvertTo-TkHtmlEncoded $category)))

        foreach ($item in @($Finding | Where-Object { [string] $_.Category -eq $category })) {

            $meta = $severity[[string] $item.Status]
            if (-not $meta) { $meta = @{ Label = [string] $item.Status; Class = 'sev-info' } }

            [void] $body.AppendLine(('<div class="card {0}">' -f $meta.Class))
            [void] $body.AppendLine('<div class="head">')
            [void] $body.AppendLine(('<span class="pill {0}">{1}</span>' -f $meta.Class, (ConvertTo-TkHtmlEncoded $meta.Label)))
            [void] $body.AppendLine(('<span class="code">{0}</span>' -f (ConvertTo-TkHtmlEncoded ([string] $item.Id))))
            [void] $body.AppendLine(('<span class="name">{0}</span>' -f (ConvertTo-TkHtmlEncoded ([string] $item.Name))))

            if ($item.Measured) {
                [void] $body.AppendLine(('<span class="measured">{0}</span>' -f (ConvertTo-TkHtmlEncoded ([string] $item.Measured))))
            }

            [void] $body.AppendLine('</div>')

            if ($item.Detail) {
                [void] $body.AppendLine(('<p class="detail">{0}</p>' -f (ConvertTo-TkHtmlEncoded ([string] $item.Detail))))
            }

            if ($item.Recommendation) {
                [void] $body.AppendLine(('<p class="reco"><strong>Recommendation:</strong> {0}</p>' -f (ConvertTo-TkHtmlEncoded ([string] $item.Recommendation))))
            }

            [void] $body.AppendLine('</div>')
        }
    }

    $meta = [ordered] @{
        Computer  = $Computer
        Generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Score     = '{0} / 100' -f [int] $Score.Score
        Controls  = @($Finding).Count
    }

    $version = try { (Get-TkContext).Version } catch { '' }
    if ($version) { $meta['Toolkit'] = $version }

    return New-TkHtmlReport `
        -Title 'Local security audit' `
        -Subtitle ('{0} - {1}' -f $Computer, (Get-Date -Format 'yyyy-MM-dd')) `
        -Meta $meta `
        -Note 'Local hygiene check. It does not replace a CIS or ANSSI benchmark run.' `
        -Body $body.ToString()
}
