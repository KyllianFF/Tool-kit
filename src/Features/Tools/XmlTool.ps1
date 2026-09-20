<#
    Toolkit - Features / XML tool

    The XML equivalent of the JSON tool: format a document so it can be read,
    minify it, say whether it is well formed and where it is not, and run an
    XPath query over it. The configs, the GPO backups and the event records an
    administrator meets are XML, and reading one folded onto a single line is
    the first obstacle.

    Read and written as text on the machine with System.Xml, so a document is
    parsed by the same reader the .NET tools use, and the errors are the ones
    they report. A query with a namespace prefix needs the document's own
    prefixes; the common no-namespace case is what this is for.
#>

<#
.SYNOPSIS
    Returns the XML declaration at the front of a text, or empty.
#>
function Get-TkXmlDeclaration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $match = [regex]::Match($Text, '^\s*(<\?xml[^>]*\?>)')
    if ($match.Success) { return $match.Groups[1].Value }
    return ''
}

<#
.SYNOPSIS
    Loads a text as an XML document, throwing on anything malformed.
#>
function Get-TkXmlDocument {
    [CmdletBinding()]
    [OutputType([System.Xml.XmlDocument])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [bool] $PreserveWhitespace = $false
    )

    $document = New-Object System.Xml.XmlDocument
    $document.PreserveWhitespace = $PreserveWhitespace
    $document.LoadXml($Text)
    return $document
}

<#
.SYNOPSIS
    Serialises an XML document to a string, indented or not.

.DESCRIPTION
    The declaration is left off the writer, which would otherwise stamp the
    encoding of the in-memory string rather than the document's, and the
    document's own declaration is put back in front unchanged.

.OUTPUTS
    System.String
#>
function Write-TkXmlString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlDocument] $Document,

        [Parameter(Mandatory)]
        [bool] $Indent,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Declaration = ''
    )

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent             = $Indent
    $settings.IndentChars        = '  '
    $settings.OmitXmlDeclaration = $true

    $builder = New-Object System.Text.StringBuilder
    $writer  = [System.Xml.XmlWriter]::Create($builder, $settings)

    $Document.Save($writer)
    $writer.Flush()
    $writer.Close()

    $body = $builder.ToString()

    if ($Declaration) {
        return $Declaration + $(if ($Indent) { "`r`n" } else { '' }) + $body
    }

    return $body
}

<#
.SYNOPSIS
    Turns the exception of a failed parse into a readable line of text.

.DESCRIPTION
    PowerShell wraps the exception a .NET method throws, so the XmlException with
    its line and position is the base of the chain, not the exception caught.

.OUTPUTS
    System.String
#>
function Format-TkXmlException {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $exception = $ErrorRecord.Exception.GetBaseException()

    if ($exception -is [System.Xml.XmlException]) {
        return ('Line {0}, position {1}: {2}' -f $exception.LineNumber, $exception.LinePosition, $exception.Message)
    }

    return $exception.Message
}

<#
.SYNOPSIS
    Says whether a text is well-formed XML, and where it is not.

.OUTPUTS
    PSCustomObject with Valid and Error.
#>
function Test-TkXmlWellFormed {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    try {
        [void] (Get-TkXmlDocument -Text $Text)
        return [pscustomobject] @{ Valid = $true; Error = '' }
    }
    catch {
        return [pscustomobject] @{ Valid = $false; Error = (Format-TkXmlException -ErrorRecord $_) }
    }
}

<#
.SYNOPSIS
    Runs an XPath query over an XML text and returns the matches.

.DESCRIPTION
    An element match is returned as its markup, an attribute or a text match as
    its value. No match is not an error; it is reported as none found.

.OUTPUTS
    System.String[]
#>
function Select-TkXmlNode {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $XPath
    )

    $document = Get-TkXmlDocument -Text $Text
    $nodes    = $document.SelectNodes($XPath)

    $results = New-Object System.Collections.Generic.List[string]

    foreach ($node in $nodes) {
        switch ($node.NodeType) {
            'Element'   { $results.Add([string] $node.OuterXml) }
            'Attribute' { $results.Add(('{0}="{1}"' -f $node.Name, $node.Value)) }
            default     { $results.Add([string] $node.Value) }
        }
    }

    return @($results)
}

<#
.SYNOPSIS
    Formats, minifies, validates or queries an XML text.

.PARAMETER Operation
    Format, Minify, Validate or XPath.

.PARAMETER XPath
    The query, for the XPath operation.

.OUTPUTS
    System.String
#>
function Invoke-TkXmlOperation {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [ValidateSet('Format', 'Minify', 'Validate', 'XPath')]
        [string] $Operation,

        [Parameter()]
        [AllowEmptyString()]
        [string] $XPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 'Paste an XML document.'
    }

    if ($Operation -eq 'Validate') {
        $check = Test-TkXmlWellFormed -Text $Text
        if ($check.Valid) { return 'Well formed.' }
        return ('Not well formed. {0}' -f $check.Error)
    }

    $declaration = Get-TkXmlDeclaration -Text $Text

    try {
        switch ($Operation) {

            'Format' {
                return Write-TkXmlString -Document (Get-TkXmlDocument -Text $Text) -Indent $true -Declaration $declaration
            }

            'Minify' {
                return Write-TkXmlString -Document (Get-TkXmlDocument -Text $Text) -Indent $false -Declaration $declaration
            }

            'XPath' {
                if (-not $XPath.Trim()) {
                    return 'Enter an XPath expression, such as //book/title or //@id.'
                }

                # Not named $matches: that is a PowerShell automatic variable.
                try {
                    $hits = @(Select-TkXmlNode -Text $Text -XPath $XPath)
                }
                catch {
                    if ($_.Exception.GetBaseException() -is [System.Xml.XPath.XPathException]) {
                        return ('That is not a valid XPath expression: {0}' -f $_.Exception.GetBaseException().Message)
                    }
                    throw
                }

                if ($hits.Count -eq 0) {
                    return 'No node matched that expression.'
                }

                $lines = @(('{0} match(es):' -f $hits.Count), '') + $hits
                return ($lines -join [Environment]::NewLine)
            }
        }
    }
    catch {
        return ('Not well formed. {0}' -f (Format-TkXmlException -ErrorRecord $_))
    }
}
