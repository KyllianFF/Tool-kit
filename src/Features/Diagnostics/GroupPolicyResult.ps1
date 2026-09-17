<#
    Toolkit - Features / Diagnostics / Group Policy results

    What Group Policy actually applied to this machine and this user, from the
    resultant set of policy (RSoP) that gpresult produces. Read only: gpresult
    reports, it does not change anything.

    The computer side of the report needs administrator rights to read; without
    them only the user side is returned, which is noted rather than failed.
#>

<#
.SYNOPSIS
    Reads the text of a single child element, by local name.

.DESCRIPTION
    The gpresult XML is namespaced, so children are matched on their local name
    to avoid carrying a namespace manager through every lookup.

.PARAMETER Node
    The parent element.

.PARAMETER Name
    The child's local name.

.OUTPUTS
    System.String, empty when the child is absent.
#>
function Get-TkXmlChildText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode] $Node,

        [Parameter(Mandatory)]
        [string] $Name
    )

    foreach ($child in $Node.ChildNodes) {
        if ($child.LocalName -eq $Name) {
            return [string] $child.InnerText
        }
    }

    return ''
}

<#
.SYNOPSIS
    Reads a gpresult RSoP document into applied policies and group membership.

.DESCRIPTION
    Walks the computer and user sections. Each Group Policy object is classified
    as applied when it is enabled, its security filtering allows it and access
    was not denied; the rest are reported as not applied, with the reason. The
    security groups the token carries, which drive filtering, are listed too.

.PARAMETER Document
    The gpresult /x XML, as an XmlDocument.

.OUTPUTS
    PSCustomObject with ReadTime, Computer and User.
#>
function ConvertFrom-TkGpResultXml {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [xml] $Document
    )

    $readSection = {
        param($sectionLocalName)

        $section = @($Document.SelectNodes(("//*[local-name()='{0}']" -f $sectionLocalName)))[0]

        if ($null -eq $section) {
            return $null
        }

        $gpos = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($gpo in @($section.ChildNodes | Where-Object { $_.LocalName -eq 'GPO' })) {

            $enabled  = (Get-TkXmlChildText -Node $gpo -Name 'Enabled') -eq 'true'
            $denied   = (Get-TkXmlChildText -Node $gpo -Name 'AccessDenied') -eq 'true'
            $filtered = (Get-TkXmlChildText -Node $gpo -Name 'FilterAllowed') -eq 'true'
            $applied  = $enabled -and $filtered -and -not $denied

            $reason = if ($applied) { '' }
                      elseif ($denied) { 'access denied' }
                      elseif (-not $filtered) { 'filtered out (security or WMI filter)' }
                      elseif (-not $enabled) { 'disabled' }
                      else { 'not applied' }

            $gpos.Add([pscustomobject] @{
                Name    = Get-TkXmlChildText -Node $gpo -Name 'Name'
                Link    = Get-TkXmlChildText -Node $gpo -Name 'Link'
                Applied = $applied
                Reason  = $reason
            })
        }

        $groups = @($section.ChildNodes |
                    Where-Object { $_.LocalName -eq 'SecurityGroup' } |
                    ForEach-Object { Get-TkXmlChildText -Node $_ -Name 'Name' } |
                    Where-Object { $_ })

        return [pscustomobject] @{
            Name           = Get-TkXmlChildText -Node $section -Name 'Name'
            Gpos           = $gpos.ToArray()
            SecurityGroups = @($groups)
        }
    }

    $readTime = @($Document.SelectNodes("//*[local-name()='ReadTime']"))[0]

    return [pscustomobject] @{
        ReadTime = if ($readTime) { $readTime.InnerText } else { '' }
        Computer = (& $readSection 'ComputerResults')
        User     = (& $readSection 'UserResults')
    }
}

<#
.SYNOPSIS
    Runs gpresult and reads the resultant set of policy.

.DESCRIPTION
    Runs gpresult /x to a temporary file and parses it. The computer side needs
    administrator rights; without them gpresult returns only the user side, and
    the report says so. The temporary file is removed afterwards.

.OUTPUTS
    PSCustomObject as ConvertFrom-TkGpResultXml returns, or $null on failure.
#>
function Get-TkGroupPolicyResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('tk-gpresult-{0}.xml' -f [guid]::NewGuid())

    try {
        # /f overwrites without asking; output is discarded, the XML is the result.
        $null = & gpresult.exe /x $path /f 2>&1

        if (-not (Test-Path -LiteralPath $path)) {
            return $null
        }

        [xml] $document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        return ConvertFrom-TkGpResultXml -Document $document
    }
    catch {
        Write-TkLog -Level Warning -Category 'Diagnostics' -Message ('gpresult could not be read: {0}' -f $_.Exception.Message)
        return $null
    }
    finally {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}
