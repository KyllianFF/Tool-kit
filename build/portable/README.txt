===============================================================================
 Toolkit - portable edition
 Version {{VERSION}} ({{COMMIT}})
 Built {{DATE}}
===============================================================================

This is the offline build of the Toolkit. It runs from this folder with no
network access: the interface and every data catalog sit here as readable
files, not downloaded on demand.

It is the same code as the online one-liner, only laid out differently. The
online build packs everything into one file so it can be piped straight into
PowerShell. That single file carries the catalogs as large base64 blocks,
which is exactly the shape a lot of antivirus engines treat as "packed" and
worth a second look. This edition keeps the script readable and leaves the
data in plain files beside it, so there is nothing that looks hidden.


-------------------------------------------------------------------------------
 What is in this folder
-------------------------------------------------------------------------------

  Toolkit.ps1        The program. Readable PowerShell, no embedded blobs.
  MainWindow.xaml    The interface layout, read at startup.
  data\              The catalogs: applications, tweaks, fixes, references...
  Start-Toolkit.cmd  A launcher that runs Toolkit.ps1 the right way.
  README.txt         This file.
  SHA256SUMS.txt     A checksum for every file, so you can verify the set.


-------------------------------------------------------------------------------
 How to run it
-------------------------------------------------------------------------------

  Double-click  Start-Toolkit.cmd

or, from a PowerShell prompt opened in this folder:

  powershell.exe -ExecutionPolicy Bypass -Sta -File .\Toolkit.ps1

The graphical interface needs Windows PowerShell (powershell.exe), which ships
with Windows. PowerShell 7 (pwsh) also works but must be started with -Sta.

To run without the interface, for a report on the console:

  powershell.exe -ExecutionPolicy Bypass -File .\Toolkit.ps1 -NoGui
  powershell.exe -ExecutionPolicy Bypass -File .\Toolkit.ps1 -Report All -OutFile .\report.json


-------------------------------------------------------------------------------
 If Windows blocks the script
-------------------------------------------------------------------------------

When a file is downloaded or extracted from a downloaded archive, Windows tags
it with a "mark of the web" (a hidden Zone.Identifier stream) that says it came
from the internet. PowerShell then refuses to run it, or prompts, depending on
the execution policy. This is a normal Windows safety feature, not a sign that
anything is wrong with the file.

Two honest ways to clear it, once you have verified the checksums below:

  1. Right-click Toolkit.ps1 -> Properties -> tick "Unblock" -> OK.
     Do the same for MainWindow.xaml if prompted.

  2. Or, from a PowerShell prompt in this folder:

       Get-ChildItem -Recurse | Unblock-File

The launcher passes -ExecutionPolicy Bypass for its own process only. That
does not change any policy on the machine; it lasts exactly as long as that one
PowerShell window. It is the documented way to run a local script you trust.


-------------------------------------------------------------------------------
 Verify what you run
-------------------------------------------------------------------------------

Every file has a SHA256 in SHA256SUMS.txt. To check the whole set on the
machine, from a PowerShell prompt in this folder:

  Get-Content .\SHA256SUMS.txt | ForEach-Object {
      $hash, $name = $_ -split '\s+', 2
      $actual = (Get-FileHash -LiteralPath $name.Trim() -Algorithm SHA256).Hash
      '{0}  {1}' -f $(if ($actual -eq $hash) { 'OK  ' } else { 'FAIL' }), $name.Trim()
  }

If Toolkit.ps1 is code-signed (see below), you can also check the signature:

  Get-AuthenticodeSignature .\Toolkit.ps1 | Format-List Status, SignerCertificate


-------------------------------------------------------------------------------
 For the security team: signing and allowlisting
-------------------------------------------------------------------------------

This tool is an administration and diagnostics toolkit. Some of what it does
looks, from an endpoint sensor's point of view, like the things it is meant to
watch for: it reads the registry, queries WMI/CIM, inspects services and
scheduled tasks, and reports on the security posture of the machine. That is
the job, done in the open. It does not obfuscate itself, disable any security
product, or hide from logging, and it is not built to.

The right way to run it on managed machines is to allow it explicitly, not to
weaken the endpoint. Two levers, in order of preference:

  1. Code signing (best). Sign Toolkit.ps1 with a certificate your
     organisation trusts, then allowlist by publisher. The repository ships
     build\New-CodeSigningCertificate.ps1 (to create a signing certificate)
     and build\Sign-Toolkit.ps1 (to sign and timestamp the file). A publisher
     rule survives a rebuild; a hash rule does not.

  2. Path or hash allowlist. Point the exception at this folder or at the
     SHA256 of Toolkit.ps1 in SHA256SUMS.txt.

  Microsoft Defender for Endpoint / Defender AV:
    Add an "Allowed / Indicator" for the file's SHA256, or a signed-publisher
    allow via Application Control (WDAC/AppLocker). For local Defender AV, a
    folder exclusion (Add-MpPreference -ExclusionPath) is possible but blunt;
    prefer the signed-publisher route.

  CrowdStrike Falcon:
    Add a hash allowlist entry (IOC Management) for the SHA256, or a Sensor
    Visibility / ML exclusion scoped to this folder path. Prefer allowlisting
    by hash of a signed build.

  ESET:
    Add the SHA256 to the detection exclusions, or exclude this folder path in
    the real-time protection settings, scoped as narrowly as possible.

If an endpoint product still flags a signed, allowlisted build, that is a
policy decision for the security team, and the answer is a scoped exception
they own - not a change to how the tool is built. Nothing here tries to get
around a sensor.


-------------------------------------------------------------------------------
 What this tool does not do
-------------------------------------------------------------------------------

  - It does not phone home. The portable edition makes no network request to
    run; features that need the network (winget, VirusTotal lookups) only reach
    out when you use them, to the service they name.
  - It is not packed, obfuscated or encrypted. The script is readable text.
  - It does not touch any antivirus, EDR, logging or Windows security setting
    to make itself run.

  Source: https://github.com/KyllianFF/Tool-kit
