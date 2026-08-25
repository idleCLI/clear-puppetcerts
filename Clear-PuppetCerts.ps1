#Requires -Version 7.0

<#
.SYNOPSIS
  Clears Puppet certificates (client-side and CA-side) via AWX / Ansible Automation Platform.

.DESCRIPTION
  Two AWX jobs per node:
    1. Client - "puppet ssl clean --localca" on the target host.
    2. Server - "puppetserver ca clean --certname <certname>" on the puppetserver.

  Jobs are polled to completion, failures capture stdout. Prints a summary and exits
  non-zero if any node failed, so it's safe to run from a scheduler.

  Needs PowerShell 7+ (7.4 LTS or newer, ideally - 7.1 is EOL). Calls exit, so invoke
  it rather than dot-sourcing.

.PARAMETER Server
  A single target FQDN.

.PARAMETER ServerList
  Path to a text file of FQDNs: one per line, blank lines ignored, lines starting with # ignored.

.PARAMETER AwxBaseUrl
  Base URL of the AWX / AAP controller, e.g. https://controller.example.com

.PARAMETER ApiBaseOverride
  Skip API auto-discovery and use this base directly.
  AAP example: https://host/api/controller/v2
  AWX example: https://host/api/v2

.PARAMETER ClientTemplateId
  Job template ID that performs the client-side "puppet ssl clean --localca".

.PARAMETER ServerTemplateId
  Job template ID that performs "puppetserver ca clean --certname <certname>".

.PARAMETER ServerOnly
  Only revoke on the CA. For hosts that are dead, wiped, or already rebuilt.

.PARAMETER ContinueOnClientFailure
  Client cleanup failing no longer skips the CA revoke. Node still counts as failed.

.PARAMETER SkipCertificateCheck
  Skip TLS validation for controller requests. For self-signed or internal-CA certs this
  host doesn't trust. Scoped to this script only. Better fix: trust the internal CA root.

.PARAMETER SkipPreflight
  Skip the one-time check that both job templates accept extra variables on launch.

.PARAMETER PollSeconds
  Interval between job status polls.

.PARAMETER TimeoutMinutes
  Max wait per job, not per run. Worth lowering for long lists.

.PARAMETER HttpTimeoutSec
  Per-request HTTP timeout.

.EXAMPLE
  .\Clear-PuppetCerts.ps1 -Server server1.domain.com -AwxBaseUrl https://controller

.EXAMPLE
  .\Clear-PuppetCerts.ps1 -ServerList /tmp/servers.txt -AwxBaseUrl https://controller -SkipCertificateCheck

.EXAMPLE
  .\Clear-PuppetCerts.ps1 -Server deadbox.domain.com -ServerOnly

.NOTES
  Both templates need "Prompt on launch" enabled for variables. Without it AWX ignores
  extra_vars, cleans the wrong host, and still reports success. Preflight catches it.
#>

[CmdletBinding(DefaultParameterSetName = "Interactive")]
param(
  [Parameter(ParameterSetName = "Single", Mandatory)]
  [string]$Server,

  [Parameter(ParameterSetName = "List", Mandatory)]
  [string]$ServerList,

  [string]$AwxBaseUrl = "https://hni0835x.bud.morley.dev",

  [string]$ApiBaseOverride = "",

  [int]$ClientTemplateId = 85,
  [int]$ServerTemplateId = 86,

  [switch]$ServerOnly,
  [switch]$ContinueOnClientFailure,
  [switch]$SkipCertificateCheck,
  [switch]$SkipPreflight,

  [int]$PollSeconds = 3,
  [int]$TimeoutMinutes = 20,
  [int]$HttpTimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Don't put the SecurityProtocol juggling back. PS7 negotiates TLS from OS policy,
# and pinning the list is how you end up blocking 1.3.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-HasProperty {
  # Strict mode throws on missing properties, so check before touching anything the API sent back.
  param(
    $InputObject,
    [Parameter(Mandatory)][string]$Name
  )

  if ($null -eq $InputObject -or $null -eq $InputObject.PSObject) { return $false }
  return $InputObject.PSObject.Properties.Name -contains $Name
}

function Get-HttpStatusCode {
  # HTTP errors carry a status. DNS, TLS and timeout failures don't, so those come
  # back 0 and get treated as transient.
  param([Parameter(Mandatory)]$ErrorRecord)

  $ex = $ErrorRecord.Exception
  if ($ex -is [Microsoft.PowerShell.Commands.HttpResponseException]) {
    return [int]$ex.Response.StatusCode
  }

  return 0
}

function Test-PermanentHttpError {
  param([Parameter(Mandatory)][int]$StatusCode)
  return $StatusCode -in 400, 401, 403, 404
}

function ConvertTo-SafeString {
  param($Value)
  return $null -eq $Value ? "" : [string]$Value
}

# ---------------------------------------------------------------------------
# Resolve target list
# ---------------------------------------------------------------------------

function Read-ServerListFile {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "ServerList file not found: $Path"
  }

  # Select-Object, not Sort-Object. Don't reshuffle someone's list on them.
  return @(
    Get-Content -LiteralPath $Path |
      ForEach-Object { (ConvertTo-SafeString $_).Trim() } |
      Where-Object { $_ -and -not $_.StartsWith("#") } |
      Select-Object -Unique
  )
}

$Servers = switch ($PSCmdlet.ParameterSetName) {
  "Single" { @((ConvertTo-SafeString $Server).Trim()) }
  "List"   { Read-ServerListFile -Path $ServerList }
  default {
    $inputValue = (ConvertTo-SafeString (Read-Host "Enter server FQDN OR path to .txt file")).Trim().Trim('"')

    if ([string]::IsNullOrWhiteSpace($inputValue)) { throw "No input provided." }

    if (Test-Path -LiteralPath $inputValue -PathType Leaf) {
      Read-ServerListFile -Path $inputValue
    } else {
      @($inputValue)
    }
  }
}

# @() or a one-element result comes back as a scalar.
$Servers = @($Servers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($Servers.Count -eq 0) {
  throw "No valid server names found."
}

Write-Host "Target node(s): $($Servers.Count)"

# ---------------------------------------------------------------------------
# Credentials and shared request defaults
# ---------------------------------------------------------------------------

# Strict mode throws on unassigned vars, so look before you read.
$credVar = Get-Variable -Name AwxCred -Scope Script -ErrorAction SilentlyContinue
if ($null -eq $credVar -or $null -eq $credVar.Value) {
  $script:AwxCred = Get-Credential -Message "AWX/Tower credentials"
}

if ($null -eq $script:AwxCred) {
  throw "No credentials supplied."
}

# PS7 does the base64 and sends it preemptively. No hand-rolled auth header.
$script:RestDefaults = @{
  Authentication = 'Basic'
  Credential     = $script:AwxCred
  Headers        = @{ Accept = 'application/json' }
  TimeoutSec     = $HttpTimeoutSec
}

if ($SkipCertificateCheck) {
  Write-Warning "TLS certificate validation is disabled for requests to the controller."
  Write-Warning "Credentials are sent as basic auth. Prefer importing the internal CA root into the trust store."
  $script:RestDefaults['SkipCertificateCheck'] = $true
}

if ($AwxBaseUrl -notmatch '^https://') {
  Write-Warning "$AwxBaseUrl is not HTTPS. Credentials will cross the network in cleartext."
  $script:RestDefaults['AllowUnencryptedAuthentication'] = $true
}

function Invoke-AwxRest {
  # One door for every controller call, so auth, timeouts and cert policy can't drift.
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Uri,
    [ValidateSet('Get', 'Post')][string]$Method = 'Get',
    $Body,
    [int]$TimeoutSec = 0
  )

  $params = $script:RestDefaults.Clone()
  $params['Uri']    = $Uri
  $params['Method'] = $Method

  if ($TimeoutSec -gt 0) { $params['TimeoutSec'] = $TimeoutSec }

  if ($null -ne $Body) {
    $params['Body']        = $Body | ConvertTo-Json -Depth 20
    $params['ContentType'] = 'application/json'
  }

  return Invoke-RestMethod @params
}

# ---------------------------------------------------------------------------
# API discovery
# ---------------------------------------------------------------------------

function Get-AwxApiBase {
  param(
    [Parameter(Mandatory)][string]$AwxBaseUrl,
    [string]$ApiBaseOverride = ""
  )

  if (-not [string]::IsNullOrWhiteSpace($ApiBaseOverride)) {
    return $ApiBaseOverride.TrimEnd('/')
  }

  $base = $AwxBaseUrl.TrimEnd('/')
  $sawAuthFailure = $false
  $lastError = ""

  # Controller path first. AAP's current_version claims /api/v2/ and is lying.
  foreach ($candidate in "$base/api/controller/v2", "$base/api/v2") {
    try {
      Invoke-AwxRest -Uri "$candidate/ping/" | Out-Null
      return $candidate
    } catch {
      $status = Get-HttpStatusCode -ErrorRecord $_
      if ($status -in 401, 403) { $sawAuthFailure = $true }
      $lastError = $_.Exception.Message
      Write-Verbose "Probe failed for ${candidate}: HTTP $status"
    }
  }

  # Nothing bit, so ask the API where it lives.
  try {
    $apiInfo = Invoke-AwxRest -Uri "$base/api/"
    if (Test-HasProperty -InputObject $apiInfo -Name 'current_version') {
      $version = ConvertTo-SafeString $apiInfo.current_version
      if (-not [string]::IsNullOrWhiteSpace($version)) {
        return ($base + $version).TrimEnd('/')
      }
    }
  } catch {
    $status = Get-HttpStatusCode -ErrorRecord $_
    if ($status -in 401, 403) { $sawAuthFailure = $true }
    $lastError = $_.Exception.Message
  }

  if ($sawAuthFailure) {
    throw "Authentication to $base was rejected (HTTP 401/403). Check the username and password, and whether the account requires a token instead of basic auth."
  }

  throw "Unable to determine API base for $base. Last error: $lastError`nTry -ApiBaseOverride, or -SkipCertificateCheck if the controller uses an untrusted certificate."
}

# ---------------------------------------------------------------------------
# Job template preflight
# ---------------------------------------------------------------------------

function Test-AwxTemplateAcceptsVars {
  # With ask_variables_on_launch off, AWX takes the launch, bins the extra_vars, runs
  # against the template's own hosts and calls it successful. Green light, nothing cleaned.
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][int]$TemplateId,
    [Parameter(Mandatory)][string]$Label
  )

  try {
    $tmpl = Invoke-AwxRest -Uri "$ApiBase/job_templates/$TemplateId/"
  } catch {
    $status = Get-HttpStatusCode -ErrorRecord $_
    if ($status -eq 404) {
      throw "$Label template ID $TemplateId does not exist (HTTP 404). If this is a workflow template, it must be launched from /workflow_job_templates/ instead."
    }
    throw "Could not read $Label template ${TemplateId}: $($_.Exception.Message)"
  }

  $name = (Test-HasProperty -InputObject $tmpl -Name 'name') ? (ConvertTo-SafeString $tmpl.name) : "(unnamed)"
  Write-Host "  ${Label}: [$TemplateId] $name"

  if (Test-HasProperty -InputObject $tmpl -Name 'ask_variables_on_launch') {
    if (-not $tmpl.ask_variables_on_launch) {
      throw "$Label template '$name' ($TemplateId) doesn't have 'Prompt on launch' enabled for variables. AWX will ignore the certname, clean the wrong host, and still report success. Enable it, or -SkipPreflight if you're sure."
    }
  } else {
    Write-Warning "  Could not confirm ask_variables_on_launch for $Label template $TemplateId."
  }
}

# ---------------------------------------------------------------------------
# Job launch and polling
# ---------------------------------------------------------------------------

function Invoke-AwxLaunch {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][int]$TemplateId,
    [Parameter(Mandatory)][hashtable]$ExtraVars
  )

  try {
    return Invoke-AwxRest -Uri "$ApiBase/job_templates/$TemplateId/launch/" -Method Post `
      -Body @{ extra_vars = $ExtraVars }
  } catch {
    $status  = Get-HttpStatusCode -ErrorRecord $_
    $message = $_.Exception.Message

    throw ($status switch {
      401     { "Launch rejected: authentication failed (HTTP 401)." }
      403     { "Launch rejected: the account lacks Execute permission on template $TemplateId (HTTP 403)." }
      404     { "Launch rejected: template $TemplateId not found (HTTP 404)." }
      default { "Launch failed for template ${TemplateId}: $message" }
    })
  }
}

function Get-LaunchedJobId {
  param([Parameter(Mandatory)]$LaunchResponse)

  $out = 0
  foreach ($name in 'id', 'job', 'workflow_job') {
    if (Test-HasProperty -InputObject $LaunchResponse -Name $name) {
      $value = $LaunchResponse.$name
      if ($null -ne $value -and [int]::TryParse($value.ToString(), [ref]$out) -and $out -gt 0) {
        return $out
      }
    }
  }

  $keys = ($null -ne $LaunchResponse -and $null -ne $LaunchResponse.PSObject) `
    ? ($LaunchResponse.PSObject.Properties.Name -join ", ") : "(none)"

  throw "Launch response did not contain a usable job id. Keys: $keys"
}

function Get-AwxJobStdout {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][int]$JobId,
    [ValidateSet('txt', 'json', 'ansi', 'html', 'txt_download', 'ansi_download')]
    [string]$Format = 'txt'
  )

  try {
    return Invoke-AwxRest -Uri "$ApiBase/jobs/$JobId/stdout/?format=$Format" -TimeoutSec 60
  } catch {
    # Don't let a failed stdout fetch bury the real error.
    return "(could not retrieve stdout for job ${JobId}: $($_.Exception.Message))"
  }
}

function Wait-AwxJob {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][int]$JobId,
    [int]$PollSeconds = 3,
    [int]$TimeoutMinutes = 20
  )

  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $terminal = 'successful', 'failed', 'error', 'canceled'
  $transientFailures = 0
  $maxTransientFailures = 10

  while ((Get-Date) -lt $deadline) {
    try {
      $job = Invoke-AwxRest -Uri "$ApiBase/jobs/$JobId/"
      $transientFailures = 0
    } catch {
      $status = Get-HttpStatusCode -ErrorRecord $_

      # These won't fix themselves. Retrying burns the full timeout and then lies about why.
      if (Test-PermanentHttpError -StatusCode $status) {
        throw "Polling job $JobId failed permanently (HTTP $status): $($_.Exception.Message)"
      }

      $transientFailures++
      if ($transientFailures -ge $maxTransientFailures) {
        throw "Polling job $JobId failed $maxTransientFailures times in a row. Last error: $($_.Exception.Message)"
      }

      Write-Verbose "Transient poll failure ($transientFailures/$maxTransientFailures) for job ${JobId}: $($_.Exception.Message)"
      Start-Sleep -Seconds $PollSeconds
      continue
    }

    $status = (Test-HasProperty -InputObject $job -Name 'status') `
      ? (ConvertTo-SafeString $job.status).ToLowerInvariant() : ""

    if ($status -in $terminal) { return $job }

    Start-Sleep -Seconds $PollSeconds
  }

  throw "Timeout waiting for job $JobId after $TimeoutMinutes minute(s). The job may still be running in AWX."
}

function Assert-ExtraVarsApplied {
  # Belt and braces behind the preflight: did the job actually get our certname?
  param(
    $Job,
    [Parameter(Mandatory)][string]$ExpectedCertname,
    [Parameter(Mandatory)][string]$Label
  )

  if (-not (Test-HasProperty -InputObject $Job -Name 'extra_vars')) { return }

  $raw = ConvertTo-SafeString $Job.extra_vars
  if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-Warning "  $Label job reported no extra_vars. The template may have ignored the certname."
    return
  }

  try {
    $parsed = $raw | ConvertFrom-Json
  } catch {
    Write-Verbose "Could not parse extra_vars for $Label job: $($_.Exception.Message)"
    return
  }

  if (Test-HasProperty -InputObject $parsed -Name 'certname') {
    $actual = ConvertTo-SafeString $parsed.certname
    if ($actual -ne $ExpectedCertname) {
      Write-Warning "  $Label job ran with certname '$actual' but '$ExpectedCertname' was requested."
    }
  } else {
    Write-Warning "  $Label job extra_vars did not include certname. The template may have discarded it."
  }
}

function Invoke-AwxCleanupStep {
  # Launch, wait, check the vars came through, throw with stdout if not.
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][int]$TemplateId,
    [Parameter(Mandatory)][hashtable]$ExtraVars,
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Certname,
    [int]$PollSeconds = 3,
    [int]$TimeoutMinutes = 20
  )

  $launch = Invoke-AwxLaunch -ApiBase $ApiBase -TemplateId $TemplateId -ExtraVars $ExtraVars
  $jobId  = Get-LaunchedJobId -LaunchResponse $launch
  Write-Host "  $Label job launched: $jobId"

  $job = Wait-AwxJob -ApiBase $ApiBase -JobId $jobId -PollSeconds $PollSeconds -TimeoutMinutes $TimeoutMinutes

  $status = (Test-HasProperty -InputObject $job -Name 'status') `
    ? (ConvertTo-SafeString $job.status).ToLowerInvariant() : "unknown"

  if ($status -ne "successful") {
    $stdout = Get-AwxJobStdout -ApiBase $ApiBase -JobId $jobId
    throw "$Label cleanup failed (job ${jobId}, status: $status).`n--- STDOUT ---`n$stdout"
  }

  Assert-ExtraVarsApplied -Job $job -ExpectedCertname $Certname -Label $Label
  Write-Host "  $Label cleanup successful (job $jobId)."

  return $jobId
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$ApiBase = Get-AwxApiBase -AwxBaseUrl $AwxBaseUrl -ApiBaseOverride $ApiBaseOverride
Write-Host "Using API base: $ApiBase"

if (-not $SkipPreflight) {
  Write-Host "`nPreflight:"
  if (-not $ServerOnly) {
    Test-AwxTemplateAcceptsVars -ApiBase $ApiBase -TemplateId $ClientTemplateId -Label "Client"
  }
  Test-AwxTemplateAcceptsVars -ApiBase $ApiBase -TemplateId $ServerTemplateId -Label "Server"
}

if ($ServerOnly) {
  Write-Host "`n-ServerOnly specified: client cleanup will be skipped."
}

$results = [System.Collections.Generic.List[object]]::new()

foreach ($rawNode in $Servers) {
  $node = (ConvertTo-SafeString $rawNode).Trim()
  if ([string]::IsNullOrWhiteSpace($node)) { continue }

  Write-Host "`n===== Processing $node ====="

  $clientState = "skipped"
  $serverState = "not attempted"
  $nodeFailed  = $false
  $notes       = [System.Collections.Generic.List[string]]::new()

  # --- 1) Client cleanup ---------------------------------------------------
  if (-not $ServerOnly) {
    try {
      Invoke-AwxCleanupStep -ApiBase $ApiBase -TemplateId $ClientTemplateId `
        -ExtraVars @{ v_host = $node; certname = $node } -Label "Client" -Certname $node `
        -PollSeconds $PollSeconds -TimeoutMinutes $TimeoutMinutes | Out-Null

      $clientState = "successful"
    } catch {
      $clientState = "failed"
      $nodeFailed  = $true
      $notes.Add("client: $($_.Exception.Message)")

      Write-Warning "  Client cleanup failed for ${node}: $($_.Exception.Message)"

      if ($ContinueOnClientFailure) {
        Write-Warning "  Continuing to server cleanup because -ContinueOnClientFailure was specified."
      } else {
        Write-Warning "  Skipping server cleanup. Re-run with -ServerOnly or -ContinueOnClientFailure to revoke the cert anyway."

        $results.Add([pscustomobject]@{
          Server    = $node
          Client    = $clientState
          Server_CA = $serverState
          Notes     = ($notes -join " | ")
        })
        continue
      }
    }
  }

  # --- 2) Server (CA) cleanup ----------------------------------------------
  try {
    Invoke-AwxCleanupStep -ApiBase $ApiBase -TemplateId $ServerTemplateId `
      -ExtraVars @{ certname = $node } -Label "Server" -Certname $node `
      -PollSeconds $PollSeconds -TimeoutMinutes $TimeoutMinutes | Out-Null

    $serverState = "successful"
  } catch {
    $serverState = "failed"
    $nodeFailed  = $true
    $notes.Add("server: $($_.Exception.Message)")
    Write-Warning "  Server cleanup failed for ${node}: $($_.Exception.Message)"
  }

  if (-not $nodeFailed) {
    Write-Host "  Completed for $node"
  }

  $results.Add([pscustomobject]@{
    Server    = $node
    Client    = $clientState
    Server_CA = $serverState
    Notes     = ($notes -join " | ")
  })
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host "`n===== Summary ====="
$results | Format-Table -AutoSize Server, Client, Server_CA | Out-Host

$failed = @($results | Where-Object { $_.Client -eq "failed" -or $_.Server_CA -ne "successful" })

if ($failed.Count -gt 0) {
  Write-Host ""
  Write-Warning "$($failed.Count) of $($results.Count) node(s) did not complete cleanly:"
  foreach ($f in $failed) {
    Write-Warning "  $($f.Server): $($f.Notes)"
  }
  exit 1
}

Write-Host "`nAll $($results.Count) node(s) processed successfully."
exit 0