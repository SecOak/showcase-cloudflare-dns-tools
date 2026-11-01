#Requires -Version 7.0
<#
.SYNOPSIS
    Read-only report of DNS records and email-auth posture for every Cloudflare zone the token can see.

.DESCRIPTION
    Reads a Cloudflare API token from a local file, verifies it, lists all zones, pulls every DNS record,
    and builds a per-domain email-security summary (MX, SPF, DMARC, DKIM, null MX).
    Makes NO changes. Exports two timestamped CSVs and prints the summary.

.PARAMETER TokenPath
    Path to a file containing only the Cloudflare API token.

.PARAMETER OutputPath
    Folder for CSV exports. Created if missing.

.EXAMPLE
    .\Get-CloudflareDnsReport.ps1

.EXAMPLE
    .\Get-CloudflareDnsReport.ps1 -Verbose

.NOTES
    Author:      Zach Anger (drafted with Claude)
    Date:        2026-11-01
    Token perms: Zone:Read, DNS:Edit (this script only uses read endpoints)
    Modules:     None (Invoke-RestMethod against api.cloudflare.com)
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$TokenPath = (Join-Path $HOME '.cloudflare\dns.token'),

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $HOME '.cloudflare\reports')
)

$ErrorActionPreference = 'Stop'
$ApiBase = 'https://api.cloudflare.com/client/v4'

function Invoke-CfRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$MaxRetries = 4
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -in 429, 503, 504 -and $attempt -lt $MaxRetries) {
                $retryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                $delay = if ($retryAfter) { [int]$retryAfter } else { [math]::Pow(2, $attempt) + (Get-Random -Maximum 1.0) }
                Write-Warning "Cloudflare returned $status. Retrying in $([math]::Round($delay,1))s (attempt $attempt of $MaxRetries)."
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Get-CfPagedResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$PerPage = 50
    )
    $page = 1
    do {
        $sep = if ($Path -like '*`?*') { '&' } else { '?' }
        $resp = Invoke-CfRequest -Uri "$ApiBase$Path$($sep)per_page=$PerPage&page=$page" -Headers $Headers
        if (-not $resp.success) { throw "Cloudflare API error on $Path : $($resp.errors | ConvertTo-Json -Compress)" }
        $resp.result
        $totalPages = $resp.result_info.total_pages
        $page++
    } while ($totalPages -and $page -le $totalPages)
}

function Get-CfEmailPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )
    $apex  = $Records | Where-Object name -eq $Domain
    $mx    = @($apex | Where-Object type -eq 'MX')
    $spf   = @($apex | Where-Object { $_.type -eq 'TXT' -and $_.content -match 'v=spf1' })
    $dmarc = @($Records | Where-Object { $_.name -eq "_dmarc.$Domain" -and $_.type -eq 'TXT' })
    $dkim  = @($Records | Where-Object { $_.name -match "^selector[12]\._domainkey\.$([regex]::Escape($Domain))$" })

    [PSCustomObject]@{
        Domain        = $Domain
        MX            = ($mx | ForEach-Object { "$($_.priority) $($_.content)" }) -join '; '
        NullMX        = [bool]($mx | Where-Object { $_.content -in '.', '' })
        SPF           = ($spf.content -join ' | ')
        SPFCount      = $spf.Count
        SPFHardFail   = [bool]($spf.content -match '-all')
        DMARC         = ($dmarc.content -join ' | ')
        DMARCPolicy   = if ($dmarc) { ([regex]::Match($dmarc[0].content, 'p=(\w+)')).Groups[1].Value } else { '' }
        DKIMSelectors = $dkim.Count
    }
}

try {
    if (-not (Test-Path $TokenPath)) { throw "Token file not found at $TokenPath." }
    $token = (Get-Content -Path $TokenPath -Raw).Trim()
    if (-not $token) { throw "Token file at $TokenPath is empty." }
    $headers = @{ Authorization = "Bearer $token" }

    # No /user/tokens/verify call: account-owned tokens fail that endpoint even when valid.
    # Listing zones works for both user and account tokens and proves the token is usable.
    Write-Verbose 'Listing zones...'
    try {
        $zones = @(Get-CfPagedResult -Path '/zones' -Headers $headers)
    }
    catch {
        throw "Could not list zones. Cloudflare said: $($_.ErrorDetails.Message ?? $_.Exception.Message). Recheck the token value and that it has Zone:Read."
    }
    if (-not $zones) { throw 'Token is valid but can see no zones. Check the token''s zone resources.' }

    $allRecords = [System.Collections.Generic.List[object]]::new()
    $summary    = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($zone in $zones) {
        $i++
        Write-Progress -Activity 'Reading DNS' -Status "Zone $i of $($zones.Count): $($zone.name)" -PercentComplete ($i / $zones.Count * 100)
        try {
            $recs = @(Get-CfPagedResult -Path "/zones/$($zone.id)/dns_records" -Headers $headers -PerPage 100)
            foreach ($r in $recs) {
                $allRecords.Add([PSCustomObject]@{
                    Zone     = $zone.name
                    Type     = $r.type
                    Name     = $r.name
                    Content  = $r.content
                    Priority = $r.priority
                    TTL      = $r.ttl
                    Proxied  = $r.proxied
                    Comment  = $r.comment
                })
            }
            $summary.Add((Get-CfEmailPosture -Domain $zone.name -Records $recs))
        }
        catch {
            Write-Warning "Failed to read records for $($zone.name): $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Reading DNS' -Completed

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $recordsCsv = Join-Path $OutputPath "CloudflareDnsRecords-$stamp.csv"
    $summaryCsv = Join-Path $OutputPath "CloudflareEmailPosture-$stamp.csv"
    $allRecords | Sort-Object Zone, Type, Name | Export-Csv -Path $recordsCsv -NoTypeInformation
    $summary    | Export-Csv -Path $summaryCsv -NoTypeInformation

    Write-Host "`nRecords: $recordsCsv"
    Write-Host "Summary: $summaryCsv`n"
    $summary | Format-Table Domain, NullMX, SPFHardFail, SPFCount, DMARCPolicy, DKIMSelectors, MX -AutoSize
}
finally {
    $token = $null
    $headers = $null
}
