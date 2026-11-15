#Requires -Version 7.0
<#
.SYNOPSIS
    Hardens SPF and DMARC on Cloudflare-hosted domains that use Microsoft 365 but do not send mail.

.DESCRIPTION
    For each domain:
      - SPF  -> v=spf1 include:spf.protection.outlook.com -all  (updates the existing SPF record, or creates one)
      - DMARC -> v=DMARC1; p=reject;                            (updates _dmarc, or creates it)
    MX, autodiscover, verification and enrollment records are left alone.

    Default is PREVIEW ONLY: shows the plan and changes nothing.
    Add -Apply to make changes. -WhatIf and -Confirm are also honored.

.PARAMETER Domain
    Domains to harden. Only pass domains that send no mail, or send only through Microsoft 365.

.PARAMETER Apply
    Actually make the changes. Without it, the script only reports what it would do.

.PARAMETER TokenPath
    Path to a file containing only the Cloudflare API token.

.EXAMPLE
    .\Set-CloudflareEmailHardening.ps1 -Domain example.com, example.net
    Preview the plan.

.EXAMPLE
    .\Set-CloudflareEmailHardening.ps1 -Domain example.com -Apply
    Apply the plan, confirming nothing further.

.NOTES
    Author:      Zach Anger (drafted with Claude)
    Date:        2026-11-01
    Token perms: Zone:Read, DNS:Edit
    Do NOT run against a domain that sends mail from anything other than M365; p=reject would block it.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Domain,

    [switch]$Apply,

    [ValidateNotNullOrEmpty()]
    [string]$TokenPath = (Join-Path $HOME '.cloudflare\dns.token')
)

$ErrorActionPreference = 'Stop'
$ApiBase     = 'https://api.cloudflare.com/client/v4'
$DesiredSpf   = 'v=spf1 include:spf.protection.outlook.com -all'
$DesiredDmarc = 'v=DMARC1; p=reject;'

function Invoke-CfRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [ValidateSet('Get', 'Post', 'Patch')][string]$Method = 'Get',
        [hashtable]$Body,
        [int]$MaxRetries = 4
    )
    $params = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ErrorAction = 'Stop' }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json -Compress); $params.ContentType = 'application/json' }
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try { return Invoke-RestMethod @params }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -in 429, 503, 504 -and $attempt -lt $MaxRetries) {
                $delay = [math]::Pow(2, $attempt) + (Get-Random -Maximum 1.0)
                Write-Warning "Cloudflare returned $status. Retrying in $([math]::Round($delay,1))s (attempt $attempt of $MaxRetries)."
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function ConvertTo-PlainTxt {
    param([string]$Value)
    ($Value -replace '^"|"$', '').Trim()
}

function Get-CfHardeningPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][hashtable]$Headers
    )
    $zoneResp = Invoke-CfRequest -Uri "$ApiBase/zones?name=$DomainName" -Headers $Headers
    $zone = $zoneResp.result | Select-Object -First 1
    if (-not $zone) {
        Write-Warning "$DomainName not found in Cloudflare (or token can't see it). Skipping."
        return
    }
    $txt = (Invoke-CfRequest -Uri "$ApiBase/zones/$($zone.id)/dns_records?type=TXT&per_page=100" -Headers $Headers).result

    # SPF
    $spf = @($txt | Where-Object { $_.name -eq $DomainName -and (ConvertTo-PlainTxt $_.content) -like 'v=spf1*' })
    if ($spf.Count -gt 1) {
        Write-Warning "$DomainName has $($spf.Count) SPF records (that alone breaks SPF). Fix manually; skipping SPF."
    }
    elseif ($spf.Count -eq 1) {
        $current = ConvertTo-PlainTxt $spf[0].content
        [PSCustomObject]@{
            Domain = $DomainName; ZoneId = $zone.id; RecordId = $spf[0].id; Record = 'SPF'; Name = $DomainName
            Current = $current; Desired = $DesiredSpf
            Action = if ($current -eq $DesiredSpf) { 'None' } else { 'Update' }
        }
    }
    else {
        [PSCustomObject]@{
            Domain = $DomainName; ZoneId = $zone.id; RecordId = $null; Record = 'SPF'; Name = $DomainName
            Current = ''; Desired = $DesiredSpf; Action = 'Create'
        }
    }

    # DMARC
    $dmarcName = "_dmarc.$DomainName"
    $dmarc = @($txt | Where-Object { $_.name -eq $dmarcName -and (ConvertTo-PlainTxt $_.content) -like 'v=DMARC1*' })
    if ($dmarc.Count -gt 1) {
        Write-Warning "$DomainName has $($dmarc.Count) DMARC records. Fix manually; skipping DMARC."
    }
    elseif ($dmarc.Count -eq 1) {
        $current = ConvertTo-PlainTxt $dmarc[0].content
        [PSCustomObject]@{
            Domain = $DomainName; ZoneId = $zone.id; RecordId = $dmarc[0].id; Record = 'DMARC'; Name = $dmarcName
            Current = $current; Desired = $DesiredDmarc
            Action = if ($current -eq $DesiredDmarc) { 'None' } else { 'Update' }
        }
    }
    else {
        [PSCustomObject]@{
            Domain = $DomainName; ZoneId = $zone.id; RecordId = $null; Record = 'DMARC'; Name = $dmarcName
            Current = ''; Desired = $DesiredDmarc; Action = 'Create'
        }
    }
}

try {
    if (-not (Test-Path $TokenPath)) { throw "Token file not found at $TokenPath." }
    $token = (Get-Content -Path $TokenPath -Raw).Trim()
    if (-not $token) { throw "Token file at $TokenPath is empty." }
    $headers = @{ Authorization = "Bearer $token" }

    # Phase 1: gather
    $plan = foreach ($d in $Domain) {
        try { Get-CfHardeningPlan -DomainName $d -Headers $headers }
        catch { Write-Warning "Could not build plan for ${d}: $($_.ErrorDetails.Message ?? $_.Exception.Message)" }
    }
    $plan = @($plan)

    # Phase 2: report
    Write-Host "`nPlan:" -ForegroundColor Cyan
    $plan | Format-Table Domain, Record, Action, Current, Desired -AutoSize -Wrap | Out-Host

    $changes = @($plan | Where-Object Action -ne 'None')
    if (-not $changes) { Write-Host 'Nothing to change.' -ForegroundColor Green; return }
    if (-not $Apply) {
        Write-Host "Preview only. $($changes.Count) change(s) planned. Re-run with -Apply to make them." -ForegroundColor Yellow
        return
    }

    # Phase 3: apply
    $results = foreach ($c in $changes) {
        $target = "$($c.Name) ($($c.Record))"
        if (-not $PSCmdlet.ShouldProcess($target, "$($c.Action) TXT to '$($c.Desired)'")) { continue }
        try {
            $content = '"' + $c.Desired + '"'
            if ($c.Action -eq 'Update') {
                $null = Invoke-CfRequest -Method Patch -Uri "$ApiBase/zones/$($c.ZoneId)/dns_records/$($c.RecordId)" `
                    -Headers $headers -Body @{ content = $content }
            }
            else {
                $null = Invoke-CfRequest -Method Post -Uri "$ApiBase/zones/$($c.ZoneId)/dns_records" `
                    -Headers $headers -Body @{ type = 'TXT'; name = $c.Name; content = $content; ttl = 1 }
            }
            [PSCustomObject]@{ Domain = $c.Domain; Record = $c.Record; Action = $c.Action; Result = 'OK' }
        }
        catch {
            Write-Warning "Failed on ${target}: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
            [PSCustomObject]@{ Domain = $c.Domain; Record = $c.Record; Action = $c.Action; Result = 'FAILED' }
        }
    }
    Write-Host "`nResults:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize | Out-Host
}
finally {
    $token = $null
    $headers = $null
}
