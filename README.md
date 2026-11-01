# Cloudflare DNS tools

> **Showcase copy.** This is a sanitized example of my work, published for portfolio purposes.
> It is a snapshot, not an actively maintained project. Issues and pull requests are welcome
> but may not get a reply. Contact: zachanger@outlook.com · [zachanger.com](https://zachanger.com)

Two small PowerShell 7 scripts for auditing and hardening email authentication on domains hosted
in Cloudflare DNS. No modules required; they call the Cloudflare v4 REST API directly.

| Script | What it does | Changes anything? |
|---|---|---|
| `Get-CloudflareDnsReport.ps1` | Lists every zone the token can see, exports all DNS records to CSV, and prints a per-domain email posture summary: MX, null MX, SPF (and whether it hard-fails), DMARC policy, DKIM selectors. | No |
| `Set-CloudflareEmailHardening.ps1` | For domains that send no mail (or send only through Microsoft 365), sets SPF to `-all` and DMARC to `p=reject`. Preview by default; `-Apply` is required to change anything, and `-WhatIf` / `-Confirm` are honored. | Only with `-Apply` |

## Setup

1. In Cloudflare, create an API token with exactly two permissions: **Zone: Read** and **DNS: Edit**, scoped to the zones you want to manage. Nothing else.
2. Save the token, by itself on one line, to `%USERPROFILE%\.cloudflare\dns.token` (or pass `-TokenPath`).
3. Run the report first:

```powershell
.\Get-CloudflareDnsReport.ps1
```

4. Preview, then apply, hardening on specific domains:

```powershell
.\Set-CloudflareEmailHardening.ps1 -Domain example.com, example.net
.\Set-CloudflareEmailHardening.ps1 -Domain example.com, example.net -Apply
```

## Design notes

- The token is read from a file and never printed, logged, or written anywhere else. Both scripts clear it in `finally`.
- Token verification uses `GET /zones` rather than `/user/tokens/verify`, because account-owned tokens fail the latter even when valid.
- Retries on 429/503/504 with exponential backoff and jitter, capped at four attempts.
- The hardening script gathers first, prints a full plan, and only then applies. It refuses to touch a domain with duplicate SPF or DMARC records instead of guessing.
- `p=reject` is the right DMARC policy for a domain that sends no mail. Do not run the hardening script against a domain that sends mail through anything other than Microsoft 365 without changing `$DesiredSpf` first.

## Licence

Released under the [MIT License](LICENSE).
