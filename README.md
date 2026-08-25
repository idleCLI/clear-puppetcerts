# Clear-PuppetCerts

Revoking a Puppet cert is two operations, and the second is the one people forget — which is how a rebuilt host ends up rejected by a CA that still remembers the machine it replaced. This does both, through AWX, for one host or a list.

PowerShell 7+. Run it, don't dot-source it.

```powershell
.\Clear-PuppetCerts.ps1 -Server server1.domain.com -AwxBaseUrl https://controller
.\Clear-PuppetCerts.ps1 -ServerList servers.txt -AwxBaseUrl https://controller
```

Run it bare and it'll ask. List files are one hostname per line; `#` comments and blanks ignored. `Get-Help .\Clear-PuppetCerts.ps1 -Full` for the rest.

**Both job templates need *Prompt on Launch* enabled for variables.** Without it AWX doesn't reject the launch — it discards your variables, runs against the template's own hosts, and reports success. A green result that means nothing, with no reason to look closer. The script preflights for this and refuses to run otherwise.

Failures are logged per host and the run continues. Exits non-zero if anything failed.
