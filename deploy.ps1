param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$HostKey,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$plink = 'C:\Program Files (x86)\PuTTY\plink.exe'
$pscp = 'C:\Program Files (x86)\PuTTY\pscp.exe'
$archive = Join-Path $PSScriptRoot 'kali-mcp-deploy.tar.gz'
Push-Location $PSScriptRoot
try {
    & tar --exclude=__pycache__ -czf $archive mcp-kali docker deploy.sh deploy-http.sh deploy-edge.sh edge-firewall.py kali-mcp-edge.service build-everything.sh activate-everything.sh prune-kali-cache.py README.md mcp-http-config.example.json kali-mcp-workers.slice kali-mcp-http.service kali-mcp-cert-renew.service kali-mcp-cert-renew.timer
    if ($LASTEXITCODE) { throw 'Archive failed' }
    & $pscp -batch -i $Key -hostkey $HostKey $archive "${Server}:/tmp/kali-mcp-deploy.tar.gz"
    if ($LASTEXITCODE) { throw 'Upload failed' }
    $command = 'mkdir -p /opt/kali-mcp && tar -xzf /tmp/kali-mcp-deploy.tar.gz -C /opt/kali-mcp'
    if (-not $SkipBuild) { $command += ' && cd /opt/kali-mcp && sh deploy.sh' }
    & $plink -batch -T -ssh -i $Key -hostkey $HostKey $Server $command
    if ($LASTEXITCODE) { throw 'Remote deployment failed' }
} finally {
    Pop-Location
}
