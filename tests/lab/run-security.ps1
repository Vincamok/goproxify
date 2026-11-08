# Lanceur PowerShell de run-security.sh (le script est en bash : il tourne sous Git Bash, pas sous le bash de WSL).
#   .\tests\lab\run-security.ps1                                        labo local jetable
#   .\tests\lab\run-security.ps1 --target tests\lab\targets\prod-lan.env   cible distante : le jeton d'API est demande sans affichage
# Toutes les options de run-security.sh sont acceptees (--help). Code retour identique a celui du script bash.
# stderr fusionne dans stdout cote bash : PowerShell 5.1 prendrait sinon chaque ligne d'avancement de docker pour une erreur
$bash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
if (-not (Test-Path $bash)) { Write-Error "Git Bash introuvable ($bash) : installer Git for Windows."; exit 2 }

$script = ($PSScriptRoot -replace '\\', '/') + '/run-security.sh'
# PowerShell lit waf,jwt comme un tableau : on le rejoint par des virgules avant de le passer a bash
$fwd = @($args | ForEach-Object { if ($_ -is [array]) { $_ -join "," } else { "$_" } } | ForEach-Object { $_ -replace "\\", "/" })

if (($fwd -contains '--target') -and -not $env:LAB_ADMIN_TOKEN) {
    $sec = Read-Host -Prompt "Jeton d'API de la cible (gpx_pat_..., non affiche)" -AsSecureString
    $env:LAB_ADMIN_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    $injected = $true
}
try {
    & $bash -c 'exec "$0" "$@" 2>&1' $script @fwd
    $rc = $LASTEXITCODE
} finally {
    if ($injected) { Remove-Item Env:LAB_ADMIN_TOKEN -ErrorAction SilentlyContinue }
}
exit $rc
