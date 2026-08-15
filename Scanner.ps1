[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Targets,

    [Parameter()]
    [Alias("D")]
    [string[]]$Domain,

    [Parameter()]
    [Alias("IP")]
    [string[]]$IPAddress,

    [Parameter()]
    [string]$InputFile,

    [Parameter()]
    [string]$OutputCsv,

    [Parameter()]
    [string]$ConfigPath
)

$ModulesPath = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $ModulesPath "VirusTotal.psm1") -Force
Import-Module (Join-Path $ModulesPath "AbuseIPDB.psm1") -Force
Import-Module (Join-Path $ModulesPath "Urlscan.psm1") -Force

function Resolve-ConfigPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) { return $ExplicitPath }

    $candidates = @(
        (Join-Path $PSScriptRoot "config\config.json"),
        (Join-Path $PSScriptRoot "config.json")
    )

    $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($found) { return $found }

    return $candidates[0]
}

function Get-ScannerConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "No se encontro '$Path'. Copia config\config.example.json a config\config.json y anade tus claves de API (o pasa -ConfigPath con la ruta que uses)."
        return $null
    }

    try {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Error "No se pudo leer la configuracion '$Path': $($_.Exception.Message)"
        return $null
    }
}

function Get-TargetList {
    param(
        [string[]]$Targets,
        [string[]]$Domain,
        [string[]]$IPAddress,
        [string]$InputFile
    )

    $list = New-Object System.Collections.Generic.List[object]

    if ($Targets) {
        foreach ($t in $Targets) {
            if (-not [string]::IsNullOrWhiteSpace($t)) {
                $list.Add([PSCustomObject]@{
                    Target = $t.Trim()
                    Type   = "Auto"
                })
            }
        }
    }

    if ($Domain) {
        foreach ($d in $Domain) {
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                $list.Add([PSCustomObject]@{
                    Target = $d.Trim()
                    Type   = "Domain"
                })
            }
        }
    }

    if ($IPAddress) {
        foreach ($ip in $IPAddress) {
            if (-not [string]::IsNullOrWhiteSpace($ip)) {
                $list.Add([PSCustomObject]@{
                    Target = $ip.Trim()
                    Type   = "IP"
                })
            }
        }
    }

    if ($InputFile) {
        if (-not (Test-Path -LiteralPath $InputFile)) {
            Write-Error "No se encuentra el fichero de entrada: $InputFile"
        }
        else {
            Get-Content -LiteralPath $InputFile | ForEach-Object {
                $line = $_.Trim()

                if ($line -and -not $line.StartsWith("#")) {
                    $list.Add([PSCustomObject]@{
                        Target = $line
                        Type   = "Auto"
                    })
                }
            }
        }
    }

    return $list |
        Group-Object { "$($_.Type)|$($_.Target)" } |
        ForEach-Object { $_.Group[0] }
}

function Write-VTSummary {
    param($Result)

    if ($null -eq $Result) { return }

    $malicious = 0
    $suspicious = 0
    $isNumeric = [int]::TryParse([string]$Result.Maliciosos, [ref]$malicious) -and `
                 [int]::TryParse([string]$Result.Sospechosos, [ref]$suspicious)

    $color = "DarkGray"
    if ($isNumeric) {
        if ($malicious -gt 0) { $color = "Red" }
        elseif ($suspicious -gt 0) { $color = "Yellow" }
        else { $color = "Green" }
    }

    Write-Host ("    VirusTotal -> maliciosos: {0} | sospechosos: {1} | limpios: {2}" -f `
            $Result.Maliciosos, $Result.Sospechosos, $Result.Limpios) -ForegroundColor $color
    Write-Host "    $($Result.Enlace)" -ForegroundColor DarkGray
}

function Get-OutputResults {
    param([System.Collections.IEnumerable]$Results)

    foreach ($result in $Results) {
        [PSCustomObject]@{
            Target          = $result.Target
            Proveedor       = $result.Proveedor
            Tipo            = $result.Tipo
            Maliciosos      = $result.Maliciosos
            Sospechosos     = $result.Sospechosos
            Limpios         = $result.Limpios
            SinDetectar     = $result.SinDetectar
            Reputacion      = $result.Reputacion
            AbuseConfidence = $result.AbuseConfidence
            TotalReports    = $result.TotalReports
            CountryCode     = $result.CountryCode
            UsageType       = $result.UsageType
            ISP             = $result.ISP
            Domain          = $result.Domain
            IsWhitelisted   = $result.IsWhitelisted
            LastReportedAt  = $result.LastReportedAt
            UrlscanUuid     = $result.UrlscanUuid
            UrlscanScore    = $result.UrlscanScore
            UrlscanCategories = $result.UrlscanCategories
            UrlscanStatus   = $result.UrlscanStatus
            UrlscanCountry  = $result.UrlscanCountry
            UrlscanDomain   = $result.UrlscanDomain
            UrlscanVisibility = $result.UrlscanVisibility
            Enlace          = $result.Enlace
        }
    }
}

$ConfigPath = Resolve-ConfigPath -ExplicitPath $ConfigPath
$config = Get-ScannerConfig -Path $ConfigPath
if (-not $config) { return }

$targetList = Get-TargetList `
    -Targets $Targets `
    -Domain $Domain `
    -IPAddress $IPAddress `
    -InputFile $InputFile
if (-not $targetList -or $targetList.Count -eq 0) {
    Write-Host "Uso:" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -Targets dominio1.com,https://url-sospechosa.com" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -InputFile targets.txt" -ForegroundColor Yellow
    return
}

if (-not $config.VirusTotal.ApiKey -or $config.VirusTotal.ApiKey -eq "TU_API_KEY_AQUI") {
    Write-Error "Falta configurar VirusTotal.ApiKey en config.json."
    return
}

$allResults = New-Object System.Collections.Generic.List[object]

foreach ($item in $targetList) {

    $target = $item.Target
    $targetType = $item.Type

    if ($targetType -eq "Auto") {
        if ($target -match '^https?://') {
            $targetType = "URL"
        }
        else {
            $parsedIp = $null

            if ([System.Net.IPAddress]::TryParse($target, [ref]$parsedIp)) {
                $targetType = "IP"
            }
            else {
                $targetType = "Domain"
            }
        }
    }

    Write-Host "`n[*] Analizando: $target [$targetType]" -ForegroundColor Cyan

    try {
        $vtResult = Get-VTReport `
            -Target $target `
            -TargetType $targetType `
            -ApiKey $config.VirusTotal.ApiKey
        Write-VTSummary -Result $vtResult
        $allResults.Add($vtResult)
    }
    catch {
        Write-Warning "VirusTotal: $_"
    }

    if ($targetType -eq "URL" -and $config.Urlscan.ApiKey -and $config.Urlscan.ApiKey -ne "TU_API_KEY_AQUI") {
        try {
            $urlscanResult = Get-UrlscanReport `
                -Url $target `
                -ApiKey $config.Urlscan.ApiKey `
                -Visibility $config.Urlscan.Visibility

            Write-UrlscanSummary -Result $urlscanResult
            $allResults.Add($urlscanResult)
        }
        catch {
            Write-Warning "urlscan.io: $_"
        }
    }

    if ($targetType -eq "IP" -and $config.AbuseIPDB.ApiKey -and $config.AbuseIPDB.ApiKey -ne "TU_API_KEY_AQUI") {

        try {
            $abuseResult = Get-AbuseIPDBReport `
                -IPAddress $target `
                -ApiKey $config.AbuseIPDB.ApiKey

            Write-AbuseIPDBSummary -Result $abuseResult
            $allResults.Add($abuseResult)
        }
        catch {
            Write-Warning "AbuseIPDB: $_"
        }
    }

    if ($targetList.Count -gt 1 -and $item -ne $targetList[-1]) {
        Start-Sleep -Seconds 16
    }
}

Write-Host "`n=== Resumen ===" -ForegroundColor Cyan
$outputResults = Get-OutputResults -Results $allResults
$outputResults | Format-Table Target, Proveedor, Tipo, Maliciosos, Sospechosos, UrlscanScore, UrlscanStatus, AbuseConfidence, TotalReports, CountryCode -AutoSize

if ($OutputCsv) {
    $outputResults | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nResultados exportados a: $OutputCsv" -ForegroundColor Green
}
