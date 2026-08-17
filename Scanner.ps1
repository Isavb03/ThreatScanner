[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Targets,

    [Parameter()]
    [Alias("D")]
    [string[]]$Domain,

    [Parameter()]
    [Alias("U")]
    [string[]]$Url,

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
Import-Module (Join-Path $ModulesPath "Whois.psm1") -Force

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

function Get-TargetConfidence {
    param([System.Collections.IEnumerable]$Results)

    $signals = @{}
    foreach ($result in $Results) {
        $risk = $null

        switch ($result.Proveedor) {
            "VirusTotal" {
                $malicious = 0
                $suspicious = 0
                $harmless = 0
                $undetected = 0

                if ([int]::TryParse([string]$result.Maliciosos, [ref]$malicious) -and
                    [int]::TryParse([string]$result.Sospechosos, [ref]$suspicious) -and
                    [int]::TryParse([string]$result.Limpios, [ref]$harmless) -and
                    [int]::TryParse([string]$result.SinDetectar, [ref]$undetected)) {
                    $total = $malicious + $suspicious + $harmless + $undetected
                    if ($total -gt 0) {
                        $risk = (100 * $malicious + 50 * $suspicious) / $total
                    }
                }
            }
            "AbuseIPDB" {
                $score = 0
                if ([int]::TryParse([string]$result.AbuseConfidence, [ref]$score)) { $risk = $score }
            }
            "urlscan.io" {
                $score = 0
                if ([int]::TryParse([string]$result.UrlscanScore, [ref]$score)) {
                    $risk = ($score + 100) / 2
                }
            }
        }

        if ($null -ne $risk) {
            if (-not $signals.ContainsKey($result.Target)) {
                $signals[$result.Target] = New-Object System.Collections.Generic.List[double]
            }
            [void]$signals[$result.Target].Add([Math]::Min(100, [Math]::Max(0, $risk)))
        }
    }

    $confidence = @{}
    foreach ($target in $signals.Keys) {
        $score = [Math]::Round(($signals[$target] | Measure-Object -Average).Average)
        $color = if ($score -ge 67) { "Red" } elseif ($score -ge 34) { "Yellow" } else { "Green" }
        $confidence[$target] = [PSCustomObject]@{ Score = $score; Color = $color }
    }

    return $confidence
}

function Get-OutputResults {
    param(
        [System.Collections.IEnumerable]$Results,
        [hashtable]$ConfidenceByTarget
    )

    foreach ($result in $Results) {
        $confidence = $ConfidenceByTarget[$result.Target]
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
            WhoisRegistrar  = $result.WhoisRegistrar
            WhoisCreated    = $result.WhoisCreated
            WhoisExpires    = $result.WhoisExpires
            WhoisStatus     = $result.WhoisStatus
            WhoisCountry    = $result.WhoisCountry
            WhoisNetwork    = $result.WhoisNetwork
            Confianza       = if ($confidence) { "$($confidence.Score)%" } else { "N/D" }
            ConfidenceColor = if ($confidence) { $confidence.Color } else { "DarkGray" }
            Enlace          = $result.Enlace
        }
    }
}

function Write-ResultsSummary {
    param([System.Collections.IEnumerable]$Results)

    $format = "{0,-32} {1,-15} {2,-8} {3,-10} {4,-12} {5,-13} {6,-11} "
    Write-Host ($format -f "Target", "Proveedor", "Tipo", "Maliciosos", "Sospechosos", "URLScan", "Abuso") -ForegroundColor DarkGray -NoNewline
    Write-Host "Confianza" -ForegroundColor DarkGray
    Write-Host ($format -f "------", "---------", "----", "----------", "------------", "-------", "-----") -ForegroundColor DarkGray -NoNewline
    Write-Host "---------" -ForegroundColor DarkGray

    foreach ($result in $Results) {
        Write-Host ($format -f `
                $result.Target, $result.Proveedor, $result.Tipo, $result.Maliciosos,
                $result.Sospechosos, $result.UrlscanScore, $result.AbuseConfidence) -NoNewline
        Write-Host ("{0,9}" -f $result.Confianza) -ForegroundColor $result.ConfidenceColor
    }
}

$ConfigPath = Resolve-ConfigPath -ExplicitPath $ConfigPath
$config = Get-ScannerConfig -Path $ConfigPath
if (-not $config) { return }

$inputTargets = @()
if ($InputFile) {
    if (-not (Test-Path -LiteralPath $InputFile)) {
        Write-Error "No se encuentra el fichero de entrada: $InputFile"
    }
    else {
        $inputTargets = foreach ($line in Get-Content -LiteralPath $InputFile) {
            $line = $line.Trim()
            if ($line -and -not $line.StartsWith("#")) { $line }
        }
    }
}

$targetList = @()
foreach ($target in (@($Targets) + @($inputTargets))) {
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        $targetList += [PSCustomObject]@{ Target = $target.Trim(); Type = "Auto" }
    }
}

foreach ($target in $Domain) {
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        $targetList += [PSCustomObject]@{ Target = $target.Trim(); Type = "Domain" }
    }
}

foreach ($target in $Url) {
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        $targetList += [PSCustomObject]@{ Target = $target.Trim(); Type = "URL" }
    }
}

foreach ($target in $IPAddress) {
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        $targetList += [PSCustomObject]@{ Target = $target.Trim(); Type = "IP" }
    }
}

$uniqueTargets = [ordered]@{}
foreach ($target in $targetList) {
    $key = "$($target.Type)|$($target.Target)"
    if (-not $uniqueTargets.Contains($key)) { $uniqueTargets[$key] = $target }
}
$targetList = @($uniqueTargets.Values)
if (-not $targetList -or $targetList.Count -eq 0) {
    Write-Host "Uso:" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -D dominio1.com | -IP 1.1.1.1 | -U https://sitio.com" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -Targets dominio1.com,1.1.1.1,https://sitio.com" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -InputFile targets.txt" -ForegroundColor Yellow
    return
}

if (-not $config.VirusTotal.ApiKey -or $config.VirusTotal.ApiKey -eq "TU_API_KEY_AQUI") {
    Write-Error "Falta configurar VirusTotal.ApiKey en config.json."
    return
}

$allResults = New-Object System.Collections.Generic.List[object]
$rdapBaseUri = $config.Whois.RdapBaseUri
if (-not $rdapBaseUri) { $rdapBaseUri = "https://rdap.org" }

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
        [void]$allResults.Add($vtResult)
    }
    catch {
        Write-Warning "VirusTotal: $_"
    }

    if ($targetType -in @("Domain", "IP")) {
        try {
            $whoisResult = Get-WhoisReport `
                -Target $target `
                -TargetType $targetType `
                -RdapBaseUri $rdapBaseUri

            Write-WhoisSummary -Result $whoisResult
            [void]$allResults.Add($whoisResult)
        }
        catch {
            Write-Warning "WHOIS/RDAP: $_"
        }
    }

    if ($targetType -eq "URL" -and $config.Urlscan.ApiKey -and $config.Urlscan.ApiKey -ne "TU_API_KEY_AQUI") {
        try {
            $urlscanResult = Get-UrlscanReport `
                -Url $target `
                -ApiKey $config.Urlscan.ApiKey `
                -Visibility $config.Urlscan.Visibility

            Write-UrlscanSummary -Result $urlscanResult
            [void]$allResults.Add($urlscanResult)
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
            [void]$allResults.Add($abuseResult)
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
$confidenceByTarget = Get-TargetConfidence -Results $allResults
$outputResults = Get-OutputResults -Results $allResults -ConfidenceByTarget $confidenceByTarget
Write-ResultsSummary -Results $outputResults

if ($OutputCsv) {
    $outputResults | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nResultados exportados a: $OutputCsv" -ForegroundColor Green
}
