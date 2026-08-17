[CmdletBinding()]
param(
    [string[]]$Targets,

    [Alias("D")]
    [string[]]$Domain,

    [Alias("U")]
    [string[]]$Url,

    [Alias("IP")]
    [string[]]$IPAddress,

    [string]$InputFile,

    [string]$OutputCsv,

    [string]$ConfigPath
)

$modulesPath = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesPath "VirusTotal.psm1") -Force
Import-Module (Join-Path $modulesPath "AbuseIPDB.psm1") -Force
Import-Module (Join-Path $modulesPath "Urlscan.psm1") -Force
Import-Module (Join-Path $modulesPath "Whois.psm1") -Force

function Get-ConfigPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) { return $ExplicitPath }

    $candidatePaths = @(
        (Join-Path $PSScriptRoot "config\config.json"),
        (Join-Path $PSScriptRoot "config.json")
    )

    $configuredPath = $candidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($configuredPath) { return $configuredPath }

    return $candidatePaths[0]
}

function Read-ScannerConfig {
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

function Get-InputFileTargets {
    param([string]$Path)

    if (-not $Path) { return @() }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "No se encuentra el fichero de entrada: $Path"
        return @()
    }

    $targets = foreach ($line in Get-Content -LiteralPath $Path) {
        $target = $line.Trim()
        if ($target -and -not $target.StartsWith("#")) { $target }
    }

    return $targets
}

function Resolve-TargetType {
    param(
        [string]$Target,
        [string]$Type
    )

    if ($Type -ne "Auto") { return $Type }
    if ($Target -match '^https?://') { return "URL" }

    $parsedIpAddress = $null
    if ([System.Net.IPAddress]::TryParse($Target, [ref]$parsedIpAddress)) {
        return "IP"
    }

    return "Domain"
}

function Get-IntegerValue {
    param($Value)

    $integer = 0
    if ([int]::TryParse([string]$Value, [ref]$integer)) { return $integer }

    return $null
}

function Get-VirusTotalRiskScore {
    param($Result)

    $malicious = Get-IntegerValue $Result.Maliciosos
    $suspicious = Get-IntegerValue $Result.Sospechosos
    $harmless = Get-IntegerValue $Result.Limpios
    $undetected = Get-IntegerValue $Result.SinDetectar

    if ($null -in @($malicious, $suspicious, $harmless, $undetected)) {
        return $null
    }

    $total = $malicious + $suspicious + $harmless + $undetected
    if ($total -eq 0) { return $null }

    return (100 * $malicious + 50 * $suspicious) / $total
}

function Get-ProviderRiskScore {
    param($Result)

    switch ($Result.Proveedor) {
        "VirusTotal" { return Get-VirusTotalRiskScore -Result $Result }
        "AbuseIPDB" { return Get-IntegerValue $Result.AbuseConfidence }
        "urlscan.io" {
            $urlscanScore = Get-IntegerValue $Result.UrlscanScore
            if ($null -ne $urlscanScore) { return ($urlscanScore + 100) / 2 }
        }
    }

    return $null
}

function Get-TargetConfidence {
    param([System.Collections.IEnumerable]$Results)

    $riskScoresByTarget = @{}

    foreach ($result in $Results) {
        $riskScore = Get-ProviderRiskScore -Result $result
        if ($null -eq $riskScore) { continue }

        if (-not $riskScoresByTarget.ContainsKey($result.Target)) {
            $riskScoresByTarget[$result.Target] = New-Object System.Collections.Generic.List[double]
        }

        [void]$riskScoresByTarget[$result.Target].Add([Math]::Min(100, [Math]::Max(0, $riskScore)))
    }

    $confidenceByTarget = @{}
    foreach ($target in $riskScoresByTarget.Keys) {
        $score = [Math]::Round(($riskScoresByTarget[$target] | Measure-Object -Average).Average)
        $color = if ($score -ge 67) { "Red" } elseif ($score -ge 34) { "Yellow" } else { "Green" }
        $confidenceByTarget[$target] = [PSCustomObject]@{ Score = $score; Color = $color }
    }

    return $confidenceByTarget
}

function Write-VirusTotalSummary {
    param($Result)

    if ($null -eq $Result) { return }

    $malicious = Get-IntegerValue $Result.Maliciosos
    $suspicious = Get-IntegerValue $Result.Sospechosos
    $color = "DarkGray"

    if ($null -ne $malicious -and $null -ne $suspicious) {
        if ($malicious -gt 0) { $color = "Red" }
        elseif ($suspicious -gt 0) { $color = "Yellow" }
        else { $color = "Green" }
    }

    Write-Host "`n  [VirusTotal]" -ForegroundColor White
    Write-Host ("  Resultado: maliciosos: {0} | sospechosos: {1} | limpios: {2}" -f `
            $Result.Maliciosos, $Result.Sospechosos, $Result.Limpios) -ForegroundColor $color
    Write-Host "  GUI: $($Result.Enlace)" -ForegroundColor DarkGray
}

function New-OutputResult {
    param(
        $Result,
        $Confidence
    )

    return [PSCustomObject]@{
        Target                = $Result.Target
        Proveedor             = $Result.Proveedor
        Tipo                  = $Result.Tipo
        Maliciosos            = $Result.Maliciosos
        Sospechosos           = $Result.Sospechosos
        Limpios               = $Result.Limpios
        SinDetectar           = $Result.SinDetectar
        Reputacion            = $Result.Reputacion
        AbuseConfidence       = $Result.AbuseConfidence
        TotalReports          = $Result.TotalReports
        CountryCode           = $Result.CountryCode
        UsageType             = $Result.UsageType
        ISP                   = $Result.ISP
        Domain                = $Result.Domain
        IsWhitelisted         = $Result.IsWhitelisted
        LastReportedAt        = $Result.LastReportedAt
        UrlscanUuid           = $Result.UrlscanUuid
        UrlscanScore          = $Result.UrlscanScore
        UrlscanCategories     = $Result.UrlscanCategories
        UrlscanStatus         = $Result.UrlscanStatus
        UrlscanCountry        = $Result.UrlscanCountry
        UrlscanDomain         = $Result.UrlscanDomain
        UrlscanVisibility     = $Result.UrlscanVisibility
        UrlscanScanFailed     = $Result.UrlscanScanFailed
        UrlscanDomainCreated  = $Result.UrlscanDomainCreated
        UrlscanDomainAgeDays  = $Result.UrlscanDomainAgeDays
        WhoisRegistrar        = $Result.WhoisRegistrar
        WhoisCreated          = $Result.WhoisCreated
        WhoisExpires          = $Result.WhoisExpires
        WhoisStatus           = $Result.WhoisStatus
        WhoisCountry          = $Result.WhoisCountry
        WhoisNetwork          = $Result.WhoisNetwork
        Confianza             = if ($Confidence) { "$($Confidence.Score)%" } else { "N/D" }
        ConfidenceColor       = if ($Confidence) { $Confidence.Color } else { "DarkGray" }
        Enlace                = $Result.Enlace
    }
}

function Get-OutputResults {
    param(
        [System.Collections.IEnumerable]$Results,
        [hashtable]$ConfidenceByTarget
    )

    foreach ($result in $Results) {
        New-OutputResult -Result $result -Confidence $ConfidenceByTarget[$result.Target]
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

function Add-TargetEntries {
    param(
        [System.Collections.ArrayList]$Destination,
        [string[]]$Values,
        [string]$Type
    )

    foreach ($value in $Values) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            [void]$Destination.Add([PSCustomObject]@{ Target = $value.Trim(); Type = $Type })
        }
    }
}

function Get-UniqueTargets {
    param([System.Collections.IEnumerable]$Targets)

    $uniqueTargets = [ordered]@{}
    foreach ($target in $Targets) {
        $key = "$($target.Type)|$($target.Target)"
        if (-not $uniqueTargets.Contains($key)) { $uniqueTargets[$key] = $target }
    }

    return @($uniqueTargets.Values)
}

function Write-Usage {
    Write-Host "Uso:" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -D dominio1.com | -IP 1.1.1.1 | -U https://sitio.com" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -Targets dominio1.com,1.1.1.1,https://sitio.com" -ForegroundColor Yellow
    Write-Host "  .\Scanner.ps1 -InputFile targets.txt" -ForegroundColor Yellow
}

$resolvedConfigPath = Get-ConfigPath -ExplicitPath $ConfigPath
$config = Read-ScannerConfig -Path $resolvedConfigPath
if (-not $config) { return }

$targetEntries = New-Object System.Collections.ArrayList
Add-TargetEntries -Destination $targetEntries -Values (@($Targets) + @(Get-InputFileTargets -Path $InputFile)) -Type "Auto"
Add-TargetEntries -Destination $targetEntries -Values $Domain -Type "Domain"
Add-TargetEntries -Destination $targetEntries -Values $Url -Type "URL"
Add-TargetEntries -Destination $targetEntries -Values $IPAddress -Type "IP"

$targetList = Get-UniqueTargets -Targets $targetEntries
if (-not $targetList -or $targetList.Count -eq 0) {
    Write-Usage
    return
}

if (-not $config.VirusTotal.ApiKey -or $config.VirusTotal.ApiKey -eq "TU_API_KEY_AQUI") {
    Write-Error "Falta configurar VirusTotal.ApiKey en config.json."
    return
}

$allResults = New-Object System.Collections.Generic.List[object]
$rdapBaseUri = if ($config.Whois.RdapBaseUri) { $config.Whois.RdapBaseUri } else { "https://rdap.org" }
$separator = ("-" * 78) -join ""

foreach ($targetEntry in $targetList) {
    $target = $targetEntry.Target
    $targetType = Resolve-TargetType -Target $target -Type $targetEntry.Type

    Write-Host "`n$separator" -ForegroundColor DarkCyan
    Write-Host "  OBJETIVO: $target [$targetType]" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor DarkCyan

    try {
        $virusTotalResult = Get-VTReport -Target $target -TargetType $targetType -ApiKey $config.VirusTotal.ApiKey
        Write-VirusTotalSummary -Result $virusTotalResult
        [void]$allResults.Add($virusTotalResult)
    }
    catch {
        Write-Warning "VirusTotal: $_"
    }

    if ($targetType -in @("Domain", "IP")) {
        try {
            $whoisResult = Get-WhoisReport -Target $target -TargetType $targetType -RdapBaseUri $rdapBaseUri
            Write-WhoisSummary -Result $whoisResult
            [void]$allResults.Add($whoisResult)
        }
        catch {
            Write-Warning "WHOIS/RDAP: $_"
        }
    }

    if ($targetType -in @("URL", "Domain") -and $config.Urlscan.ApiKey -and $config.Urlscan.ApiKey -ne "TU_API_KEY_AQUI") {
        try {
            $urlscanUrl = if ($targetType -eq "Domain") { "https://$target" } else { $target }
            $urlscanResult = Get-UrlscanReport `
                -Url $urlscanUrl `
                -DisplayTarget $target `
                -TargetType $targetType `
                -ApiKey $config.Urlscan.ApiKey `
                -Visibility $config.Urlscan.Visibility

            Write-UrlscanSummary -Result $urlscanResult
            [void]$allResults.Add($urlscanResult)

            if ($targetType -eq "URL" -and -not [string]::IsNullOrWhiteSpace($urlscanResult.UrlscanApexDomain)) {
                try {
                    $urlscanWhoisResult = Get-WhoisReport `
                        -Target $urlscanResult.UrlscanApexDomain `
                        -TargetType "Domain" `
                        -RdapBaseUri $rdapBaseUri

                    Write-WhoisSummary -Result $urlscanWhoisResult -Title "WHOIS / RDAP - dominio de urlscan"
                    [void]$allResults.Add($urlscanWhoisResult)
                }
                catch {
                    Write-Warning "WHOIS/RDAP (dominio de urlscan): $_"
                }
            }
        }
        catch {
            Write-Warning "urlscan.io: $_"
        }
    }

    if ($targetType -eq "IP" -and $config.AbuseIPDB.ApiKey -and $config.AbuseIPDB.ApiKey -ne "TU_API_KEY_AQUI") {
        try {
            $abuseIpDbResult = Get-AbuseIPDBReport -IPAddress $target -ApiKey $config.AbuseIPDB.ApiKey
            Write-AbuseIPDBSummary -Result $abuseIpDbResult
            [void]$allResults.Add($abuseIpDbResult)
        }
        catch {
            Write-Warning "AbuseIPDB: $_"
        }
    }

    if ($targetList.Count -gt 1 -and $targetEntry -ne $targetList[-1]) {
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
