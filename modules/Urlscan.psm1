$script:UrlscanBaseUri = "https://urlscan.io/api/v1"

function Invoke-UrlscanRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [ValidateSet("GET", "POST")]
        [string]$Method = "GET",

        [hashtable]$Body,

        [switch]$AllowNotFound
    )

    $params = @{
        Uri         = $Uri
        Headers     = @{ "api-key" = $ApiKey }
        Method      = $Method
        ErrorAction = "Stop"
    }

    if ($Body) {
        $params["Body"] = $Body | ConvertTo-Json -Compress
        $params["ContentType"] = "application/json"
    }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 404 -and $AllowNotFound) { return $null }

        switch ($statusCode) {
            400 { throw "urlscan.io rechazo la URL: $($_.Exception.Message)" }
            401 { throw "API key de urlscan.io invalida o ausente." }
            403 { throw "No tienes permiso para usar la API de urlscan.io." }
            410 { throw "El resultado de urlscan.io fue eliminado." }
            429 { throw "Rate limit de urlscan.io alcanzado. Espera e intenta de nuevo." }
            default { throw "Error llamando a urlscan.io ($Uri): $($_.Exception.Message)" }
        }
    }
}

function Get-UrlscanDomainAge {
    param($Result)

    $ageDays = 0
    $hasAge = [int]::TryParse([string]$Result.page.domainAgeDays, [ref]$ageDays)
    if (-not $hasAge) {
        $hasAge = [int]::TryParse([string]$Result.page.apexDomainAgeDays, [ref]$ageDays)
    }

    if (-not $hasAge) {
        return [PSCustomObject]@{ Date = "N/D"; Days = "N/D"; Color = "DarkGray" }
    }

    $scanDate = [DateTime]::UtcNow
    if ($Result.task.time) {
        $parsedDate = [DateTime]::MinValue
        if ([DateTime]::TryParse([string]$Result.task.time, [ref]$parsedDate)) {
            $scanDate = $parsedDate.ToUniversalTime()
        }
    }

    $color = if ($ageDays -lt 30) { "Red" } elseif ($ageDays -le 90) { "Yellow" } elseif ($ageDays -gt 365) { "Green" } else { "Yellow" }
    return [PSCustomObject]@{
        Date  = $scanDate.AddDays(-$ageDays).ToString("yyyy-MM-dd")
        Days  = $ageDays
        Color = $color
    }
}

function Get-UrlscanReport {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [string]$DisplayTarget,

        [ValidateSet("URL", "Domain")]
        [string]$TargetType = "URL",

        [ValidateSet("public", "unlisted", "private")]
        [string]$Visibility = "unlisted"
    )

    $reportTarget = if ($DisplayTarget) { $DisplayTarget } else { $Url }
    $reportType = if ($TargetType -eq "Domain") { "Dominio" } else { "URL" }

    Write-Host "`n  [urlscan.io]" -ForegroundColor White
    Write-Host "  Estado: enviando URL para analisis..." -ForegroundColor DarkCyan
    $submission = Invoke-UrlscanRequest `
        -Uri "$script:UrlscanBaseUri/scan/" `
        -ApiKey $ApiKey `
        -Method "POST" `
        -Body @{ url = $Url; visibility = $Visibility }

    $uuid = $submission.uuid
    if (-not $uuid) { throw "urlscan.io no devolvio un identificador de analisis." }

    $resultLink = if ($submission.result) { $submission.result } else { "https://urlscan.io/result/$uuid/" }
    Write-Host "  Estado: esperando resultado..." -ForegroundColor DarkCyan
    Start-Sleep -Seconds 10

    do {
        $result = Invoke-UrlscanRequest `
            -Uri "$script:UrlscanBaseUri/result/$uuid/" `
            -ApiKey $ApiKey `
            -AllowNotFound

        if (-not $result) { Start-Sleep -Seconds 5 }
    } while (-not $result)

    if ([string]::IsNullOrWhiteSpace([string]$result.page.status)) {
        return [PSCustomObject]@{
            Target            = $reportTarget
            Tipo              = $reportType
            UrlscanUuid       = $uuid
            UrlscanScore      = "N/D"
            UrlscanCategories = "N/D"
            UrlscanStatus     = "No evaluable"
            UrlscanCountry    = $result.page.country
            UrlscanDomain     = $result.page.domain
            UrlscanVisibility = $result.task.visibility
            UrlscanScanFailed = $true
            UrlscanDomainCreated = "N/D"
            UrlscanDomainAgeDays = "N/D"
            UrlscanDomainAgeColor = "DarkGray"
            Enlace            = $resultLink
            Proveedor         = "urlscan.io"
        }
    }

    $domainAge = Get-UrlscanDomainAge -Result $result
    return [PSCustomObject]@{
        Target            = $reportTarget
        Tipo              = $reportType
        UrlscanUuid       = $uuid
        UrlscanScore      = $result.verdicts.urlscan.score
        UrlscanCategories = $result.verdicts.urlscan.categories -join ", "
        UrlscanStatus     = $result.page.status
        UrlscanCountry    = $result.page.country
        UrlscanDomain     = $result.page.domain
        UrlscanVisibility = $result.task.visibility
        UrlscanScanFailed = $false
        UrlscanDomainCreated = $domainAge.Date
        UrlscanDomainAgeDays = $domainAge.Days
        UrlscanDomainAgeColor = $domainAge.Color
        Enlace            = $resultLink
        Proveedor         = "urlscan.io"
    }
}

function Write-UrlscanSummary {
    param([Parameter(Mandatory)]$Result)

    $score = 0
    $isNumeric = [int]::TryParse([string]$Result.UrlscanScore, [ref]$score)
    $color = "DarkGray"

    if ($Result.UrlscanScanFailed) {
        $color = "Yellow"
    }
    elseif ($isNumeric) {
        if ($score -ge 50) { $color = "Red" }
        elseif ($score -gt 0) { $color = "Yellow" }
        else { $color = "Green" }
    }

    Write-Host (
        "  Resultado: score: {0} | estado HTTP: {1} | dominio: {2}" -f
        $Result.UrlscanScore,
        $Result.UrlscanStatus,
        $Result.UrlscanDomain
    ) -ForegroundColor $color
    Write-Host "  Dominio creado: $($Result.UrlscanDomainCreated) ($($Result.UrlscanDomainAgeDays) dias)" -ForegroundColor $Result.UrlscanDomainAgeColor
    Write-Host "  GUI: $($Result.Enlace)" -ForegroundColor DarkGray
}

Export-ModuleMember -Function `
    Get-UrlscanReport, `
    Write-UrlscanSummary
