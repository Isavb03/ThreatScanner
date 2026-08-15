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

function Get-UrlscanReport {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [ValidateSet("public", "unlisted", "private")]
        [string]$Visibility = "unlisted"
    )

    Write-Host "    [urlscan.io] Enviando URL para analisis..." -ForegroundColor DarkCyan
    $submission = Invoke-UrlscanRequest `
        -Uri "$script:UrlscanBaseUri/scan/" `
        -ApiKey $ApiKey `
        -Method "POST" `
        -Body @{ url = $Url; visibility = $Visibility }

    $uuid = $submission.uuid
    if (-not $uuid) { throw "urlscan.io no devolvio un identificador de analisis." }

    $resultLink = if ($submission.result) { $submission.result } else { "https://urlscan.io/result/$uuid/" }
    Start-Sleep -Seconds 15
    $result = Invoke-UrlscanRequest `
        -Uri "$script:UrlscanBaseUri/result/$uuid/" `
        -ApiKey $ApiKey `
        -AllowNotFound

    if (-not $result) {
        return [PSCustomObject]@{
            Target            = $Url
            Tipo              = "URL"
            UrlscanUuid       = $uuid
            UrlscanScore      = "pendiente"
            UrlscanCategories = "pendiente"
            UrlscanStatus     = "pendiente"
            UrlscanCountry    = "N/D"
            UrlscanDomain     = "N/D"
            UrlscanVisibility = $submission.visibility
            Enlace            = $resultLink
            Proveedor         = "urlscan.io"
        }
    }

    return [PSCustomObject]@{
        Target            = $Url
        Tipo              = "URL"
        UrlscanUuid       = $uuid
        UrlscanScore      = $result.verdicts.urlscan.score
        UrlscanCategories = $result.verdicts.urlscan.categories -join ", "
        UrlscanStatus     = $result.page.status
        UrlscanCountry    = $result.page.country
        UrlscanDomain     = $result.page.domain
        UrlscanVisibility = $result.task.visibility
        Enlace            = $resultLink
        Proveedor         = "urlscan.io"
    }
}

function Write-UrlscanSummary {
    param([Parameter(Mandatory)]$Result)

    $score = 0
    $isNumeric = [int]::TryParse([string]$Result.UrlscanScore, [ref]$score)
    $color = "DarkGray"

    if ($isNumeric) {
        if ($score -ge 50) { $color = "Red" }
        elseif ($score -gt 0) { $color = "Yellow" }
        else { $color = "Green" }
    }

    Write-Host (
        "    urlscan.io -> score: {0} | estado HTTP: {1} | dominio: {2}" -f
        $Result.UrlscanScore,
        $Result.UrlscanStatus,
        $Result.UrlscanDomain
    ) -ForegroundColor $color
    Write-Host "    $($Result.Enlace)" -ForegroundColor DarkGray
}

Export-ModuleMember -Function `
    Get-UrlscanReport, `
    Write-UrlscanSummary
