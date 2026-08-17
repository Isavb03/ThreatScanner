$script:GoogleSafeBrowsingBaseUri = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

function Invoke-GoogleSafeBrowsingRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $requestBody = @{
        client = @{
            clientId      = "threatscanner"
            clientVersion = "1.0"
        }
        threatInfo = @{
            threatTypes      = @("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
            platformTypes    = @("ANY_PLATFORM")
            threatEntryTypes = @("URL")
            threatEntries    = @(@{ url = $Url })
        }
    } | ConvertTo-Json -Depth 5 -Compress

    $apiKey = [Uri]::EscapeDataString($ApiKey)

    try {
        return Invoke-RestMethod `
            -Uri "$script:GoogleSafeBrowsingBaseUri`?key=$apiKey" `
            -Method Post `
            -ContentType "application/json" `
            -Body $requestBody `
            -ErrorAction Stop
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        switch ($statusCode) {
            400 { throw "Google Safe Browsing rechazo la URL o la solicitud." }
            403 { throw "API key de Google Safe Browsing invalida o sin permiso." }
            429 { throw "Limite de Google Safe Browsing alcanzado." }
            default { throw "Error llamando a Google Safe Browsing: $($_.Exception.Message)" }
        }
    }
}

function Get-GoogleSafeBrowsingReport {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    Write-Host "`n  [Google Safe Browsing]" -ForegroundColor White
    Write-Host "  Estado: consultando..." -ForegroundColor DarkCyan

    $response = Invoke-GoogleSafeBrowsingRequest -Url $Url -ApiKey $ApiKey
    $matches = @($response.matches | Where-Object { $null -ne $_ })
    $threats = @($matches | ForEach-Object { $_.threatType } | Select-Object -Unique)
    $hasThreats = $matches.Count -gt 0

    return [PSCustomObject]@{
        Target                    = $Url
        Tipo                      = "URL"
        GoogleSafeBrowsingStatus  = if ($hasThreats) { "Amenazas detectadas" } else { "Sin amenazas detectadas" }
        GoogleSafeBrowsingThreats = if ($hasThreats) { $threats -join ", " } else { "Ninguna" }
        GoogleSafeBrowsingMatches = $matches.Count
        GoogleSafeBrowsingMatched = $hasThreats
        Enlace                    = "https://transparencyreport.google.com/safe-browsing/search?url=$([Uri]::EscapeDataString($Url))"
        Proveedor                 = "Google Safe Browsing"
    }
}

function Write-GoogleSafeBrowsingSummary {
    param([Parameter(Mandatory)]$Result)

    $color = if ($Result.GoogleSafeBrowsingMatched) { "Red" } else { "Green" }
    Write-Host (
        "  Resultado: {0} | amenazas: {1}" -f
        $Result.GoogleSafeBrowsingStatus,
        $Result.GoogleSafeBrowsingThreats
    ) -ForegroundColor $color
    Write-Host "  GUI: $($Result.Enlace)" -ForegroundColor DarkGray
}

Export-ModuleMember -Function `
    Get-GoogleSafeBrowsingReport, `
    Write-GoogleSafeBrowsingSummary
