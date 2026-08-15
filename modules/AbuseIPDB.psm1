$script:AbuseIPDBBaseUri = "https://api.abuseipdb.com/api/v2"


function Invoke-AbuseIPDBRequest {

    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [int]$MaxAgeInDays = 90
    )

    $headers = @{
        "Key"    = $ApiKey
        "Accept" = "application/json"
    }

    $query = @{
        ipAddress   = $IPAddress
        maxAgeInDays = $MaxAgeInDays
    }

    try {

        return Invoke-RestMethod `
            -Uri "$script:AbuseIPDBBaseUri/check" `
            -Headers $headers `
            -Method GET `
            -Body $query `
            -ErrorAction Stop
    }
    catch {

        $statusCode = $null

        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        switch ($statusCode) {

            401 {
                throw "API key de AbuseIPDB inválida."
            }

            429 {
                throw "Límite de AbuseIPDB alcanzado."
            }

            422 {
                throw "La IP enviada a AbuseIPDB no es válida."
            }

            default {
                throw "Error llamando a AbuseIPDB: $($_.Exception.Message)"
            }
        }
    }
}


function Get-AbuseIPDBReport {

    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $parsedIp = $null

    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsedIp)) {
        throw "'$IPAddress' no es una dirección IP válida."
    }

    Write-Host "    [AbuseIPDB] Consultando..." -ForegroundColor DarkCyan

    $response = Invoke-AbuseIPDBRequest `
        -IPAddress $IPAddress `
        -ApiKey $ApiKey `
        -MaxAgeInDays 90

    $data = $response.data

    return [PSCustomObject]@{
        Target             = $IPAddress
        Tipo               = "IP"
        AbuseConfidence    = $data.abuseConfidenceScore
        TotalReports       = $data.totalReports
        CountryCode        = $data.countryCode
        UsageType          = $data.usageType
        ISP                = $data.isp
        Domain             = $data.domain
        IsWhitelisted      = $data.isWhitelisted
        LastReportedAt     = $data.lastReportedAt
        Enlace             = "https://www.abuseipdb.com/check/$IPAddress"
        Proveedor          = "AbuseIPDB"
    }
}


function Write-AbuseIPDBSummary {

    param(
        [Parameter(Mandatory)]
        $Result
    )

    $score = 0

    $isNumeric = [int]::TryParse(
        [string]$Result.AbuseConfidence,
        [ref]$score
    )

    $color = "DarkGray"

    if ($isNumeric) {

        if ($score -ge 75) {
            $color = "Red"
        }
        elseif ($score -ge 25) {
            $color = "Yellow"
        }
        else {
            $color = "Green"
        }
    }

    Write-Host (
        "    AbuseIPDB -> confianza abuso: {0}% | reports: {1} | país: {2} | ISP: {3}" -f
        $Result.AbuseConfidence,
        $Result.TotalReports,
        $Result.CountryCode,
        $Result.ISP
    ) -ForegroundColor $color

    Write-Host "    $($Result.Enlace)" -ForegroundColor DarkGray
}


Export-ModuleMember -Function `
    Get-AbuseIPDBReport, `
    Write-AbuseIPDBSummary
