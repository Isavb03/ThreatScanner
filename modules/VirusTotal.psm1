$script:VTBaseUri = "https://www.virustotal.com/api/v3"

function ConvertTo-VTUrlId {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Url)
    $b64 = [Convert]::ToBase64String($bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Invoke-VTRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [string]$Method = "GET",

        [hashtable]$Body
    )

    $headers = @{ "x-apikey" = $ApiKey }
    $params = @{
        Uri     = $Uri
        Headers = $headers
        Method  = $Method
        ErrorAction = "Stop"
    }
    if ($Body) {
        $params["Body"] = $Body
        $params["ContentType"] = "application/x-www-form-urlencoded"
    }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        switch ($statusCode) {
            404 { return $null }
            401 { throw "API key de VirusTotal invalida o ausente." }
            429 { throw "Rate limit de VirusTotal alcanzado (capa gratuita: 4 peticiones/min). Espera e intenta de nuevo." }
            default { throw "Error llamando a VirusTotal ($Uri): $($_.Exception.Message)" }
        }
    }
}

function Get-VTDomainReport {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $uri = "$script:VTBaseUri/domains/$Domain"
    $response = Invoke-VTRequest -Uri $uri -ApiKey $ApiKey

    if (-not $response) {
        return [PSCustomObject]@{
            Target      = $Domain
            Tipo        = "Dominio"
            Maliciosos  = "N/D"
            Sospechosos = "N/D"
            Limpios     = "N/D"
            SinDetectar = "N/D"
            Reputacion  = "N/D"
            Enlace      = "https://www.virustotal.com/gui/domain/$Domain"
            Proveedor   = "VirusTotal"
        }
    }

    $stats = $response.data.attributes.last_analysis_stats
    return [PSCustomObject]@{
        Target      = $Domain
        Tipo        = "Dominio"
        Maliciosos  = $stats.malicious
        Sospechosos = $stats.suspicious
        Limpios     = $stats.harmless
        SinDetectar = $stats.undetected
        Reputacion  = $response.data.attributes.reputation
        Enlace      = "https://www.virustotal.com/gui/domain/$Domain"
        Proveedor   = "VirusTotal"
    }
}

function Get-VTUrlReport {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $urlId = ConvertTo-VTUrlId -Url $Url
    $uri = "$script:VTBaseUri/urls/$urlId"
    $response = Invoke-VTRequest -Uri $uri -ApiKey $ApiKey

    if (-not $response) {
        Write-Host "    (sin informe previo en VT, enviando para analisis...)" -ForegroundColor DarkGray
        $submitUri = "$script:VTBaseUri/urls"
        $null = Invoke-VTRequest -Uri $submitUri -ApiKey $ApiKey -Method "POST" -Body @{ url = $Url }

        Start-Sleep -Seconds 15
        $response = Invoke-VTRequest -Uri $uri -ApiKey $ApiKey
    }

    if (-not $response) {
        return [PSCustomObject]@{
            Target      = $Url
            Tipo        = "URL"
            Maliciosos  = "pendiente"
            Sospechosos = "pendiente"
            Limpios     = "pendiente"
            SinDetectar = "pendiente"
            Reputacion  = "N/D"
            Enlace      = "N/D"
            Proveedor   = "VirusTotal"
        }
    }

    $stats = $response.data.attributes.last_analysis_stats
    return [PSCustomObject]@{
        Target      = $Url
        Tipo        = "URL"
        Maliciosos  = $stats.malicious
        Sospechosos = $stats.suspicious
        Limpios     = $stats.harmless
        SinDetectar = $stats.undetected
        Reputacion  = $response.data.attributes.reputation
        Enlace      = "https://www.virustotal.com/gui/url/$($response.data.id)"
        Proveedor   = "VirusTotal"
    }
}

function Get-VTIPReport {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $uri = "$script:VTBaseUri/ip_addresses/$IPAddress"

    $response = Invoke-VTRequest `
        -Uri $uri `
        -ApiKey $ApiKey

    if (-not $response) {
        return [PSCustomObject]@{
            Target      = $IPAddress
            Tipo        = "IP"
            Maliciosos  = "N/D"
            Sospechosos = "N/D"
            Limpios     = "N/D"
            SinDetectar = "N/D"
            Reputacion  = "N/D"
            Enlace      = "https://www.virustotal.com/gui/ip-address/$IPAddress"
            Proveedor   = "VirusTotal"
        }
    }

    $stats = $response.data.attributes.last_analysis_stats

    return [PSCustomObject]@{
        Target      = $IPAddress
        Tipo        = "IP"
        Maliciosos  = $stats.malicious
        Sospechosos = $stats.suspicious
        Limpios     = $stats.harmless
        SinDetectar = $stats.undetected
        Reputacion  = $response.data.attributes.reputation
        Enlace      = "https://www.virustotal.com/gui/ip-address/$IPAddress"
        Proveedor   = "VirusTotal"
    }
}

function Get-VTReport {
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateSet("IP", "Domain", "URL")]
        [string]$TargetType,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    switch ($TargetType) {

        "IP" {
            return Get-VTIPReport `
                -IPAddress $Target `
                -ApiKey $ApiKey
        }

        "Domain" {
            return Get-VTDomainReport `
                -Domain $Target `
                -ApiKey $ApiKey
        }

        "URL" {
            return Get-VTUrlReport `
                -Url $Target `
                -ApiKey $ApiKey
        }
    }
}

Export-ModuleMember -Function `
    Get-VTReport, `
    Get-VTDomainReport, `
    Get-VTUrlReport, `
    Get-VTIPReport
