$script:VTBaseUri = "https://www.virustotal.com/api/v3"

function ConvertTo-VTUrlId {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $base64Url = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Url))
    return $base64Url.TrimEnd('=').Replace('+', '-').Replace('/', '_')
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

    $requestParameters = @{
        Uri         = $Uri
        Headers     = @{ "x-apikey" = $ApiKey }
        Method      = $Method
        ErrorAction = "Stop"
    }

    if ($Body) {
        $requestParameters.Body = $Body
        $requestParameters.ContentType = "application/x-www-form-urlencoded"
    }

    try {
        return Invoke-RestMethod @requestParameters
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

function Get-VTGuiLink {
    param(
        [ValidateSet("IP", "Domain", "URL")]
        [string]$TargetType,
        [string]$Target,
        $Response
    )

    switch ($TargetType) {
        "IP" { return "https://www.virustotal.com/gui/ip-address/$Target" }
        "Domain" { return "https://www.virustotal.com/gui/domain/$Target" }
        "URL" { return "https://www.virustotal.com/gui/url/$($Response.data.id)" }
    }
}

function New-VTReport {
    param(
        [string]$Target,
        [ValidateSet("IP", "Domain", "URL")]
        [string]$TargetType,
        $Response
    )

    $typeLabel = switch ($TargetType) {
        "IP" { "IP" }
        "Domain" { "Dominio" }
        "URL" { "URL" }
    }

    if ($Response) {
        $statistics = $Response.data.attributes.last_analysis_stats
        return [PSCustomObject]@{
            Target       = $Target
            Tipo         = $typeLabel
            Maliciosos   = $statistics.malicious
            Sospechosos  = $statistics.suspicious
            Limpios      = $statistics.harmless
            SinDetectar  = $statistics.undetected
            Reputacion   = $Response.data.attributes.reputation
            Enlace       = Get-VTGuiLink -TargetType $TargetType -Target $Target -Response $Response
            Proveedor    = "VirusTotal"
        }
    }

    return [PSCustomObject]@{
        Target       = $Target
        Tipo         = $typeLabel
        Maliciosos   = "N/D"
        Sospechosos  = "N/D"
        Limpios      = "N/D"
        SinDetectar  = "N/D"
        Reputacion   = "N/D"
        Enlace       = Get-VTGuiLink -TargetType $TargetType -Target $Target
        Proveedor    = "VirusTotal"
    }
}

function New-VTPendingUrlReport {
    param([string]$Url)

    return [PSCustomObject]@{
        Target       = $Url
        Tipo         = "URL"
        Maliciosos   = "pendiente"
        Sospechosos  = "pendiente"
        Limpios      = "pendiente"
        SinDetectar  = "pendiente"
        Reputacion   = "N/D"
        Enlace       = "N/D"
        Proveedor    = "VirusTotal"
    }
}

function Get-VTDomainReport {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $response = Invoke-VTRequest -Uri "$script:VTBaseUri/domains/$Domain" -ApiKey $ApiKey
    return New-VTReport -Target $Domain -TargetType "Domain" -Response $response
}

function Get-VTUrlReport {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $urlId = ConvertTo-VTUrlId -Url $Url
    $response = Invoke-VTRequest -Uri "$script:VTBaseUri/urls/$urlId" -ApiKey $ApiKey

    if (-not $response) {
        Write-Host "    (sin informe previo en VT, enviando para analisis...)" -ForegroundColor DarkGray
        $null = Invoke-VTRequest -Uri "$script:VTBaseUri/urls" -ApiKey $ApiKey -Method "POST" -Body @{ url = $Url }
        Start-Sleep -Seconds 15
        $response = Invoke-VTRequest -Uri "$script:VTBaseUri/urls/$urlId" -ApiKey $ApiKey

        if (-not $response) {
            return New-VTPendingUrlReport -Url $Url
        }
    }

    return New-VTReport -Target $Url -TargetType "URL" -Response $response
}

function Get-VTIPReport {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $response = Invoke-VTRequest -Uri "$script:VTBaseUri/ip_addresses/$IPAddress" -ApiKey $ApiKey
    return New-VTReport -Target $IPAddress -TargetType "IP" -Response $response
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
        "IP" { return Get-VTIPReport -IPAddress $Target -ApiKey $ApiKey }
        "Domain" { return Get-VTDomainReport -Domain $Target -ApiKey $ApiKey }
        "URL" { return Get-VTUrlReport -Url $Target -ApiKey $ApiKey }
    }
}

Export-ModuleMember -Function Get-VTReport, Get-VTDomainReport, Get-VTUrlReport, Get-VTIPReport
