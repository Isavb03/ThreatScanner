$script:DefaultRdapBaseUri = "https://rdap.org"

function Invoke-RdapRequest {
    param([Parameter(Mandatory)][string]$Uri)

    try {
        return Invoke-RestMethod -Uri $Uri -Method GET -ErrorAction Stop
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        switch ($statusCode) {
            404 { return $null }
            400 { throw "Consulta RDAP no valida: $($_.Exception.Message)" }
            403 { throw "RDAP rechazo la consulta por limite o politicas del servidor." }
            429 { throw "Rate limit de RDAP alcanzado. Espera e intenta de nuevo." }
            default { throw "Error llamando a RDAP ($Uri): $($_.Exception.Message)" }
        }
    }
}

function Get-RdapEventDate {
    param($Events, [string]$Action)

    $event = $Events | Where-Object { $_.eventAction -eq $Action } | Select-Object -First 1
    if ($event) { return $event.eventDate }

    return "N/D"
}

function Get-RdapRegistrar {
    param($Entities)

    $registrar = $Entities | Where-Object { $_.roles -contains "registrar" } | Select-Object -First 1
    if (-not $registrar) { return "N/D" }

    $name = $registrar.vcardArray[1] |
        Where-Object { $_[0] -eq "fn" } |
        ForEach-Object { $_[3] } |
        Select-Object -First 1

    if ($name) { return $name }
    if ($registrar.handle) { return $registrar.handle }

    return "N/D"
}

function New-WhoisResult {
    param([string]$Target, [string]$Type, [string]$Link)

    return [PSCustomObject]@{
        Target         = $Target
        Tipo           = $Type
        WhoisRegistrar = "N/D"
        WhoisCreated   = "N/D"
        WhoisExpires   = "N/D"
        WhoisStatus    = "N/D"
        WhoisCountry   = "N/D"
        WhoisNetwork   = "N/D"
        Enlace         = $Link
        Proveedor      = "RDAP (WHOIS)"
    }
}

function Get-WhoisDomainReport {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$RdapBaseUri = $script:DefaultRdapBaseUri
    )

    $uri = "$($RdapBaseUri.TrimEnd('/'))/domain/$Domain"
    $response = Invoke-RdapRequest -Uri $uri
    if (-not $response) { return New-WhoisResult -Target $Domain -Type "Dominio" -Link $uri }

    $result = New-WhoisResult -Target $Domain -Type "Dominio" -Link $uri
    $result.WhoisRegistrar = Get-RdapRegistrar -Entities $response.entities
    $result.WhoisCreated = Get-RdapEventDate -Events $response.events -Action "registration"
    $result.WhoisExpires = Get-RdapEventDate -Events $response.events -Action "expiration"
    $result.WhoisStatus = $response.status -join ", "
    $result.WhoisCountry = $response.entities |
        Where-Object { $_.roles -contains "registrant" } |
        ForEach-Object { $_.country } |
        Select-Object -First 1
    if (-not $result.WhoisCountry) { $result.WhoisCountry = "N/D" }

    return $result
}

function Get-WhoisIPReport {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [string]$RdapBaseUri = $script:DefaultRdapBaseUri
    )

    $uri = "$($RdapBaseUri.TrimEnd('/'))/ip/$IPAddress"
    $response = Invoke-RdapRequest -Uri $uri
    if (-not $response) { return New-WhoisResult -Target $IPAddress -Type "IP" -Link $uri }

    $result = New-WhoisResult -Target $IPAddress -Type "IP" -Link $uri
    $result.WhoisNetwork = $response.name
    $result.WhoisCountry = $response.country
    $result.WhoisStatus = $response.status -join ", "
    if (-not $result.WhoisNetwork) { $result.WhoisNetwork = "$($response.startAddress) - $($response.endAddress)" }
    if (-not $result.WhoisCountry) { $result.WhoisCountry = "N/D" }

    return $result
}

function Get-WhoisReport {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet("Domain", "IP")][string]$TargetType,
        [string]$RdapBaseUri = $script:DefaultRdapBaseUri
    )

    if ($TargetType -eq "Domain") {
        return Get-WhoisDomainReport -Domain $Target -RdapBaseUri $RdapBaseUri
    }

    return Get-WhoisIPReport -IPAddress $Target -RdapBaseUri $RdapBaseUri
}

function Write-WhoisSummary {
    param([Parameter(Mandatory)]$Result)

    Write-Host "`n  [WHOIS / RDAP]" -ForegroundColor White
    if ($Result.Tipo -eq "Dominio") {
        Write-Host (
            "  Resultado: registrador: {0} | creado: {1} | expira: {2}" -f
            $Result.WhoisRegistrar,
            $Result.WhoisCreated,
            $Result.WhoisExpires
        ) -ForegroundColor DarkCyan
    }
    else {
        Write-Host (
            "  Resultado: red: {0} | pais: {1} | estado: {2}" -f
            $Result.WhoisNetwork,
            $Result.WhoisCountry,
            $Result.WhoisStatus
        ) -ForegroundColor DarkCyan
    }

    Write-Host "  GUI: $($Result.Enlace)" -ForegroundColor DarkGray
}

Export-ModuleMember -Function `
    Get-WhoisReport, `
    Get-WhoisDomainReport, `
    Get-WhoisIPReport, `
    Write-WhoisSummary
