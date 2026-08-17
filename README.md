# ThreatScanner

## Uso

```powershell
# Dominio
.\Scanner.ps1 -D "example.com"

# IP
.\Scanner.ps1 -IP "8.8.8.8"

# URL
.\Scanner.ps1 -U "https://example.com/login"

# Lista combinada: dominios, IPs y URLs
.\Scanner.ps1 -Targets "example.com","8.8.8.8","https://example.com/login"

# Lista desde archivo
.\Scanner.ps1 -InputFile ".\targets.txt"

# Exportar el resultado
.\Scanner.ps1 -D "example.com" -OutputCsv ".\results.csv"

# Usar otro archivo de configuracion
.\Scanner.ps1 -D "example.com" -ConfigPath ".\config\config.json"
```

`-Targets` detecta automáticamente cada tipo. `-D`, `-IP` y `-U` fuerzan el tipo indicado.

urlscan.io analiza URLs y dominios. Los dominios se envian como `https://<dominio>`.

## Google Safe Browsing

1. Crea un proyecto en [Google Cloud Console](https://console.cloud.google.com/), activa **Safe Browsing APIs** y crea una API key.
2. Añade la clave en `config/config.json`:

```json
"GoogleSafeBrowsing": { "ApiKey": "TU_API_KEY_AQUI" }
```

Google Safe Browsing analiza URLs y se ejecuta con `-U` o con URLs en `-Targets`. Es gratuito para uso no comercial.

La columna `Confianza` mide el riesgo combinado: verde (0-33%), amarillo (34-66%) y rojo (67-100%). Combina VirusTotal, AbuseIPDB, urlscan.io y Google Safe Browsing; RDAP/WHOIS no se usa para el cálculo.
