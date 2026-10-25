# Serves the debug APK on the Wi-Fi address only, with a QR code for the phone.
# Binding to one address keeps the file off VPN, WSL and other adapters.
# Run through `mise run android:share`. Ctrl+C stops the server.
$ErrorActionPreference = 'Stop'

$apkDir = Join-Path $PSScriptRoot '..\app\build\outputs\apk\debug'
$apk = Join-Path $apkDir 'app-debug.apk'
if (-not (Test-Path $apk)) {
    throw "No APK at $apk. Run mise run android:debug first."
}

# Guessing wrong here makes the QR code useless, so stop unless exactly one
# candidate adapter is found. SERVE_IP overrides the choice.
$virtual = 'WSL|Hyper-V|vEthernet|NordLynx|OpenVPN|VPN|Docker|Bluetooth|Loopback'
$candidates = @(Get-NetIPConfiguration | Where-Object {
    $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and $_.InterfaceAlias -notmatch $virtual
})
if ($env:SERVE_IP) {
    $ip = $env:SERVE_IP
} elseif ($candidates.Count -eq 1) {
    $ip = $candidates[0].IPv4Address.IPAddress
} else {
    $names = ($candidates | ForEach-Object { $_.InterfaceAlias }) -join ', '
    throw "Found $($candidates.Count) Wi-Fi candidates [$names]. Set SERVE_IP to the laptop's Wi-Fi address."
}

$port = if ($env:SERVE_PORT) { $env:SERVE_PORT } else { '8000' }
$url = "http://${ip}:${port}/app-debug.apk"

Write-Host ''
Write-Host "Download address: $url" -ForegroundColor Green
Write-Host ''

# The QR code needs the qrcode package. Without it, the link above still works.
python -c "import qrcode" 2>$null
if ($LASTEXITCODE -eq 0) {
    python -c "import qrcode,sys; q=qrcode.QRCode(); q.add_data(sys.argv[1]); q.print_ascii(invert=True)" $url
} else {
    Write-Host 'No QR code: the qrcode package is missing. Run: pip install qrcode' -ForegroundColor Yellow
}

Write-Host ''
Write-Host "Serving $apkDir on ${ip}:${port}. Ctrl+C stops it. Anyone on this Wi-Fi who has the link can download the APK while it runs." -ForegroundColor Yellow
python -m http.server $port --bind $ip --directory $apkDir
