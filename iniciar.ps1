$ErrorActionPreference = 'Stop'

Write-Host 'duckspy - inicialização local' -ForegroundColor Cyan
Write-Host 'Cole sua chave privada do VirusTotal. Ela não será exibida nem salva em arquivo.'
$secureKey = Read-Host 'Chave da API' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)

try {
    $env:VT_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw 'Node.js não encontrado. Instale a versão LTS em https://nodejs.org/en/download e abra um novo PowerShell.'
    }
    Write-Host 'Iniciando o site. Mantenha esta janela aberta.' -ForegroundColor Green
    Write-Host 'Abra http://localhost:3000 no navegador.' -ForegroundColor Green
    node (Join-Path $PSScriptRoot 'server.js')
}
finally {
    Remove-Item Env:\VT_API_KEY -ErrorAction SilentlyContinue
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    $secureKey.Dispose()
}
