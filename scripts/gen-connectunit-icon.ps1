# Regenerate windows/ConnectUnit.ico from windows/icon.svg geometry.
# Requires Python 3 with Pillow (pip install Pillow).
# Optional: ImageMagick `magick` — not used when Python script is present.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "Cargo.toml"))) {
    Write-Error "Run from repo scripts/ folder (Cargo.toml not found at $Root)"
}

$PyScript = Join-Path $Root "scripts\gen_connectunit_icon.py"
if (-not (Test-Path $PyScript)) {
    Write-Error "Missing $PyScript"
}

python $PyScript
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Icon ready at windows\ConnectUnit.ico - rebuild with: cargo build --release"
