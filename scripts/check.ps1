# Rust-Proxy Local Check Script (ASCII-only for max compatibility)

Write-Host "--- Starting Project System Check ---"

# 1. Environment Check
Write-Host "[1/3] Checking eBPF target..."
$targets = rustup target list --installed
if ($targets -notcontains "bpfel-unknown-none") {
    Write-Host "Installing missing target..."
    rustup target add bpfel-unknown-none
}

# 2. Kernel Code Check
$currentDir = Get-Location
try {
    if (Test-Path "rust-proxy-ebpf") {
        Write-Host "[2/3] Checking eBPF (Kernel) code..."
        Set-Location "rust-proxy-ebpf"
        cargo check --target bpfel-unknown-none
        if ($LASTEXITCODE -ne 0) {
            Write-Host "!!! eBPF Check Failed !!!" -ForegroundColor Red
            exit 1
        }
    }
} finally {
    Set-Location $currentDir
}

# 3. User Code Check
Write-Host "[3/3] Checking User Space & Tests..."
cargo test --lib domain::protocol::sni
if ($LASTEXITCODE -ne 0) {
    Write-Host "!!! Unit Test Failed !!!" -ForegroundColor Red
    exit 1
}

Write-Host "--- ALL CHECKS PASSED. Ready to commit. ---" -ForegroundColor Green
