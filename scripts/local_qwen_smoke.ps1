# NEOTH local-Qwen real-weights smoke test (Windows PowerShell).
#
# Runs the gated integration test `local_qwen_forward_pass_against_cached_weights`
# against the operator's already-cached Qwen2 weights. The test loads the
# model, prompts "Capital of France?", asserts the reply contains "paris".
#
# Usage (from repo root):
#   pwsh scripts\local_qwen_smoke.ps1
#
# Prerequisites:
#   1. `neoth init` was run + the operator picked local_qwen
#   2. `~/.neoth/models/Qwen-Qwen2.5-3B-Instruct/` exists with
#      tokenizer.json, config.json, model.safetensors

$ErrorActionPreference = "Stop"

$repo = "Qwen-Qwen2.5-3B-Instruct"
$home_models = Join-Path $env:USERPROFILE ".neoth\models\$repo"

if (-not (Test-Path (Join-Path $home_models "tokenizer.json"))) {
    Write-Host "ERROR: tokenizer.json missing at $home_models" -ForegroundColor Red
    Write-Host "Run 'neoth init' first and pick local_qwen so the wizard caches weights." -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path (Join-Path $home_models "model.safetensors"))) {
    Write-Host "ERROR: model.safetensors missing at $home_models" -ForegroundColor Red
    exit 1
}

Write-Host "Cache directory: $home_models" -ForegroundColor Cyan
$env:NEOTH_QWEN_TEST_REPO_PATH = $home_models

$start = Get-Date
Write-Host "Running gated test (this may take 20-60s on CPU)..." -ForegroundColor Cyan
& "C:\Temp\build-neoth.cmd" test -p neoth `
    --release `
    -- `
    --ignored `
    local_qwen_forward_pass_against_cached_weights `
    --nocapture
$exit = $LASTEXITCODE
$elapsed = (Get-Date) - $start

if ($exit -ne 0) {
    Write-Host "Test failed after $($elapsed.TotalSeconds)s" -ForegroundColor Red
    exit $exit
}
Write-Host "PASS in $($elapsed.TotalSeconds)s" -ForegroundColor Green
