# GOLD-ADAPT-PWF-01 — Operator companion script for manual plan-hash verification.
#
# NEOTH's Rust daemon computes and verifies the SHA-256 hash of task_plan.md
# automatically on every writing_plans / executing_plans turn. Use this script
# to independently verify the hash from a PowerShell prompt, e.g. after a
# suspicious "[PLAN TAMPERED]" block, to confirm which version of the file
# was present.
#
# Usage:
#   cd <project-dir>
#   .\scripts\attest-plan.ps1
#
# Output: lowercase hex SHA-256 of task_plan.md (matches NEOTH's Rust output).

param(
    [string]$PlanFile = "task_plan.md"
)

$resolved = Resolve-Path -LiteralPath $PlanFile -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-Error "task_plan.md not found at: $(Join-Path (Get-Location) $PlanFile)"
    exit 1
}

$hash = Get-FileHash -LiteralPath $resolved.Path -Algorithm SHA256
# Output as lowercase hex to match Rust's sha2 format!("{:x}", hasher.finalize())
$hash.Hash.ToLower()
