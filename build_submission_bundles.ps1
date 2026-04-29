param(
  [string]$OutputDir = "submission_dist"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $root $OutputDir
if (Test-Path $out) {
  Remove-Item -Recurse -Force $out
}
New-Item -ItemType Directory -Path $out | Out-Null

$coreFiles = @(
  "requirements.txt",
  "config.py",
  "enforcer.py",
  "rebuff_engine.py",
  "whisper_detector.py",
  "mimicry_hunter.py",
  "ghost_monitor.py",
  "vault_guardian.py",
  "kinetic_hooks.py",
  "p2p_mesh.py",
  "osint_expert.py",
  "neural_mirror.py",
  "calibrate.py",
  "security_logging.py",
  "preseed_ioc_cache.py",
  "export_security_metrics_prometheus.py",
  "_smoke_v2.py",
  "tests/test_core_security.py",
  "README.md",
  "GO_NOGO_PACK.md",
  "SUBMISSION_CHECKLIST.md",
  "FINAL_SUBMISSION_PACKET.md",
  "EXECUTIVE_SUMMARY.md",
  "REVIEWER_QUICKSTART.md",
  "SUBMISSION_LETTER.md",
  "classified_hardening_profile.md",
  "production_deployment.md",
  "STIG_VERIFICATION_CHECKLIST.md",
  "SECURITY.md",
  "MATURITY.md",
  "CHANGELOG_CONFIG.md",
  "CONTRIBUTING.md",
  "PACKAGING_NOTE.md",
  "COVER_LETTER_FINAL.md",
  "sample_ioc_seed.json",
  "sbom.cdx.json",
  "sbom.spdx.json",
  "bandit-report.json",
  "semgrep-report.json",
  "LICENSE"
)

$coreStage = Join-Path $out "darkspace_core_stage"
New-Item -ItemType Directory -Path $coreStage | Out-Null

foreach ($f in $coreFiles) {
  $src = Join-Path $root $f
  if (-not (Test-Path $src)) {
    Write-Warning "Missing core artifact: $f"
    continue
  }
  $dst = Join-Path $coreStage $f
  $dstDir = Split-Path -Parent $dst
  if (-not (Test-Path $dstDir)) {
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
  }
  Copy-Item -Path $src -Destination $dst -Force
}

$coreZip = Join-Path $out "darkspace_core_poc.zip"
Compress-Archive -Path (Join-Path $coreStage "*") -DestinationPath $coreZip -Force

$demoZip = Join-Path $out "darkspace_full_demo_repo.zip"
$exclude = @(".git", ".venv", "__pycache__", "submission_dist")
$all = Get-ChildItem -Path $root -Force | Where-Object { $exclude -notcontains $_.Name }
Compress-Archive -Path $all.FullName -DestinationPath $demoZip -Force

$shaFile = Join-Path $out "SHA256SUMS.txt"
$coreHash = Get-FileHash -Path $coreZip -Algorithm SHA256
$demoHash = Get-FileHash -Path $demoZip -Algorithm SHA256
$hashes = @($coreHash, $demoHash)
$hashes | ForEach-Object { "{0}  {1}" -f $_.Hash, (Split-Path $_.Path -Leaf) } | Set-Content -Path $shaFile -Encoding utf8

Write-Host "Built bundles:"
Write-Host " - $coreZip"
Write-Host " - $demoZip"
Write-Host "Checksums: $shaFile"
