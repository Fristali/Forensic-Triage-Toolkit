#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Phase 6 Verification Script for Forensic Triage Toolkit
    
.DESCRIPTION
    Tests all Phase 6 features including documentation, build system,
    CI/CD workflows, and package generation. This script verifies that
    the project is ready for production deployment.
    
.NOTES
    Run this script to verify Phase 6 implementation is complete and functional.
#>

param(
    [switch]$Verbose,
    [switch]$CleanupOnly,
    [switch]$SkipBuild
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   PHASE 6 VERIFICATION SCRIPT" -ForegroundColor Cyan
Write-Host "   Forensic Triage Toolkit" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

if ($CleanupOnly) {
    Write-Host "Cleaning up test artifacts..." -ForegroundColor Yellow
    $cleanupDirs = @("./build-output", "./tests/phase-tests/phase6-artifacts")
    foreach ($dir in $cleanupDirs) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
            Write-Host "✓ Removed $dir" -ForegroundColor Green
        }
    }
    Write-Host "Cleanup completed!" -ForegroundColor Green
    exit 0
}

try {
    # Verification tracking
    $script:VerificationResults = @{
        Documentation = @()
        BuildSystem = @()
        CICD = @()
        Packaging = @()
        TotalTests = 0
        PassedTests = 0
        FailedTests = 0
    }

    function Test-Component {
        param(
            [string]$Category,
            [string]$TestName,
            [scriptblock]$TestScript
        )
        
        $script:VerificationResults.TotalTests++
        
        try {
            Write-Host "   Testing: $TestName..." -ForegroundColor Cyan
            & $TestScript
            Write-Host "   ✓ $TestName passed" -ForegroundColor Green
            $script:VerificationResults[$Category] += @{
                Name = $TestName
                Status = "PASSED"
                Error = $null
            }
            $script:VerificationResults.PassedTests++
        }
        catch {
            Write-Host "   ✗ $TestName failed: $($_.Exception.Message)" -ForegroundColor Red
            $script:VerificationResults[$Category] += @{
                Name = $TestName
                Status = "FAILED"
                Error = $_.Exception.Message
            }
            $script:VerificationResults.FailedTests++
        }
    }

    # Test 1: Documentation Verification
    Write-Host "1. Verifying Documentation Structure..." -ForegroundColor Yellow
    
    Test-Component -Category "Documentation" -TestName "Architecture Documentation Exists" -TestScript {
        if (-not (Test-Path "./docs/architecture.md")) {
            throw "Architecture documentation not found"
        }
        $content = Get-Content "./docs/architecture.md" -Raw
        if ($content.Length -lt 1000) {
            throw "Architecture documentation appears incomplete"
        }
    }
    
    Test-Component -Category "Documentation" -TestName "Chain-of-Custody Specification Exists" -TestScript {
        if (-not (Test-Path "./docs/chain-of-custody.md")) {
            throw "Chain-of-custody specification not found"
        }
        $content = Get-Content "./docs/chain-of-custody.md" -Raw
        if ($content.Length -lt 1000) {
            throw "Chain-of-custody specification appears incomplete"
        }
    }
    
    Test-Component -Category "Documentation" -TestName "README Updated with Badges" -TestScript {
        $readmeContent = Get-Content "./README.md" -Raw
        $requiredBadges = @("CI/CD Pipeline", "PowerShell", "License", "Documentation", "Coverage", "Security")
        foreach ($badge in $requiredBadges) {
            if ($readmeContent -notmatch $badge) {
                throw "README missing required badge: $badge"
            }
        }
    }
    
    Test-Component -Category "Documentation" -TestName "README Phase 6 Completion" -TestScript {
        $readmeContent = Get-Content "./README.md" -Raw
        if ($readmeContent -notmatch "Phase 6.*complete") {
            throw "README does not indicate Phase 6 completion"
        }
    }

    # Test 2: Build System Verification
    Write-Host ""
    Write-Host "2. Verifying Build System..." -ForegroundColor Yellow
    
    Test-Component -Category "BuildSystem" -TestName "Build Script Exists" -TestScript {
        if (-not (Test-Path "./build.ps1")) {
            throw "Build script not found"
        }
    }
    
    Test-Component -Category "BuildSystem" -TestName "Build Script Help Documentation" -TestScript {
        $buildContent = Get-Content "./build.ps1" -Raw
        if ($buildContent -notmatch "\.SYNOPSIS" -or $buildContent -notmatch "\.DESCRIPTION") {
            throw "Build script missing proper help documentation"
        }
    }
    
    if (-not $SkipBuild) {
        Test-Component -Category "BuildSystem" -TestName "Build Script Module Structure Validation" -TestScript {
            & "./build.ps1" -Task Analyze -SkipTests 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Build script module validation failed"
            }
        }
        
        Test-Component -Category "BuildSystem" -TestName "Package Generation" -TestScript {
            & "./build.ps1" -Task Package -SkipAnalysis -SkipTests 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Package generation failed"
            }
            if (-not (Test-Path "./build-output/AcquisitionToolkit-v1.0.0.zip")) {
                throw "Package file not created"
            }
        }
    } else {
        Write-Host "   Skipping build tests (SkipBuild specified)" -ForegroundColor Yellow
    }

    # Test 3: CI/CD Configuration Verification
    Write-Host ""
    Write-Host "3. Verifying CI/CD Configuration..." -ForegroundColor Yellow
    
    Test-Component -Category "CICD" -TestName "GitHub Actions Workflow Exists" -TestScript {
        if (-not (Test-Path "./.github/workflows/ci.yml")) {
            throw "GitHub Actions CI/CD workflow not found"
        }
    }
    
    Test-Component -Category "CICD" -TestName "CI Workflow Structure" -TestScript {
        $ciContent = Get-Content "./.github/workflows/ci.yml" -Raw
        $requiredJobs = @("lint-and-analyze", "test", "build", "security-scan", "integration-test", "docs-check")
        foreach ($job in $requiredJobs) {
            if ($ciContent -notmatch $job) {
                throw "CI workflow missing required job: $job"
            }
        }
    }
    
    Test-Component -Category "CICD" -TestName "Multi-Platform Testing Configuration" -TestScript {
        $ciContent = Get-Content "./.github/workflows/ci.yml" -Raw
        $platforms = @("ubuntu-latest", "windows-latest", "macos-latest")
        foreach ($platform in $platforms) {
            if ($ciContent -notmatch $platform) {
                throw "CI workflow missing platform: $platform"
            }
        }
    }
    
    Test-Component -Category "CICD" -TestName "Security Scanning Configuration" -TestScript {
        $ciContent = Get-Content "./.github/workflows/ci.yml" -Raw
        if ($ciContent -notmatch "trivy-action" -or $ciContent -notmatch "security-scan") {
            throw "CI workflow missing security scanning configuration"
        }
    }

    # Test 4: Package Structure Verification
    Write-Host ""
    Write-Host "4. Verifying Package Structure..." -ForegroundColor Yellow
    
    if (Test-Path "./build-output/package") {
        Test-Component -Category "Packaging" -TestName "Package Contains Module Files" -TestScript {
            if (-not (Test-Path "./build-output/package/AcquisitionToolkit/AcquisitionToolkit.psm1")) {
                throw "Package missing main module file"
            }
            if (-not (Test-Path "./build-output/package/AcquisitionToolkit/AcquisitionToolkit.psd1")) {
                throw "Package missing module manifest"
            }
        }
        
        Test-Component -Category "Packaging" -TestName "Package Contains Documentation" -TestScript {
            if (-not (Test-Path "./build-output/package/docs")) {
                throw "Package missing documentation directory"
            }
            if (-not (Test-Path "./build-output/package/README.md")) {
                throw "Package missing README"
            }
        }
        
        Test-Component -Category "Packaging" -TestName "Package Contains Configuration Example" -TestScript {
            if (-not (Test-Path "./build-output/package/config.env.example")) {
                throw "Package missing configuration example"
            }
        }
        
        Test-Component -Category "Packaging" -TestName "ZIP Package Creation" -TestScript {
            if (-not (Test-Path "./build-output/AcquisitionToolkit-v1.0.0.zip")) {
                throw "ZIP package not created"
            }
            $zipSize = (Get-Item "./build-output/AcquisitionToolkit-v1.0.0.zip").Length
            if ($zipSize -lt 10KB) {
                throw "ZIP package appears too small"
            }
        }
    } else {
        Write-Host "   Package directory not found - skipping package structure tests" -ForegroundColor Yellow
    }

    # Test 5: Integration with Previous Phases
    Write-Host ""
    Write-Host "5. Verifying Integration with Previous Phases..." -ForegroundColor Yellow
    
    Test-Component -Category "BuildSystem" -TestName "Module Import Functionality" -TestScript {
        Import-Module "./src/AcquisitionToolkit.psm1" -Force
        $functions = Get-Command -Module AcquisitionToolkit
        if ($functions.Count -ne 14) {
            throw "Expected 14 exported functions, found $($functions.Count)"
        }
    }
    
    Test-Component -Category "Documentation" -TestName "Phase Integration Documentation" -TestScript {
        $readmeContent = Get-Content "./README.md" -Raw
        $phases = @("Phase 0", "Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5", "Phase 6")
        foreach ($phase in $phases) {
            if ($readmeContent -notmatch $phase) {
                throw "README missing documentation for: $phase"
            }
        }
    }

    # Test 6: Quality Assurance
    Write-Host ""
    Write-Host "6. Quality Assurance Checks..." -ForegroundColor Yellow
    
    Test-Component -Category "Documentation" -TestName "Documentation Completeness" -TestScript {
        $docFiles = @("./README.md", "./docs/architecture.md", "./docs/chain-of-custody.md", "./Phases.md")
        foreach ($file in $docFiles) {
            if (-not (Test-Path $file)) {
                throw "Required documentation file missing: $file"
            }
            $content = Get-Content $file -Raw
            if ($content -match "TODO|FIXME|XXX") {
                throw "Documentation file contains TODO markers: $file"
            }
        }
    }
    
    Test-Component -Category "BuildSystem" -TestName "Build System Error Handling" -TestScript {
        # Test invalid task by trying to bypass ValidateSet
        try {
            & "./build.ps1" -Task "InvalidTask" 2>&1 | Out-Null
            throw "Build script should have failed with invalid task"
        } catch {
            # Parameter validation error is expected and correct behavior
            if ($_.Exception.Message -match "ValidateSet") {
                # This is the expected behavior - parameter validation works
            } else {
                throw "Unexpected error: $($_.Exception.Message)"
            }
        }
    }

    # Generate final report
    Write-Host ""
    Write-Host "7. Generating Final Report..." -ForegroundColor Yellow
    
    $reportDir = "./tests/phase-tests/phase6-artifacts"
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    
    $report = @{
        TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalTests = $script:VerificationResults.TotalTests
        PassedTests = $script:VerificationResults.PassedTests
        FailedTests = $script:VerificationResults.FailedTests
        SuccessRate = [math]::Round(($script:VerificationResults.PassedTests / $script:VerificationResults.TotalTests) * 100, 2)
        Categories = @{
            Documentation = $script:VerificationResults.Documentation
            BuildSystem = $script:VerificationResults.BuildSystem
            CICD = $script:VerificationResults.CICD
            Packaging = $script:VerificationResults.Packaging
        }
    }
    
    $reportPath = Join-Path $reportDir "phase6-verification-report.json"
    $report | ConvertTo-Json -Depth 4 | Out-File -Path $reportPath -Encoding UTF8
    
    Write-Host "   ✓ Verification report saved: $reportPath" -ForegroundColor Green

    # Final summary
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "   ✅ PHASE 6 VERIFICATION COMPLETE" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Test Results Summary:" -ForegroundColor White
    Write-Host "  Total Tests: $($script:VerificationResults.TotalTests)" -ForegroundColor White
    Write-Host "  Passed: $($script:VerificationResults.PassedTests)" -ForegroundColor Green
    Write-Host "  Failed: $($script:VerificationResults.FailedTests)" -ForegroundColor Red
    Write-Host "  Success Rate: $($report.SuccessRate)%" -ForegroundColor White
    Write-Host ""
    
    # Category breakdown
    foreach ($category in @("Documentation", "BuildSystem", "CICD", "Packaging")) {
        $categoryTests = $script:VerificationResults[$category]
        $passed = ($categoryTests | Where-Object { $_.Status -eq "PASSED" }).Count
        $total = $categoryTests.Count
        Write-Host "✅ $category`: $passed/$total tests passed" -ForegroundColor Green
    }
    
    Write-Host ""
    
    if ($script:VerificationResults.FailedTests -eq 0) {
        Write-Host "🎯 Phase 6 implementation is COMPLETE and ready for production!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Key Phase 6 Achievements:" -ForegroundColor Yellow
        Write-Host "✅ Comprehensive documentation (Architecture + Chain-of-Custody)" -ForegroundColor Green
        Write-Host "✅ Automated build system with PSScriptAnalyzer + Pester" -ForegroundColor Green
        Write-Host "✅ Multi-platform CI/CD pipeline with GitHub Actions" -ForegroundColor Green
        Write-Host "✅ Security scanning and vulnerability assessment" -ForegroundColor Green
        Write-Host "✅ Automated package generation and distribution" -ForegroundColor Green
        Write-Host "✅ Documentation publishing to GitHub Pages" -ForegroundColor Green
        Write-Host ""
        Write-Host "The Forensic Triage Toolkit is now PRODUCTION-READY!" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Phase 6 verification completed with $($script:VerificationResults.FailedTests) failures" -ForegroundColor Yellow
        Write-Host "Please review the failed tests and resolve issues before production deployment." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Verification artifacts created in: $reportDir" -ForegroundColor Cyan
    Write-Host "Run with -CleanupOnly to remove test files" -ForegroundColor Cyan

}
catch {
    Write-Host ""
    Write-Host "❌ Phase 6 verification failed with error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
} 