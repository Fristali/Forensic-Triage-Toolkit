#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Quick test script to verify basic module functionality
#>

Write-Host "=== QUICK MODULE FUNCTIONALITY TEST ===" -ForegroundColor Cyan
Write-Host ""

try {
    # Test 1: Module Import
    Write-Host "1. Testing module import..." -ForegroundColor Yellow
    Import-Module "./src/AcquisitionToolkit.psm1" -Force
    
    $module = Get-Module AcquisitionToolkit
    if ($module) {
        Write-Host "   ✓ Module imported successfully" -ForegroundColor Green
        Write-Host "   ✓ Exported functions: $($module.ExportedFunctions.Count)" -ForegroundColor Green
    } else {
        throw "Module import failed"
    }
    
    # Test 2: Environment Configuration
    Write-Host ""
    Write-Host "2. Testing environment configuration..." -ForegroundColor Yellow
    
    # Create test .env file
    $testEnv = @"
TEST_KEY=test_value
S3_BUCKET=test-bucket
MEMORY_LIMIT_MB=2048
OFFLINE=true
"@
    $testEnvPath = "./test_quick.env"
    $testEnv | Out-File -FilePath $testEnvPath -Encoding UTF8
    
    Import-EnvironmentConfig -EnvPath $testEnvPath
    
    $testValue = Get-ConfigValue -Key "TEST_KEY"
    $bucketValue = Get-ConfigValue -Key "S3_BUCKET"
    $memoryLimit = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger
    $offlineMode = Get-ConfigValue -Key "OFFLINE" -AsBoolean
    
    if ($testValue -eq "test_value" -and $bucketValue -eq "test-bucket" -and $memoryLimit -eq 2048 -and $offlineMode -eq $true) {
        Write-Host "   ✓ Configuration loading works correctly" -ForegroundColor Green
    } else {
        throw "Configuration values incorrect"
    }
    
    # Test 3: Logging
    Write-Host ""
    Write-Host "3. Testing logging functionality..." -ForegroundColor Yellow
    
    $logFile = "./tests/logs/quick_test.log"
    Write-LogMessage -Message "Test log entry" -Level Info -LogFile $logFile
    
    if (Test-Path $logFile) {
        $logContent = Get-Content $logFile -Raw
        if ($logContent -match "Test log entry") {
            Write-Host "   ✓ Logging works correctly" -ForegroundColor Green
        } else {
            throw "Log content incorrect"
        }
    } else {
        throw "Log file not created"
    }
    
    # Test 4: Hash Function (basic)
    Write-Host ""
    Write-Host "4. Testing hash calculation..." -ForegroundColor Yellow
    
    $testFile = "./test_artifact.raw"
    "Test content for hashing" | Out-File -FilePath $testFile -Encoding ASCII
    
    $hashResult = Get-ArtifactHash -FilePath $testFile
    
    if ($hashResult.Summary.SuccessfulHashes -eq 1 -and $hashResult.Results[0].Hash) {
        Write-Host "   ✓ Hash calculation works correctly" -ForegroundColor Green
    } else {
        throw "Hash calculation failed"
    }
    
    # Test 5: Simulation Mode
    Write-Host ""
    Write-Host "5. Testing simulation mode..." -ForegroundColor Yellow
    
    $simResult = New-SimulatedArtifact -Type "Memory" -OutputPath "./sim_test.raw" -SizeMB 1
    
    if ($simResult.Success -and (Test-Path "./sim_test.raw")) {
        Write-Host "   ✓ Simulation mode works correctly" -ForegroundColor Green
    } else {
        throw "Simulation mode failed"
    }
    
    Write-Host ""
    Write-Host "=== ALL QUICK TESTS PASSED ===" -ForegroundColor Green
    Write-Host ""
    
    # Cleanup
    Remove-Item $testEnvPath -Force -ErrorAction SilentlyContinue
    Remove-Item $logFile -Force -ErrorAction SilentlyContinue
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    Remove-Item "./sim_test.raw" -Force -ErrorAction SilentlyContinue
    Remove-Module AcquisitionToolkit -Force -ErrorAction SilentlyContinue
    
    exit 0
}
catch {
    Write-Host ""
    Write-Host "=== QUICK TEST FAILED ===" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    # Cleanup on error
    Remove-Item "./test_quick.env" -Force -ErrorAction SilentlyContinue
    Remove-Item "./tests/logs/quick_test.log" -Force -ErrorAction SilentlyContinue
    Remove-Item "./test_artifact.raw" -Force -ErrorAction SilentlyContinue
    Remove-Item "./sim_test.raw" -Force -ErrorAction SilentlyContinue
    Remove-Module AcquisitionToolkit -Force -ErrorAction SilentlyContinue
    
    exit 1
} 