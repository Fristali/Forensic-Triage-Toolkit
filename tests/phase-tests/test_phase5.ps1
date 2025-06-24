#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Phase 5 Verification Script for Forensic Triage Toolkit
    
.DESCRIPTION
    Tests all Phase 5 features including simulation mode, interactive options,
    and complete workflow automation. This script verifies that all new
    functions work correctly and produce expected outputs.
    
.NOTES
    Run this script to verify Phase 5 implementation is complete and functional.
#>

param(
    [switch]$Verbose,
    [switch]$CleanupOnly
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   PHASE 5 VERIFICATION SCRIPT" -ForegroundColor Cyan
Write-Host "   Forensic Triage Toolkit" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

if ($CleanupOnly) {
    Write-Host "Cleaning up test artifacts..." -ForegroundColor Yellow
    $testDirs = @("./tests/phase-tests/phase5-artifacts", "./evidence", "./logs")
    foreach ($dir in $testDirs) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
            Write-Host "✓ Removed $dir" -ForegroundColor Green
        }
    }
    Write-Host "Cleanup completed!" -ForegroundColor Green
    exit 0
}

try {
    # Import the module
    Write-Host "1. Loading AcquisitionToolkit module..." -ForegroundColor Yellow
    Import-Module "./src/AcquisitionToolkit.psm1" -Force
    
    # Verify all functions are exported
    $exportedFunctions = Get-Command -Module AcquisitionToolkit
    Write-Host "   ✓ Module loaded with $($exportedFunctions.Count) functions" -ForegroundColor Green
    
    # Check for Phase 5 functions specifically
    $phase5Functions = @("Start-InteractiveMode", "New-SimulatedArtifact", "Invoke-CompleteWorkflow")
    foreach ($func in $phase5Functions) {
        $found = $exportedFunctions | Where-Object { $_.Name -eq $func }
        if ($found) {
            Write-Host "   ✓ $func found" -ForegroundColor Green
        } else {
            throw "Phase 5 function $func not found!"
        }
    }
    
    # Setup test environment
    Write-Host ""
    Write-Host "2. Setting up test environment..." -ForegroundColor Yellow
    $testDir = "./tests/phase-tests/phase5-artifacts"
    if (Test-Path $testDir) {
        Remove-Item -Path $testDir -Recurse -Force
    }
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    Write-Host "   ✓ Test directory created: $testDir" -ForegroundColor Green
    
    # Test 1: New-SimulatedArtifact function
    Write-Host ""
    Write-Host "3. Testing New-SimulatedArtifact function..." -ForegroundColor Yellow
    
    # Test different artifact types
    $artifactTypes = @("Memory", "Disk", "Registry", "EventLog", "NetworkCapture")
    foreach ($type in $artifactTypes) {
        $outputPath = Join-Path $testDir "simulated_$($type.ToLower()).raw"
        $result = New-SimulatedArtifact -Type $type -OutputPath $outputPath -SizeMB 1
        
        if ($result.Success -and (Test-Path $outputPath)) {
            $size = [math]::Round((Get-Item $outputPath).Length / 1MB, 2)
            Write-Host "   ✓ $type artifact created: $size MB" -ForegroundColor Green
        } else {
            throw "Failed to create $type artifact"
        }
    }
    
    # Test with metadata
    Write-Host "   Testing artifact with metadata..." -ForegroundColor Cyan
    $metadataPath = Join-Path $testDir "simulated_with_metadata.raw"
    $metadataResult = New-SimulatedArtifact -Type "Memory" -OutputPath $metadataPath -SizeMB 2 -IncludeMetadata
    
    if ($metadataResult.Success -and (Test-Path "$metadataPath.metadata.json")) {
        $metadata = Get-Content "$metadataPath.metadata.json" | ConvertFrom-Json
        Write-Host "   ✓ Metadata file created with tool: $($metadata.Tool)" -ForegroundColor Green
    } else {
        throw "Failed to create artifact with metadata"
    }
    
    # Test 2: Simulated Memory Acquisition
    Write-Host ""
    Write-Host "4. Testing simulated memory acquisition..." -ForegroundColor Yellow
    $simMemResult = Invoke-MemoryAcquisition -OutputDir $testDir -Simulation -MemoryLimitMB 1024
    
    if ($simMemResult.Success -and $simMemResult.Simulated) {
        Write-Host "   ✓ Simulated memory acquisition successful" -ForegroundColor Green
        Write-Host "   ✓ Output file: $($simMemResult.OutputFile)" -ForegroundColor Green
        Write-Host "   ✓ Size: $($simMemResult.SizeMB) MB" -ForegroundColor Green
    } else {
        throw "Simulated memory acquisition failed"
    }
    
    # Test 3: Simulated Disk Acquisition
    Write-Host ""
    Write-Host "5. Testing simulated disk acquisition..." -ForegroundColor Yellow
    $simDiskResult = Invoke-DiskAcquisition -OutputDir $testDir -Simulation -Volumes @("C:", "D:")
    
    if ($simDiskResult.Summary.SuccessfulVolumes -eq 2) {
        Write-Host "   ✓ Simulated disk acquisition successful" -ForegroundColor Green
        Write-Host "   ✓ Volumes acquired: $($simDiskResult.Summary.SuccessfulVolumes)" -ForegroundColor Green
        
        foreach ($result in $simDiskResult.Results) {
            if ($result.Simulated) {
                Write-Host "   ✓ Volume $($result.Volume): $($result.SizeGB) GB" -ForegroundColor Green
            }
        }
    } else {
        throw "Simulated disk acquisition failed"
    }
    
    # Test 4: Hash calculation on simulated artifacts
    Write-Host ""
    Write-Host "6. Testing hash calculation on simulated artifacts..." -ForegroundColor Yellow
    $hashResult = Get-ArtifactHash -OutputDir $testDir -IncludePattern "*.raw"
    
    if ($hashResult.Summary.SuccessfulHashes -gt 0) {
        Write-Host "   ✓ Hash calculation successful: $($hashResult.Summary.SuccessfulHashes) hashes" -ForegroundColor Green
        
        # Show first few hashes
        $count = [Math]::Min(3, $hashResult.Results.Count)
        for ($i = 0; $i -lt $count; $i++) {
            $artifact = $hashResult.Results[$i]
            Write-Host "   ✓ $($artifact.FileName): $($artifact.Hash.Substring(0,16))..." -ForegroundColor Green
        }
    } else {
        throw "Hash calculation failed"
    }
    
    # Test 5: Manifest generation with simulated artifacts
    Write-Host ""
    Write-Host "7. Testing manifest generation with simulated artifacts..." -ForegroundColor Yellow
    $manifestResult = Write-Manifest -OutputDir $testDir -CaseNumber "PHASE5-TEST" -InvestigatorName "Phase 5 Verification"
    
    if ($manifestResult.Success) {
        Write-Host "   ✓ Manifest generated: $($manifestResult.ManifestPath)" -ForegroundColor Green
        Write-Host "   ✓ Total artifacts: $($manifestResult.TotalArtifacts)" -ForegroundColor Green
        Write-Host "   ✓ Total size: $($manifestResult.TotalSizeGB) GB" -ForegroundColor Green
        
        # Verify digital timestamp is included
        $manifest = Get-Content $manifestResult.ManifestPath | ConvertFrom-Json
        if ($manifest.Integrity.DigitalTimestamp) {
            Write-Host "   ✓ Digital timestamp included in manifest" -ForegroundColor Green
        }
    } else {
        throw "Manifest generation failed"
    }
    
    # Test 6: Function availability verification
    Write-Host ""
    Write-Host "8. Verifying Phase 5 function parameters..." -ForegroundColor Yellow
    
    # Check Invoke-MemoryAcquisition has new parameters
    $memFunc = Get-Command Invoke-MemoryAcquisition
    $hasSimulation = $memFunc.Parameters.ContainsKey("Simulation")
    $hasInteractive = $memFunc.Parameters.ContainsKey("Interactive")
    
    if ($hasSimulation -and $hasInteractive) {
        Write-Host "   ✓ Invoke-MemoryAcquisition has Simulation and Interactive parameters" -ForegroundColor Green
    } else {
        throw "Invoke-MemoryAcquisition missing Phase 5 parameters"
    }
    
    # Check Invoke-DiskAcquisition has new parameters
    $diskFunc = Get-Command Invoke-DiskAcquisition
    $hasSimulation = $diskFunc.Parameters.ContainsKey("Simulation")
    $hasInteractive = $diskFunc.Parameters.ContainsKey("Interactive")
    
    if ($hasSimulation -and $hasInteractive) {
        Write-Host "   ✓ Invoke-DiskAcquisition has Simulation and Interactive parameters" -ForegroundColor Green
    } else {
        throw "Invoke-DiskAcquisition missing Phase 5 parameters"
    }
    
    # Test 7: Operation summary with simulated operations
    Write-Host ""
    Write-Host "9. Testing operation summary with simulated operations..." -ForegroundColor Yellow
    
    $mockOperations = @(
        [PSCustomObject]@{ Success = $true; FileName = "simulated_memory.raw"; Duration = 1.2; Attempts = 1; Message = "Success" },
        [PSCustomObject]@{ Success = $true; FileName = "simulated_disk_c.raw"; Duration = 2.5; Attempts = 1; Message = "Success" },
        [PSCustomObject]@{ Success = $true; FileName = "simulated_disk_d.raw"; Duration = 1.8; Attempts = 1; Message = "Success" }
    )
    
    $summaryResult = Get-OperationSummary -OperationType "Simulation" -OperationResults $mockOperations -IncludeRetryDetails
    
    if ($summaryResult.Statistics.SuccessRate -eq 100) {
        Write-Host "   ✓ Operation summary: $($summaryResult.Status)" -ForegroundColor Green
        Write-Host "   ✓ Success rate: $($summaryResult.Statistics.SuccessRate)%" -ForegroundColor Green
        Write-Host "   ✓ Total operations: $($summaryResult.Statistics.TotalOperations)" -ForegroundColor Green
    } else {
        throw "Operation summary generation failed"
    }
    
    # Test 8: Enhanced logging with Phase 4 integration
    Write-Host ""
    Write-Host "10. Testing enhanced logging integration..." -ForegroundColor Yellow
    
    $loggingResult = Set-LoggingMode -Mode Verbose -LogToFile -LogDirectory $testDir
    if ($loggingResult.Mode -eq "Verbose" -and $loggingResult.LogToFile) {
        Write-Host "   ✓ Verbose logging enabled with file output" -ForegroundColor Green
        Write-Host "   ✓ Log directory: $($loggingResult.LogDirectory)" -ForegroundColor Green
    } else {
        throw "Enhanced logging setup failed"
    }
    
    # Test 9: Digital timestamp generation
    Write-Host ""
    Write-Host "11. Testing digital timestamp generation..." -ForegroundColor Yellow
    
    $evidencePackage = @{
        CaseNumber = "PHASE5-TEST"
        Artifacts = @("simulated_memory.raw", "simulated_disk_c.raw", "simulated_disk_d.raw")
        TotalSize = "15.2 MB"
    }
    
    $timestampResult = Get-TimestampSignature -Data $evidencePackage -IncludeSystemInfo
    if ($timestampResult.Signature -and $timestampResult.Signature.Length -eq 64) {
        Write-Host "   ✓ Digital timestamp generated: $($timestampResult.Signature.Substring(0,16))..." -ForegroundColor Green
        Write-Host "   ✓ Timestamp version: $($timestampResult.TimestampVersion)" -ForegroundColor Green
        Write-Host "   ✓ Created at: $($timestampResult.CreatedAt)" -ForegroundColor Green
    } else {
        throw "Digital timestamp generation failed"
    }
    
    # Test 10: Complete integration test
    Write-Host ""
    Write-Host "12. Running complete integration test..." -ForegroundColor Yellow
    
    $integrationDir = Join-Path $testDir "integration"
    New-Item -Path $integrationDir -ItemType Directory -Force | Out-Null
    
    # Run complete simulated workflow
    $workflow1 = Invoke-MemoryAcquisition -OutputDir $integrationDir -Simulation
    $workflow2 = Invoke-DiskAcquisition -OutputDir $integrationDir -Simulation -Volumes @("TEST")
    $workflow3 = Get-ArtifactHash -OutputDir $integrationDir -IncludePattern "*.raw"
    $workflow4 = Write-Manifest -OutputDir $integrationDir -CaseNumber "INTEGRATION-TEST" -InvestigatorName "Automated Test"
    
    $allSuccessful = $workflow1.Success -and 
                     ($workflow2.Summary.SuccessfulVolumes -gt 0) -and 
                     ($workflow3.Summary.SuccessfulHashes -gt 0) -and 
                     $workflow4.Success
    
    if ($allSuccessful) {
        Write-Host "   ✓ Complete integration workflow successful" -ForegroundColor Green
        Write-Host "   ✓ All components working together" -ForegroundColor Green
    } else {
        throw "Integration test failed"
    }
    
    # Final verification
    Write-Host ""
    Write-Host "13. Final verification..." -ForegroundColor Yellow
    
    $finalCommands = Get-Command -Module AcquisitionToolkit
    $expectedCount = 14  # Updated for Phase 5
    
    if ($finalCommands.Count -eq $expectedCount) {
        Write-Host "   ✓ All $expectedCount functions exported correctly" -ForegroundColor Green
    } else {
        throw "Function count mismatch: expected $expectedCount, got $($finalCommands.Count)"
    }
    
    # Summary
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host "   ✅ PHASE 5 VERIFICATION COMPLETE" -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ New-SimulatedArtifact function operational" -ForegroundColor Green
    Write-Host "✅ Simulation mode in acquisition functions" -ForegroundColor Green
    Write-Host "✅ Interactive parameters available" -ForegroundColor Green
    Write-Host "✅ Start-InteractiveMode function available" -ForegroundColor Green
    Write-Host "✅ Invoke-CompleteWorkflow function available" -ForegroundColor Green
    Write-Host "✅ Enhanced logging integration working" -ForegroundColor Green
    Write-Host "✅ Digital timestamps with simulated data" -ForegroundColor Green
    Write-Host "✅ Complete workflow automation ready" -ForegroundColor Green
    Write-Host "✅ All 14 functions exported successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "🎯 Phase 5 implementation is COMPLETE and ready for production!" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not $Verbose) {
        Write-Host "Test artifacts created in: $testDir" -ForegroundColor Yellow
        Write-Host "Run with -CleanupOnly to remove test files" -ForegroundColor Yellow
    }

} catch {
    Write-Host ""
    Write-Host "❌ PHASE 5 VERIFICATION FAILED" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    if ($_.ScriptStackTrace) {
        Write-Host "Stack trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }
    
    exit 1
} finally {
    if ($Verbose -and (Test-Path $testDir)) {
        Write-Host ""
        Write-Host "Cleaning up test artifacts..." -ForegroundColor Yellow
        Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Test artifacts cleaned up" -ForegroundColor Green
    }
} 