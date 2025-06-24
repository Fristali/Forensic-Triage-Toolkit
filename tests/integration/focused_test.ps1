#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Focused test script for core functions without hanging operations
#>

#Requires -Modules Pester

param(
    [switch]$Verbose
)

Write-Host "=== FOCUSED FUNCTION TESTS ===" -ForegroundColor Cyan
Write-Host ""

# Configure Pester
$PesterConfiguration = [PesterConfiguration]::Default
$PesterConfiguration.Run.Path = $PSScriptRoot
$PesterConfiguration.Output.Verbosity = if ($Verbose) { 'Detailed' } else { 'Normal' }
$PesterConfiguration.TestResult.Enabled = $false
$PesterConfiguration.CodeCoverage.Enabled = $false

BeforeAll {
    # Import the module
    $ModulePath = Join-Path $PSScriptRoot ".." ".." "src" "AcquisitionToolkit.psm1"
    Import-Module $ModulePath -Force
    
    # Create test environment
    $script:TestEnvPath = Join-Path $TestDrive "test.env"
    $script:TestEnvContent = @"
AWS_ACCESS_KEY_ID=test_access_key
AWS_SECRET_ACCESS_KEY=test_secret_key
AWS_DEFAULT_REGION=us-west-2
S3_BUCKET=test-forensic-bucket
MEMORY_LIMIT_MB=2048
EVIDENCE_DIR=./tests/evidence
OFFLINE=true
"@
    Set-Content -Path $script:TestEnvPath -Value $script:TestEnvContent
    Import-EnvironmentConfig -EnvPath $script:TestEnvPath
}

AfterAll {
    Remove-Module AcquisitionToolkit -Force -ErrorAction SilentlyContinue
}

Describe "Core Module Functions" {
    
    It "Should import module with all functions" {
        $module = Get-Module AcquisitionToolkit
        $module | Should -Not -BeNullOrEmpty
        $module.ExportedFunctions.Count | Should -Be 14
    }
    
    Context "Configuration Functions" {
        
        It "Should load environment configuration correctly" {
            $bucketValue = Get-ConfigValue -Key "S3_BUCKET"
            $bucketValue | Should -Be "test-forensic-bucket"
            
            $memoryLimit = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger
            $memoryLimit | Should -Be 2048
            
            $offlineMode = Get-ConfigValue -Key "OFFLINE" -AsBoolean
            $offlineMode | Should -Be $true
        }
        
        It "Should handle missing keys with defaults" {
            $defaultValue = Get-ConfigValue -Key "MISSING_KEY" -DefaultValue "default"
            $defaultValue | Should -Be "default"
        }
    }
    
    Context "Hash Functions" {
        
        BeforeEach {
            $script:TestFile = Join-Path $TestDrive "test_hash.raw"
            "Test content for hashing verification" | Out-File -FilePath $script:TestFile -Encoding ASCII
        }
        
        It "Should calculate file hash correctly" {
            $result = Get-ArtifactHash -FilePath $script:TestFile
            
            $result.Summary.TotalFiles | Should -Be 1
            $result.Summary.SuccessfulHashes | Should -Be 1
            $result.Results[0].Success | Should -Be $true
            $result.Results[0].Hash | Should -Not -BeNullOrEmpty
            $result.Results[0].Algorithm | Should -Be 'SHA256'
        }
        
        It "Should handle multiple files" {
            $testFile2 = Join-Path $TestDrive "test_hash2.raw"
            "Different content" | Out-File -FilePath $testFile2 -Encoding ASCII
            
            $result = Get-ArtifactHash -FilePath @($script:TestFile, $testFile2)
            
            $result.Summary.TotalFiles | Should -Be 2
            $result.Summary.SuccessfulHashes | Should -Be 2
            
            # Hashes should be different
            $result.Results[0].Hash | Should -Not -Be $result.Results[1].Hash
        }
    }
    
    Context "Simulation Functions" {
        
        It "Should create simulated memory artifact" {
            $outputPath = Join-Path $TestDrive "sim_memory.raw"
            
            $result = New-SimulatedArtifact -Type "Memory" -OutputPath $outputPath -SizeMB 1
            
            $result.Success | Should -Be $true
            $result.Type | Should -Be "Memory"
            $result.Simulated | Should -Be $true
            Test-Path $outputPath | Should -Be $true
            
            $fileSize = (Get-Item $outputPath).Length
            $fileSize | Should -BeGreaterThan 0
        }
        
        It "Should create different artifact types" {
            $types = @("Memory", "Disk", "Registry", "EventLog", "NetworkCapture")
            
            foreach ($type in $types) {
                $outputPath = Join-Path $TestDrive "sim_$type.raw"
                $result = New-SimulatedArtifact -Type $type -OutputPath $outputPath -SizeMB 1
                
                $result.Success | Should -Be $true
                $result.Type | Should -Be $type
                Test-Path $outputPath | Should -Be $true
            }
        }
    }
    
    Context "Memory Acquisition with Simulation" {
        
        It "Should run memory acquisition in simulation mode" {
            $outputDir = Join-Path $TestDrive "memory_sim"
            
            $result = Invoke-MemoryAcquisition -OutputDir $outputDir -Simulation -MemoryLimitMB 1024
            
            $result.Success | Should -Be $true
            $result.Simulated | Should -Be $true
            $result.MemoryLimitMB | Should -Be 1024
            Test-Path $result.OutputFile | Should -Be $true
        }
    }
    
    Context "Disk Acquisition with Simulation" {
        
        It "Should run disk acquisition in simulation mode with specified volumes" {
            $outputDir = Join-Path $TestDrive "disk_sim"
            $testVolumes = @("TEST_VOL")
            
            $result = Invoke-DiskAcquisition -OutputDir $outputDir -Simulation -Volumes $testVolumes
            
            $result.Summary.TotalVolumes | Should -Be 1
            $result.Summary.SuccessfulVolumes | Should -Be 1
            $result.Results[0].Success | Should -Be $true
            $result.Results[0].Simulated | Should -Be $true
            Test-Path $result.Results[0].OutputFile | Should -Be $true
        }
    }
    
    Context "Manifest Generation" {
        
        BeforeEach {
            $script:ManifestDir = Join-Path $TestDrive "manifest_test"
            New-Item -Path $script:ManifestDir -ItemType Directory -Force | Out-Null
            
            # Create test artifacts
            "Test artifact 1" | Out-File -FilePath (Join-Path $script:ManifestDir "artifact1.raw") -Encoding ASCII
            "Test artifact 2" | Out-File -FilePath (Join-Path $script:ManifestDir "artifact2.raw") -Encoding ASCII
        }
        
        It "Should create manifest for artifacts" {
            $result = Write-Manifest -OutputDir $script:ManifestDir -CaseNumber "TEST-001" -InvestigatorName "Test User"
            
            $result.Success | Should -Be $true
            $result.TotalArtifacts | Should -Be 2
            $result.CaseNumber | Should -Be "TEST-001"
            Test-Path $result.ManifestPath | Should -Be $true
            
            $manifestContent = Get-Content $result.ManifestPath -Raw | ConvertFrom-Json
            $manifestContent.Case.CaseNumber | Should -Be "TEST-001"
            $manifestContent.Artifacts.Count | Should -Be 2
        }
    }
    
    Context "S3 Upload in Offline Mode" {
        
        It "Should handle S3 upload in offline mode" {
            $uploadDir = Join-Path $TestDrive "upload_test"
            New-Item -Path $uploadDir -ItemType Directory -Force | Out-Null
            
            "Test upload content" | Out-File -FilePath (Join-Path $uploadDir "upload_test.raw") -Encoding ASCII
            
            $result = Send-ToS3 -OutputDir $uploadDir -Offline
            
            $result.Success | Should -Be $true
            $result.TotalFiles | Should -Be 1
            $result.SuccessfulUploads | Should -Be 1
            $result.UploadResults[0].Skipped | Should -Be $true
            $result.UploadResults[0].Message | Should -Match "Offline mode"
        }
    }
    
    Context "Logging Functions" {
        
        It "Should set logging mode correctly" {
            $result = Set-LoggingMode -Mode Verbose
            
            $result.Mode | Should -Be "Verbose"
        }
        
        It "Should create log entries" {
            $logFile = Join-Path $TestDrive "test.log"
            Write-LogMessage -Message "Test log message" -Level Info -LogFile $logFile
            
            Test-Path $logFile | Should -Be $true
            $logContent = Get-Content $logFile -Raw
            $logContent | Should -Match "Test log message"
        }
    }
    
    Context "Digital Timestamps" {
        
        It "Should generate digital timestamp signature" {
            $testData = "Test data for timestamp"
            
            $timestamp = Get-TimestampSignature -Data $testData
            
            $timestamp.TimestampVersion | Should -Be "1.0"
            $timestamp.SignatureType | Should -Be "SHA256-Digest"
            $timestamp.Signature | Should -Not -BeNullOrEmpty
            $timestamp.Payload.Data | Should -Be $testData
        }
    }
    
    Context "Operation Summary" {
        
        It "Should generate operation summary" {
            $testResults = @(
                [PSCustomObject]@{ Success = $true; FileName = "test1.raw"; Duration = 1.5; Attempts = 1; Message = "Success" }
                [PSCustomObject]@{ Success = $true; FileName = "test2.raw"; Duration = 2.0; Attempts = 1; Message = "Success" }
                [PSCustomObject]@{ Success = $false; FileName = "test3.raw"; Duration = 0.5; Attempts = 2; Message = "Failed" }
            )
            
            $summary = Get-OperationSummary -OperationType "Acquisition" -OperationResults $testResults
            
            $summary.OperationType | Should -Be "Acquisition"
            $summary.Statistics.TotalOperations | Should -Be 3
            $summary.Statistics.SuccessfulOperations | Should -Be 2
            $summary.Statistics.FailedOperations | Should -Be 1
            $summary.Statistics.SuccessRate | Should -Be 66.67
        }
    }
}

# Run the tests
Write-Host "Running focused Pester tests..." -ForegroundColor Yellow
$testResult = Invoke-Pester -Configuration $PesterConfiguration

Write-Host ""
if ($testResult.FailedCount -eq 0) {
    Write-Host "=== ALL FOCUSED TESTS PASSED ===" -ForegroundColor Green
    Write-Host "Passed: $($testResult.PassedCount)" -ForegroundColor Green
    Write-Host "Skipped: $($testResult.SkippedCount)" -ForegroundColor Yellow
} else {
    Write-Host "=== SOME TESTS FAILED ===" -ForegroundColor Red
    Write-Host "Passed: $($testResult.PassedCount)" -ForegroundColor Green
    Write-Host "Failed: $($testResult.FailedCount)" -ForegroundColor Red
    Write-Host "Skipped: $($testResult.SkippedCount)" -ForegroundColor Yellow
}
Write-Host "" 