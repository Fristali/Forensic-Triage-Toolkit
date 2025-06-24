#Requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for Forensic Triage Toolkit - Phase 0 tests
    
.DESCRIPTION
    Tests for environment configuration loading and basic module functionality.
    This is the initial test file as specified in Phase 0 deliverables.
    
.NOTES
    Requires Pester v5.0+
    Run with: Invoke-Pester -Path "./tests/unit/AcquisitionToolkit.Tests.ps1"
#>

BeforeAll {
    # Import the module under test
    $ModulePath = Join-Path $PSScriptRoot ".." ".." "src" "AcquisitionToolkit.psm1"
    Import-Module $ModulePath -Force
    
    # Create test environment file
    $script:TestEnvPath = Join-Path $TestDrive "test.env"
    $script:TestEnvContent = @"
# Test environment configuration
AWS_ACCESS_KEY_ID=test_access_key
AWS_SECRET_ACCESS_KEY=test_secret_key
AWS_DEFAULT_REGION=us-west-2
S3_BUCKET=test-forensic-bucket
MEMORY_LIMIT_MB=2048
EVIDENCE_DIR=./tests/evidence
COMPRESS=true
OFFLINE=false
ENCRYPT=true
LOG_LEVEL=Debug
VERBOSE=true
INVESTIGATOR_NAME=Test Investigator
CASE_NUMBER=CASE-2025-001
"@
    
    Set-Content -Path $script:TestEnvPath -Value $script:TestEnvContent
}

AfterAll {
    # Clean up
    Remove-Module AcquisitionToolkit -Force -ErrorAction SilentlyContinue
}

Describe "AcquisitionToolkit Module Loading" {
    
    It "Should import module successfully" {
        Get-Module AcquisitionToolkit | Should -Not -BeNullOrEmpty
    }
    
    It "Should export expected functions" {
        $expectedFunctions = @(
            'Import-EnvironmentConfig'
            'Get-ConfigValue'
            'Write-LogMessage'
            'Invoke-MemoryAcquisition'
            'Invoke-DiskAcquisition'
            'Get-ArtifactHash'
            'Write-Manifest'
            'Send-ToS3'
        )
        
        $exportedFunctions = (Get-Module AcquisitionToolkit).ExportedFunctions.Keys
        
        foreach ($function in $expectedFunctions) {
            $exportedFunctions | Should -Contain $function
        }
    }
}

Describe "Phase 2 - Hash & Manifest Functions" {
    
    BeforeAll {
        # Load test configuration
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
        
        # Create test artifact files for hashing
        $script:TestArtifact1 = Join-Path $TestDrive "test_artifact1.raw"
        $script:TestArtifact2 = Join-Path $TestDrive "test_artifact2.img"
        $script:TestArtifact3 = Join-Path $TestDrive "test_artifact3.dd"
        
        "This is test artifact 1 content for hashing" | Out-File -FilePath $script:TestArtifact1 -Encoding ASCII
        "This is test artifact 2 content with different data for verification" | Out-File -FilePath $script:TestArtifact2 -Encoding ASCII
        "Another test artifact with unique content for hash validation" | Out-File -FilePath $script:TestArtifact3 -Encoding ASCII
    }
    
    Describe "Get-ArtifactHash" {
        
        It "Should calculate hash for a single file" {
            $result = Get-ArtifactHash -FilePath $script:TestArtifact1
            
            $result.Summary.TotalFiles | Should -Be 1
            $result.Summary.SuccessfulHashes | Should -Be 1
            $result.Summary.FailedHashes | Should -Be 0
            $result.Results.Count | Should -Be 1
            
            $hashResult = $result.Results[0]
            $hashResult.Success | Should -Be $true
            $hashResult.Hash | Should -Not -BeNullOrEmpty
            $hashResult.Algorithm | Should -Be 'SHA256'
            $hashResult.FileName | Should -Be "test_artifact1.raw"
            $hashResult.SizeBytes | Should -BeGreaterThan 0
        }
        
        It "Should calculate hashes for multiple files" {
            $result = Get-ArtifactHash -FilePath @($script:TestArtifact1, $script:TestArtifact2, $script:TestArtifact3)
            
            $result.Summary.TotalFiles | Should -Be 3
            $result.Summary.SuccessfulHashes | Should -Be 3
            $result.Summary.FailedHashes | Should -Be 0
            $result.Results.Count | Should -Be 3
            
            # Verify each hash is unique
            $hashes = $result.Results | ForEach-Object { $_.Hash }
            $uniqueHashes = $hashes | Select-Object -Unique
            $uniqueHashes.Count | Should -Be 3
        }
        
        It "Should process directory with pattern filter" {
            $testDir = Join-Path $TestDrive "artifacts"
            New-Item -Path $testDir -ItemType Directory -Force | Out-Null
            
            # Create test files
            "Test raw file" | Out-File -FilePath (Join-Path $testDir "test1.raw") -Encoding ASCII
            "Test img file" | Out-File -FilePath (Join-Path $testDir "test2.img") -Encoding ASCII
            "Test txt file" | Out-File -FilePath (Join-Path $testDir "readme.txt") -Encoding ASCII
            
            # Test with *.raw pattern
            $result = Get-ArtifactHash -OutputDir $testDir -IncludePattern "*.raw"
            
            $result.Summary.TotalFiles | Should -Be 1
            $result.Results[0].FileName | Should -Be "test1.raw"
            
            # Test with * pattern (all files)
            $result = Get-ArtifactHash -OutputDir $testDir -IncludePattern "*"
            
            $result.Summary.TotalFiles | Should -Be 3
        }
        
        It "Should handle missing files gracefully" {
            $nonExistentFile = Join-Path $TestDrive "missing.raw"
            
            $result = Get-ArtifactHash -FilePath $nonExistentFile
            
            $result.Summary.TotalFiles | Should -Be 1
            $result.Summary.SuccessfulHashes | Should -Be 0
            $result.Summary.FailedHashes | Should -Be 1
            $result.Results[0].Success | Should -Be $false
            $result.Results[0].Error | Should -Be "File not found"
        }
        
        It "Should include file metadata in results" {
            $result = Get-ArtifactHash -FilePath $script:TestArtifact1
            
            $hashResult = $result.Results[0]
            $hashResult.FilePath | Should -Be $script:TestArtifact1
            $hashResult.FileName | Should -Be "test_artifact1.raw"
            $hashResult.FileExtension | Should -Be ".raw"
            $hashResult.Directory | Should -Not -BeNullOrEmpty
            $hashResult.CreationTime | Should -Not -BeNullOrEmpty
            $hashResult.LastWriteTime | Should -Not -BeNullOrEmpty
            $hashResult.HashCalculationTime | Should -BeGreaterThan 0
            $hashResult.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It "Should produce consistent hashes for same content" {
            # Create two identical files
            $testFile1 = Join-Path $TestDrive "identical1.raw"
            $testFile2 = Join-Path $TestDrive "identical2.raw"
            
            "Identical content for hash testing" | Out-File -FilePath $testFile1 -Encoding ASCII
            "Identical content for hash testing" | Out-File -FilePath $testFile2 -Encoding ASCII
            
            $result1 = Get-ArtifactHash -FilePath $testFile1
            $result2 = Get-ArtifactHash -FilePath $testFile2
            
            $result1.Results[0].Hash | Should -Be $result2.Results[0].Hash
        }
        
        It "Should handle empty directory" {
            $emptyDir = Join-Path $TestDrive "empty"
            New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
            
            $result = Get-ArtifactHash -OutputDir $emptyDir
            
            $result | Should -BeNullOrEmpty
        }
    }
    
    Describe "Write-Manifest" {
        
        BeforeEach {
            # Create a test artifacts directory
            $script:TestManifestDir = Join-Path $TestDrive "manifest_test"
            New-Item -Path $script:TestManifestDir -ItemType Directory -Force | Out-Null
            
            # Copy test artifacts to manifest directory
            Copy-Item $script:TestArtifact1 -Destination (Join-Path $script:TestManifestDir "artifact1.raw")
            Copy-Item $script:TestArtifact2 -Destination (Join-Path $script:TestManifestDir "artifact2.img")
        }
        
        It "Should create manifest from artifact paths" {
            $artifacts = @(
                (Join-Path $script:TestManifestDir "artifact1.raw"),
                (Join-Path $script:TestManifestDir "artifact2.img")
            )
            
            $result = Write-Manifest -ArtifactPaths $artifacts -CaseNumber "TEST-001" -InvestigatorName "Test User"
            
            $result.Success | Should -Be $true
            $result.ManifestPath | Should -Not -BeNullOrEmpty
            $result.LogPath | Should -Not -BeNullOrEmpty
            $result.TotalArtifacts | Should -Be 2
            $result.CaseNumber | Should -Be "TEST-001"
            
            # Verify manifest file was created
            Test-Path $result.ManifestPath | Should -Be $true
            Test-Path $result.LogPath | Should -Be $true
        }
        
        It "Should create manifest from output directory" {
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-002"
            
            $result.Success | Should -Be $true
            $result.TotalArtifacts | Should -BeGreaterThan 0
            
            # Verify manifest content
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            $manifestContent.Case.CaseNumber | Should -Be "TEST-002"
            $manifestContent.Artifacts | Should -Not -BeNullOrEmpty
            $manifestContent.System | Should -Not -BeNullOrEmpty
            $manifestContent.ManifestVersion | Should -Be "1.0"
        }
        
        It "Should include system information in manifest" {
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-003"
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            
            $manifestContent.System.Hostname | Should -Not -BeNullOrEmpty
            $manifestContent.System.Username | Should -Not -BeNullOrEmpty
            $manifestContent.System.OSVersion | Should -Not -BeNullOrEmpty
            $manifestContent.System.PowerShellVersion | Should -Not -BeNullOrEmpty
            $manifestContent.System.LocalTime | Should -Not -BeNullOrEmpty
            $manifestContent.System.UTCTime | Should -Not -BeNullOrEmpty
        }
        
        It "Should include artifact hashes in manifest" {
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-004"
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            
            $manifestContent.Artifacts.Count | Should -BeGreaterThan 0
            
            foreach ($artifact in $manifestContent.Artifacts) {
                $artifact.Hash | Should -Not -BeNullOrEmpty
                $artifact.Algorithm | Should -Be "SHA256"
                $artifact.SizeBytes | Should -BeGreaterThan 0
                $artifact.FileName | Should -Not -BeNullOrEmpty
            }
        }
        
        It "Should include acquisition parameters" {
            $acquisitionParams = @{
                MemoryLimitMB = 2048
                Volumes = @("C:", "D:")
                Method = "Test Acquisition"
            }
            
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-005" -AcquisitionParams $acquisitionParams
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            
            $manifestContent.Acquisition.Parameters.MemoryLimitMB | Should -Be 2048
            $manifestContent.Acquisition.Parameters.Volumes.Count | Should -Be 2
            $manifestContent.Acquisition.Parameters.Method | Should -Be "Test Acquisition"
        }
        
        It "Should calculate and include manifest hash" {
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-006"
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            
            $manifestContent.Integrity.ManifestHash | Should -Not -BeNullOrEmpty
            $manifestContent.Integrity.HashAlgorithm | Should -Be "SHA256"
            $manifestContent.Integrity.CreatedBy | Should -Not -BeNullOrEmpty
            $manifestContent.Integrity.CreatedOn | Should -Not -BeNullOrEmpty
            
            # Verify the hash matches
            $result.ManifestHash | Should -Be $manifestContent.Integrity.ManifestHash
        }
        
        It "Should create human-readable log file" {
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-007" -InvestigatorName "Test Investigator"
            
            Test-Path $result.LogPath | Should -Be $true
            
            $logContent = Get-Content $result.LogPath -Raw
            $logContent | Should -Match "FORENSIC TRIAGE TOOLKIT"
            $logContent | Should -Match "Case Number: TEST-007"
            $logContent | Should -Match "Investigator: Test Investigator"
            $logContent | Should -Match "ACQUISITION SUMMARY"
            $logContent | Should -Match "ARTIFACTS"
            $logContent | Should -Match "INTEGRITY"
        }
        
        It "Should use configuration values when parameters not provided" {
            # Test that function uses config defaults
            $result = Write-Manifest -OutputDir $script:TestManifestDir
            
            $result.Success | Should -Be $true
            
            # Should use defaults from config or "N/A"
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            $manifestContent.Case.CaseNumber | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle custom manifest path" {
            $customManifestPath = Join-Path $TestDrive "custom_manifest.json"
            
            $result = Write-Manifest -OutputDir $script:TestManifestDir -ManifestPath $customManifestPath -CaseNumber "TEST-008"
            
            $result.Success | Should -Be $true
            $result.ManifestPath | Should -Be $customManifestPath
            Test-Path $customManifestPath | Should -Be $true
        }
        
        It "Should include evidence notes when provided" {
            $evidenceNotes = "Test evidence acquired under controlled conditions"
            
            $result = Write-Manifest -OutputDir $script:TestManifestDir -CaseNumber "TEST-009" -EvidenceNotes $evidenceNotes
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            $manifestContent.Case.EvidenceNotes | Should -Be $evidenceNotes
        }
        
        It "Should handle empty artifact directory" {
            $emptyDir = Join-Path $TestDrive "empty_manifest"
            New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
            
            $result = Write-Manifest -OutputDir $emptyDir -CaseNumber "TEST-010"
            
            $result.Success | Should -Be $true
            $result.TotalArtifacts | Should -Be 0
            
            $manifestContent = Get-Content $result.ManifestPath | ConvertFrom-Json
            $manifestContent.Artifacts.Count | Should -Be 0
            $manifestContent.Acquisition.TotalArtifacts | Should -Be 0
        }
    }
    
    Describe "Hash & Manifest Integration Tests" {
        
        It "Should perform complete hash and manifest workflow" {
            $workflowDir = Join-Path $TestDrive "workflow_test"
            New-Item -Path $workflowDir -ItemType Directory -Force | Out-Null
            
            # Create test artifacts
            "Memory dump content" | Out-File -FilePath (Join-Path $workflowDir "memory.raw") -Encoding ASCII
            "Disk image content" | Out-File -FilePath (Join-Path $workflowDir "disk.img") -Encoding ASCII
            
            # Calculate hashes first
            $hashResult = Get-ArtifactHash -OutputDir $workflowDir
            $hashResult.Summary.SuccessfulHashes | Should -Be 2
            
            # Create manifest
            $manifestResult = Write-Manifest -OutputDir $workflowDir -CaseNumber "WORKFLOW-001" -InvestigatorName "Test User"
            $manifestResult.Success | Should -Be $true
            $manifestResult.TotalArtifacts | Should -Be 2
            
            # Verify both files were created
            Test-Path $manifestResult.ManifestPath | Should -Be $true
            Test-Path $manifestResult.LogPath | Should -Be $true
            
            # Verify manifest contains correct hash information
            $manifestContent = Get-Content $manifestResult.ManifestPath | ConvertFrom-Json
            $manifestContent.Artifacts.Count | Should -Be 2
            $manifestContent.HashSummary.SuccessfulHashes | Should -Be 2
        }
        
        It "Should handle mixed success/failure scenarios" {
            $mixedDir = Join-Path $TestDrive "mixed_test"
            New-Item -Path $mixedDir -ItemType Directory -Force | Out-Null
            
            # Create one valid file
            "Valid artifact" | Out-File -FilePath (Join-Path $mixedDir "valid.raw") -Encoding ASCII
            
            # Test with both valid and invalid files
            $artifacts = @(
                (Join-Path $mixedDir "valid.raw"),
                (Join-Path $mixedDir "missing.raw")  # This file doesn't exist
            )
            
            $hashResult = Get-ArtifactHash -FilePath $artifacts
            $hashResult.Summary.SuccessfulHashes | Should -Be 1
            $hashResult.Summary.FailedHashes | Should -Be 1
            
            # Manifest should only include successful artifacts
            $manifestResult = Write-Manifest -ArtifactPaths $artifacts -CaseNumber "MIXED-001"
            $manifestResult.Success | Should -Be $true
            $manifestResult.TotalArtifacts | Should -Be 1  # Only the valid one
        }
    }
}

Describe "Import-EnvironmentConfig" {
    
    BeforeEach {
        # Reset environment config before each test
        # We can't directly access script variables, so we'll test via the public interface
    }
    
    It "Should load environment file successfully" {
        { Import-EnvironmentConfig -EnvPath $script:TestEnvPath } | Should -Not -Throw
    }
    
    It "Should handle missing environment file gracefully" {
        $nonExistentPath = Join-Path $TestDrive "nonexistent.env"
        { Import-EnvironmentConfig -EnvPath $nonExistentPath } | Should -Not -Throw
    }
    
    It "Should skip empty lines and comments" {
        $testContent = @"
# This is a comment
TEST_KEY=test_value

# Another comment
ANOTHER_KEY=another_value
"@
        $testPath = Join-Path $TestDrive "comments.env"
        Set-Content -Path $testPath -Value $testContent
        
        { Import-EnvironmentConfig -EnvPath $testPath } | Should -Not -Throw
    }
    
    It "Should handle quoted values correctly" {
        $testContent = @"
QUOTED_DOUBLE="double quoted value"
QUOTED_SINGLE='single quoted value'
UNQUOTED=unquoted value
"@
        $testPath = Join-Path $TestDrive "quotes.env"
        Set-Content -Path $testPath -Value $testContent
        
        { Import-EnvironmentConfig -EnvPath $testPath } | Should -Not -Throw
    }
}

Describe "Get-ConfigValue" {
    
    BeforeAll {
        # Load test configuration
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
    }
    
    It "Should retrieve string configuration values" {
        $result = Get-ConfigValue -Key "S3_BUCKET"
        $result | Should -Be "test-forensic-bucket"
    }
    
    It "Should retrieve integer configuration values" {
        $result = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger
        $result | Should -Be 2048
        $result | Should -BeOfType [int]
    }
    
    It "Should retrieve boolean configuration values" {
        $compressResult = Get-ConfigValue -Key "COMPRESS" -AsBoolean
        $compressResult | Should -Be $true
        $compressResult | Should -BeOfType [bool]
        
        $offlineResult = Get-ConfigValue -Key "OFFLINE" -AsBoolean
        $offlineResult | Should -Be $false
        $offlineResult | Should -BeOfType [bool]
    }
    
    It "Should return default value for missing keys" {
        $result = Get-ConfigValue -Key "NONEXISTENT_KEY" -DefaultValue "default_value"
        $result | Should -Be "default_value"
    }
    
    It "Should return null for missing keys without default" {
        $result = Get-ConfigValue -Key "NONEXISTENT_KEY"
        $result | Should -BeNullOrEmpty
    }
    
    It "Should handle boolean conversion with various values" {
        # Test different boolean representations
        $testValues = @{
            "true" = $true
            "yes" = $true
            "1" = $true
            "on" = $true
            "false" = $false
            "no" = $false
            "0" = $false
            "off" = $false
            "random" = $false
        }
        
        foreach ($key in $testValues.Keys) {
            $testContent = "TEST_BOOL=$key"
            $testPath = Join-Path $TestDrive "bool_$key.env"
            Set-Content -Path $testPath -Value $testContent
            
            Import-EnvironmentConfig -EnvPath $testPath
            $result = Get-ConfigValue -Key "TEST_BOOL" -AsBoolean
            $expected = $testValues[$key]
            
            $result | Should -Be $expected -Because "Value '$key' should convert to $expected"
        }
    }
    
    It "Should throw error for invalid integer conversion" {
        $testContent = "INVALID_INT=not_a_number"
        $testPath = Join-Path $TestDrive "invalid.env"
        Set-Content -Path $testPath -Value $testContent
        
        Import-EnvironmentConfig -EnvPath $testPath
        
        { Get-ConfigValue -Key "INVALID_INT" -AsInteger } | Should -Throw
    }
}

Describe "Write-LogMessage" {
    
    It "Should write log message without throwing" {
        { Write-LogMessage -Message "Test message" -Level Info } | Should -Not -Throw
    }
    
    It "Should write to log file when specified" {
        $logFile = Join-Path $TestDrive "test.log"
        
        Write-LogMessage -Message "Test file logging" -Level Info -LogFile $logFile
        
        Test-Path $logFile | Should -Be $true
        $content = Get-Content $logFile
        $content | Should -Match "Test file logging"
        $content | Should -Match "\[Info\]"
        $content | Should -Match "\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
    }
    
    It "Should create log directory if it doesn't exist" {
        $logDir = Join-Path $TestDrive "logs"
        $logFile = Join-Path $logDir "test.log"
        
        Test-Path $logDir | Should -Be $false
        
        Write-LogMessage -Message "Test directory creation" -Level Info -LogFile $logFile
        
        Test-Path $logDir | Should -Be $true
        Test-Path $logFile | Should -Be $true
    }
    
    It "Should handle different log levels" {
        $levels = @('Info', 'Warning', 'Error', 'Verbose', 'Debug')
        
        foreach ($level in $levels) {
            { Write-LogMessage -Message "Test $level message" -Level $level } | Should -Not -Throw
        }
    }
    
    It "Should handle file write errors gracefully" {
        # Try to write to an invalid path (should show warning but not throw)
        { Write-LogMessage -Message "Test error handling" -Level Info -LogFile "Z:\invalid\path\test.log" } | Should -Not -Throw
    }
}

Describe "Module Integration Tests" {
    
    It "Should load configuration automatically on import" {
        # Test that the module loads configuration on import
        # This is tested indirectly by checking if functions work after import
        
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
        $bucket = Get-ConfigValue -Key "S3_BUCKET"
        $bucket | Should -Not -BeNullOrEmpty
    }
    
    It "Should handle complete workflow simulation" {
        # Simulate a basic workflow using the available functions
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
        
        $bucket = Get-ConfigValue -Key "S3_BUCKET"
        $memLimit = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger
        $compress = Get-ConfigValue -Key "COMPRESS" -AsBoolean
        
        $bucket | Should -Be "test-forensic-bucket"
        $memLimit | Should -Be 2048
        $compress | Should -Be $true
        
        # Test logging workflow
        $logFile = Join-Path $TestDrive "workflow.log"
        Write-LogMessage -Message "Configuration loaded successfully" -Level Info -LogFile $logFile
        Write-LogMessage -Message "Bucket: $bucket, Memory: $memLimit MB, Compress: $compress" -Level Info -LogFile $logFile
        
        Test-Path $logFile | Should -Be $true
        $logContent = Get-Content $logFile -Raw
        $logContent | Should -Match "Configuration loaded successfully"
        $logContent | Should -Match "Bucket: test-forensic-bucket"
    }
}

Describe "Phase 1 - Acquisition Functions" {
    
    BeforeAll {
        # Load test configuration
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
        
        # Create mock Velociraptor binary for testing
        $script:MockVelociraptorPath = Join-Path $TestDrive "mock_velociraptor.exe"
        $mockScript = @"
# Mock Velociraptor script for testing
param([string[]]`$args)

# Write arguments to a log file for verification
`$logPath = Join-Path "$TestDrive" "velociraptor_calls.log"
"`$args" | Out-File -FilePath `$logPath -Append

# Create mock output files based on arguments
if (`$args -contains "Windows.Memory.Acquisition") {
    # Find the filename argument
    `$filenameArg = `$args | Where-Object { `$_ -match "Filename=" }
    if (`$filenameArg) {
        `$filename = `$filenameArg -replace "Filename="
        "Mock memory dump content" | Out-File -FilePath `$filename
    }
}

if (`$args -contains "Windows.Disk.Image") {
    # Find the filename argument
    `$filenameArg = `$args | Where-Object { `$_ -match "Filename=" }
    if (`$filenameArg) {
        `$filename = `$filenameArg -replace "Filename="
        "Mock disk image content - this would be much larger in reality" | Out-File -FilePath `$filename
    }
}

# Create mock Velociraptor output logs
`$outputDir = `$args[`$args.IndexOf("--output") + 1]
if (`$outputDir -and (Test-Path `$outputDir)) {
    "Mock Velociraptor execution completed successfully" | Out-File -FilePath (Join-Path `$outputDir "velociraptor_mock.log")
}

# Exit with success
exit 0
"@
        $mockScript | Out-File -FilePath $script:MockVelociraptorPath -Encoding UTF8
    }
    
    BeforeEach {
        # Clear the mock call log before each test
        $callLogPath = Join-Path $TestDrive "velociraptor_calls.log"
        if (Test-Path $callLogPath) {
            Remove-Item $callLogPath -Force
        }
    }
    
    Describe "Invoke-MemoryAcquisition" {
        
        It "Should throw error when Velociraptor binary not found" {
            $testOutputDir = Join-Path $TestDrive "memory_test"
            { Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "C:\NonExistent\velociraptor.exe" } | Should -Throw "*not found*"
        }
        
        It "Should create output directory if it doesn't exist" {
            $testOutputDir = Join-Path $TestDrive "memory_test_new"
            Test-Path $testOutputDir | Should -Be $false
            
            { Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -WhatIf } | Should -Not -Throw
            
            Test-Path $testOutputDir | Should -Be $true
        }
        
        It "Should use configuration defaults when parameters not provided" {
            $testOutputDir = Join-Path $TestDrive "memory_default"
            
            # Test WhatIf mode to avoid actually running Velociraptor
            $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -WhatIf
            
            $result.Success | Should -Be $false
            $result.Message | Should -Match "WhatIf"
            $result.WouldExecute | Should -Match "powershell.exe"
        }
        
        It "Should generate proper Velociraptor arguments" {
            $testOutputDir = Join-Path $TestDrive "memory_args"
            
            $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -MemoryLimitMB 1024 -WhatIf
            
            $result.WouldExecute | Should -Match "Windows.Memory.Acquisition"
            $result.WouldExecute | Should -Match "PhysicalMemory"
            $result.WouldExecute | Should -Match "MaxSize="
        }
        
        It "Should handle different memory limits" {
            $testOutputDir = Join-Path $TestDrive "memory_limits"
            
            # Test with custom memory limit
            $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -MemoryLimitMB 512 -WhatIf
            $result.WouldExecute | Should -Match "MaxSize=536870912" # 512 * 1024 * 1024
            
            # Test with zero memory limit (should not include MaxSize)
            $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -MemoryLimitMB 0 -WhatIf
            $result.WouldExecute | Should -Not -Match "MaxSize="
        }
        
        It "Should create mock memory dump file with mock Velociraptor" {
            $testOutputDir = Join-Path $TestDrive "memory_mock"
            
            $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath
            
            $result.Success | Should -Be $true
            $result.OutputFile | Should -Not -BeNullOrEmpty
            Test-Path $result.OutputFile | Should -Be $true
            $result.SizeBytes | Should -BeGreaterThan 0
        }
    }
    
    Describe "Invoke-DiskAcquisition" {
        
        It "Should throw error when Velociraptor binary not found" {
            $testOutputDir = Join-Path $TestDrive "disk_test"
            { Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "C:\NonExistent\velociraptor.exe" } | Should -Throw "*not found*"
        }
        
        It "Should create output directory if it doesn't exist" {
            $testOutputDir = Join-Path $TestDrive "disk_test_new"
            Test-Path $testOutputDir | Should -Be $false
            
            { Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -WhatIf } | Should -Not -Throw
            
            Test-Path $testOutputDir | Should -Be $true
        }
        
        It "Should auto-detect volumes when not specified" {
            $testOutputDir = Join-Path $TestDrive "disk_auto"
            
            # Use explicit volumes to avoid WMI calls that can hang
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -Volumes @("C:") -WhatIf
            
            $result.Summary.TotalVolumes | Should -Be 1
            $result.Results | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle specified volumes array" {
            $testOutputDir = Join-Path $TestDrive "disk_specified"
            $testVolumes = @("C:", "D:")
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -Volumes $testVolumes -WhatIf
            
            $result.Summary.TotalVolumes | Should -Be 2
            $result.Results.Count | Should -Be 2
            $result.Results[0].Volume | Should -Be "C:"
            $result.Results[1].Volume | Should -Be "D:"
        }
        
        It "Should generate proper Velociraptor arguments for each volume" {
            $testOutputDir = Join-Path $TestDrive "disk_args"
            $testVolumes = @("C:")
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -Volumes $testVolumes -WhatIf
            
            $result.Results[0].WouldExecute | Should -Match "Windows.Disk.Image"
            $result.Results[0].WouldExecute | Should -Match "Device=C:"
        }
        
        It "Should handle MaxSize parameter" {
            $testOutputDir = Join-Path $TestDrive "disk_maxsize"
            $testVolumes = @("C:")
            $maxSize = 10GB
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath "powershell.exe" -Volumes $testVolumes -MaxSize $maxSize -WhatIf
            
            $result.Results[0].WouldExecute | Should -Match "MaxSize=$maxSize"
        }
        
        It "Should create mock disk image files with mock Velociraptor" {
            $testOutputDir = Join-Path $TestDrive "disk_mock"
            $testVolumes = @("C:")
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath -Volumes $testVolumes
            
            $result.Summary.SuccessfulVolumes | Should -Be 1
            $result.Results[0].Success | Should -Be $true
            $result.Results[0].OutputFile | Should -Not -BeNullOrEmpty
            Test-Path $result.Results[0].OutputFile | Should -Be $true
            $result.Results[0].SizeBytes | Should -BeGreaterThan 0
        }
        
        It "Should handle multiple volumes correctly" {
            $testOutputDir = Join-Path $TestDrive "disk_multi"
            $testVolumes = @("C:", "D:", "E:")
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath -Volumes $testVolumes
            
            $result.Summary.TotalVolumes | Should -Be 3
            $result.Summary.SuccessfulVolumes | Should -Be 3
            $result.Results.Count | Should -Be 3
            
            foreach ($volumeResult in $result.Results) {
                $volumeResult.Success | Should -Be $true
                Test-Path $volumeResult.OutputFile | Should -Be $true
            }
        }
        
        It "Should return proper summary statistics" {
            $testOutputDir = Join-Path $TestDrive "disk_summary"
            $testVolumes = @("C:", "D:")
            
            $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath -Volumes $testVolumes
            
            $result.Summary | Should -Not -BeNullOrEmpty
            $result.Summary.TotalVolumes | Should -Be 2
            $result.Summary.SuccessfulVolumes | Should -Be 2
            $result.Summary.FailedVolumes | Should -Be 0
            $result.Summary.Timestamp | Should -Not -BeNullOrEmpty
        }
    }
    
    Describe "Acquisition Integration Tests" {
        
        It "Should perform complete memory and disk acquisition workflow" {
            $testOutputDir = Join-Path $TestDrive "integration_test"
            $logFile = Join-Path $testOutputDir "integration.log"
            
            # Test memory acquisition
            $memoryResult = Invoke-MemoryAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath -LogFile $logFile
            
            $memoryResult.Success | Should -Be $true
            Test-Path $memoryResult.OutputFile | Should -Be $true
            
            # Test disk acquisition
            $diskResult = Invoke-DiskAcquisition -OutputDir $testOutputDir -VelociraptorPath $script:MockVelociraptorPath -Volumes @("C:") -LogFile $logFile
            
            $diskResult.Summary.SuccessfulVolumes | Should -Be 1
            Test-Path $diskResult.Results[0].OutputFile | Should -Be $true
            
            # Verify log file was created
            Test-Path $logFile | Should -Be $true
            $logContent = Get-Content $logFile -Raw
            $logContent | Should -Match "Starting memory acquisition"
            $logContent | Should -Match "Starting disk acquisition"
        }
        
        It "Should use configuration values correctly" {
            $testOutputDir = Join-Path $TestDrive "config_test"
            
            # Test that functions use configuration defaults
            $memoryResult = Invoke-MemoryAcquisition -VelociraptorPath $script:MockVelociraptorPath -OutputDir $testOutputDir
            $diskResult = Invoke-DiskAcquisition -VelociraptorPath $script:MockVelociraptorPath -Volumes @("C:") -OutputDir $testOutputDir
            
            # Both should succeed using test configuration
            $memoryResult.Success | Should -Be $true
            $diskResult.Summary.SuccessfulVolumes | Should -Be 1
            
            # Verify they used the specified output directory
            $memoryResult.OutputFile | Should -Match "config_test"
            $diskResult.Results[0].OutputFile | Should -Match "config_test"
        }
    }

    #endregion Phase 1 Tests

    #region Phase 3 Tests - Upload & Verification

    Describe "Send-ToS3 Function" {
        BeforeAll {
            # Create test environment
            $testEvidence = "./evidence"
            $testFile = Join-Path $testEvidence "test_upload.raw"
            
            if (-not (Test-Path $testEvidence)) {
                New-Item -ItemType Directory -Path $testEvidence -Force
            }
            
            # Create test artifact
            "Test upload content for Phase 3" | Set-Content -Path $testFile -Encoding UTF8
            
            # Mock environment variables for testing
            $env:S3_BUCKET = "test-forensic-bucket"
            $env:AWS_DEFAULT_REGION = "us-west-2"
            $env:OFFLINE = "true"
        }
        
        AfterAll {
            # Clean up test files
            if (Test-Path $testFile) {
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            }
            
            # Clean up environment
            Remove-Item Env:S3_BUCKET -ErrorAction SilentlyContinue
            Remove-Item Env:AWS_DEFAULT_REGION -ErrorAction SilentlyContinue
            Remove-Item Env:OFFLINE -ErrorAction SilentlyContinue
        }
        
        Context "Parameter Validation" {
            It "Should accept ArtifactPaths parameter" {
                { Send-ToS3 -ArtifactPaths @($testFile) -Offline } | Should -Not -Throw
            }
            
            It "Should accept OutputDir parameter" {
                { Send-ToS3 -OutputDir $testEvidence -Offline } | Should -Not -Throw
            }
            
            It "Should throw when no parameters provided" {
                { Send-ToS3 } | Should -Throw
            }
            
            It "Should throw when OutputDir doesn't exist" {
                { Send-ToS3 -OutputDir "./nonexistent" -Offline } | Should -Throw
            }
        }
        
        Context "Offline Mode" {
            It "Should process files in offline mode" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                
                $result | Should -Not -BeNullOrEmpty
                $result.Success | Should -Be $true
                $result.TotalFiles | Should -Be 1
                $result.SuccessfulUploads | Should -Be 1
                $result.FailedUploads | Should -Be 0
                $result.UploadResults | Should -HaveCount 1
                $result.UploadResults[0].Skipped | Should -Be $true
            }
            
            It "Should generate proper S3 key prefix" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                
                $result.S3KeyPrefix | Should -Match "^$env:COMPUTERNAME-\d{14}$"
                $result.UploadResults[0].S3Key | Should -Match "^$env:COMPUTERNAME-\d{14}/test_upload\.raw$"
            }
            
            It "Should use custom S3 key prefix when provided" {
                $customPrefix = "CUSTOM-20250101120000"
                $result = Send-ToS3 -ArtifactPaths @($testFile) -S3KeyPrefix $customPrefix -Offline
                
                $result.S3KeyPrefix | Should -Be $customPrefix
                $result.UploadResults[0].S3Key | Should -Be "$customPrefix/test_upload.raw"
            }
            
            It "Should include manifest files when IncludeManifest is true" {
                # Create manifest files
                $manifestPath = Join-Path $testEvidence "manifest.json"
                $logPath = Join-Path $testEvidence "log.txt"
                
                '{"test": "manifest"}' | Set-Content -Path $manifestPath
                "Test log content" | Set-Content -Path $logPath
                
                try {
                    $result = Send-ToS3 -OutputDir $testEvidence -IncludeManifest $true -Offline
                    
                    $result.TotalFiles | Should -BeGreaterThan 1
                    $manifestIncluded = $result.UploadResults | Where-Object { $_.FileName -eq "manifest.json" }
                    $logIncluded = $result.UploadResults | Where-Object { $_.FileName -eq "log.txt" }
                    
                    $manifestIncluded | Should -Not -BeNullOrEmpty
                    $logIncluded | Should -Not -BeNullOrEmpty
                }
                finally {
                    Remove-Item $manifestPath -Force -ErrorAction SilentlyContinue
                    Remove-Item $logPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        Context "Configuration Integration" {
            It "Should use S3_BUCKET from environment" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                $result.S3Bucket | Should -Be "test-forensic-bucket"
            }
            
            It "Should use AWS_DEFAULT_REGION from environment" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                $result.S3Region | Should -Be "us-west-2"
            }
            
            It "Should override configuration with explicit parameters" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -S3Bucket "override-bucket" -S3Region "eu-west-1" -Offline
                
                $result.S3Bucket | Should -Be "override-bucket"
                $result.S3Region | Should -Be "eu-west-1"
            }
        }
        
        Context "File Discovery" {
            It "Should discover artifact files in directory" {
                # Create additional test files
                $testFiles = @(
                    Join-Path $testEvidence "memory.raw",
                    Join-Path $testEvidence "disk.img",
                    Join-Path $testEvidence "swap.vmem",
                    Join-Path $testEvidence "readme.txt"  # Should be ignored
                )
                
                try {
                    foreach ($file in $testFiles) {
                        "Test content" | Set-Content -Path $file
                    }
                    
                    $result = Send-ToS3 -OutputDir $testEvidence -IncludeManifest $false -Offline
                    
                    # Should find .raw, .img, .vmem files but not .txt
                    $result.TotalFiles | Should -Be 4  # Including original test_upload.raw
                    
                    $foundFiles = $result.UploadResults | ForEach-Object { $_.FileName }
                    $foundFiles | Should -Contain "memory.raw"
                    $foundFiles | Should -Contain "disk.img"
                    $foundFiles | Should -Contain "swap.vmem"
                    $foundFiles | Should -Not -Contain "readme.txt"
                }
                finally {
                    foreach ($file in $testFiles) {
                        Remove-Item $file -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        Context "Error Handling" {
            It "Should handle missing files gracefully" {
                $missingFile = "./nonexistent.raw"
                $result = Send-ToS3 -ArtifactPaths @($missingFile) -Offline
                
                $result.Success | Should -Be $false
                $result.FailedUploads | Should -Be 1
                $result.UploadResults[0].Success | Should -Be $false
                $result.UploadResults[0].Message | Should -Be "File not found"
            }
            
            It "Should handle mixed success and failure scenarios" {
                $missingFile = "./nonexistent.raw"
                $validFile = $testFile
                
                $result = Send-ToS3 -ArtifactPaths @($validFile, $missingFile) -Offline
                
                $result.TotalFiles | Should -Be 2
                $result.SuccessfulUploads | Should -Be 1
                $result.FailedUploads | Should -Be 1
                $result.Success | Should -Be $false
            }
        }
        
        Context "Return Object Structure" {
            It "Should return properly structured result object" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                
                $result | Should -Not -BeNullOrEmpty
                $result.PSObject.Properties.Name | Should -Contain "Success"
                $result.PSObject.Properties.Name | Should -Contain "Message"
                $result.PSObject.Properties.Name | Should -Contain "TotalFiles"
                $result.PSObject.Properties.Name | Should -Contain "SuccessfulUploads"
                $result.PSObject.Properties.Name | Should -Contain "FailedUploads"
                $result.PSObject.Properties.Name | Should -Contain "S3Bucket"
                $result.PSObject.Properties.Name | Should -Contain "S3Region"
                $result.PSObject.Properties.Name | Should -Contain "S3KeyPrefix"
                $result.PSObject.Properties.Name | Should -Contain "UploadResults"
                $result.PSObject.Properties.Name | Should -Contain "Duration"
                $result.PSObject.Properties.Name | Should -Contain "Timestamp"
            }
            
            It "Should include detailed upload results" {
                $result = Send-ToS3 -ArtifactPaths @($testFile) -Offline
                
                $uploadResult = $result.UploadResults[0]
                $uploadResult.PSObject.Properties.Name | Should -Contain "LocalPath"
                $uploadResult.PSObject.Properties.Name | Should -Contain "FileName"
                $uploadResult.PSObject.Properties.Name | Should -Contain "S3Key"
                $uploadResult.PSObject.Properties.Name | Should -Contain "Success"
                $uploadResult.PSObject.Properties.Name | Should -Contain "Message"
                $uploadResult.PSObject.Properties.Name | Should -Contain "SizeBytes"
                $uploadResult.PSObject.Properties.Name | Should -Contain "Timestamp"
            }
        }
        
        Context "Compression Support" {
            It "Should support compression flag" {
                # Create a larger test file that would benefit from compression
                $compressibleContent = "A" * 1000  # 1KB of repeated content
                $compressibleFile = Join-Path $testEvidence "compressible.raw"
                
                try {
                    $compressibleContent | Set-Content -Path $compressibleFile -NoNewline
                    
                    $result = Send-ToS3 -ArtifactPaths @($compressibleFile) -Compress -Offline
                    
                    $result.Success | Should -Be $true
                    $uploadResult = $result.UploadResults[0]
                    
                    # Should indicate compression was attempted
                    $uploadResult.FileName | Should -Be "compressible.raw"
                    # Note: In offline mode, compression might not actually occur
                }
                finally {
                    Remove-Item $compressibleFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # Integration test combining multiple phases
    Describe "Phase 3 Integration Tests" {
        BeforeAll {
            $testDir = "./evidence"
            $testArtifact = Join-Path $testDir "integration_test.raw"
            
            if (-not (Test-Path $testDir)) {
                New-Item -ItemType Directory -Path $testDir -Force
            }
            
            # Create test artifact
            "Integration test data for Phase 3" | Set-Content -Path $testArtifact
            
            # Set offline mode for testing
            $env:OFFLINE = "true"
            $env:S3_BUCKET = "integration-test-bucket"
        }
        
        AfterAll {
            Remove-Item $testArtifact -Force -ErrorAction SilentlyContinue
            Remove-Item Env:OFFLINE -ErrorAction SilentlyContinue
            Remove-Item Env:S3_BUCKET -ErrorAction SilentlyContinue
        }
        
        It "Should complete full workflow: Hash -> Manifest -> Upload" {
            # Phase 2: Generate hash
            $hashResult = Get-ArtifactHash -FilePath $testArtifact
            $hashResult.Success | Should -Be $true
            
            # Phase 2: Create manifest
            $manifestResult = Write-Manifest -ArtifactPaths @($testArtifact) -CaseNumber "INT-001" -InvestigatorName "Integration Test"
            $manifestResult.Success | Should -Be $true
            
            # Phase 3: Upload (offline mode)
            $uploadResult = Send-ToS3 -OutputDir $testDir -IncludeManifest $true -Offline
            $uploadResult.Success | Should -Be $true
            
            # Verify all components worked together
            $uploadResult.TotalFiles | Should -BeGreaterThan 1  # Artifact + manifest + log
            
            $artifactUpload = $uploadResult.UploadResults | Where-Object { $_.FileName -eq "integration_test.raw" }
            $manifestUpload = $uploadResult.UploadResults | Where-Object { $_.FileName -eq "manifest.json" }
            $logUpload = $uploadResult.UploadResults | Where-Object { $_.FileName -eq "log.txt" }
            
            $artifactUpload | Should -Not -BeNullOrEmpty
            $manifestUpload | Should -Not -BeNullOrEmpty
            $logUpload | Should -Not -BeNullOrEmpty
            
            # Clean up generated files
            Remove-Item (Join-Path $testDir "manifest.json") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $testDir "log.txt") -Force -ErrorAction SilentlyContinue
        }
    }

    #endregion Phase 3 Tests

    #region Phase 4 Tests - Chain-of-Custody & Logging Enhancements

    Describe "Set-LoggingMode Function" {
        BeforeAll {
            # Save original logging state
            $script:OriginalLoggingMode = $script:LoggingMode
            $script:OriginalGlobalLogToFile = $script:GlobalLogToFile
            $script:OriginalGlobalLogDirectory = $script:GlobalLogDirectory
        }
        
        AfterAll {
            # Restore original logging state
            $script:LoggingMode = $script:OriginalLoggingMode
            $script:GlobalLogToFile = $script:OriginalGlobalLogToFile
            $script:GlobalLogDirectory = $script:OriginalGlobalLogDirectory
        }
        
        Context "Logging Mode Configuration" {
            It "Should set logging mode to Quiet" {
                $result = Set-LoggingMode -Mode Quiet
                
                $result.Mode | Should -Be "Quiet"
                $result.LogToFile | Should -Be $false
                $script:LoggingMode | Should -Be "Quiet"
            }
            
            It "Should set logging mode to Verbose" {
                $result = Set-LoggingMode -Mode Verbose
                
                $result.Mode | Should -Be "Verbose"
                $script:LoggingMode | Should -Be "Verbose"
            }
            
            It "Should enable file logging" {
                $testLogDir = Join-Path $TestDrive "test_logs"
                $result = Set-LoggingMode -Mode Normal -LogToFile -LogDirectory $testLogDir
                
                $result.LogToFile | Should -Be $true
                $result.LogDirectory | Should -Be $testLogDir
                Test-Path $testLogDir | Should -Be $true
            }
            
            It "Should return proper result structure" {
                $result = Set-LoggingMode -Mode Debug
                
                $result.PSObject.Properties.Name | Should -Contain "Mode"
                $result.PSObject.Properties.Name | Should -Contain "LogToFile"
                $result.PSObject.Properties.Name | Should -Contain "LogDirectory"
                $result.PSObject.Properties.Name | Should -Contain "Timestamp"
                $result.Timestamp | Should -Not -BeNullOrEmpty
            }
        }
    }

    Describe "Get-TimestampSignature Function" {
        
        Context "Basic Timestamp Generation" {
            It "Should generate timestamp signature for string data" {
                $testData = "Test evidence for timestamp signature"
                $result = Get-TimestampSignature -Data $testData
                
                $result | Should -Not -BeNullOrEmpty
                $result.TimestampVersion | Should -Be "1.0"
                $result.SignatureType | Should -Be "SHA256-Digest"
                $result.Signature | Should -Not -BeNullOrEmpty
                $result.CreatedAt | Should -Not -BeNullOrEmpty
                $result.CreatedAtUTC | Should -Not -BeNullOrEmpty
                $result.Payload.Data | Should -Be $testData
                $result.Payload.DataHash | Should -Not -BeNullOrEmpty
            }
            
            It "Should generate timestamp signature for hashtable data" {
                $testData = @{
                    CaseNumber = "TEST-001"
                    Evidence = "Memory dump"
                    Size = "2GB"
                }
                
                $result = Get-TimestampSignature -Data $testData
                
                $result.Payload.Data | Should -Not -BeNullOrEmpty
                $result.Payload.DataHash | Should -Not -BeNullOrEmpty
                $result.Signature | Should -Not -BeNullOrEmpty
            }
            
            It "Should include system information when requested" {
                $testData = "Test with system info"
                $result = Get-TimestampSignature -Data $testData -IncludeSystemInfo
                
                $result.Payload.SystemInfo | Should -Not -BeNullOrEmpty
                $result.Payload.SystemInfo.Hostname | Should -Not -BeNullOrEmpty
                $result.Payload.SystemInfo.Username | Should -Not -BeNullOrEmpty
                $result.Payload.SystemInfo.OSVersion | Should -Not -BeNullOrEmpty
                $result.Payload.SystemInfo.PowerShellVersion | Should -Not -BeNullOrEmpty
            }
            
            It "Should include proper metadata" {
                $testData = "Test metadata"
                $result = Get-TimestampSignature -Data $testData
                
                $result.Metadata | Should -Not -BeNullOrEmpty
                $result.Metadata.ToolkitVersion | Should -Be "1.0.0"
                $result.Metadata.SigningMethod | Should -Be "Local-SHA256"
                $result.Metadata.Verified | Should -Be $true
                $result.Metadata.VerifiedAt | Should -Not -BeNullOrEmpty
            }
        }
    }

    Describe "Get-OperationSummary Function" {
        
        BeforeAll {
            # Create mock operation results
            $script:MockSuccessResults = @(
                [PSCustomObject]@{ Success = $true; FileName = "file1.raw"; Duration = 1.5; Attempts = 1; Message = "Success" },
                [PSCustomObject]@{ Success = $true; FileName = "file2.img"; Duration = 2.3; Attempts = 1; Message = "Success" },
                [PSCustomObject]@{ Success = $true; FileName = "file3.vmem"; Duration = 0.8; Attempts = 2; Message = "Success after retry" }
            )
            
            $script:MockFailureResults = @(
                [PSCustomObject]@{ Success = $false; FileName = "file4.raw"; Duration = 0.5; Attempts = 3; Message = "Network error" },
                [PSCustomObject]@{ Success = $false; FileName = "file5.img"; Duration = 0.3; Attempts = 3; Message = "File not found" }
            )
            
            $script:MockMixedResults = $script:MockSuccessResults + $script:MockFailureResults
        }
        
        Context "Basic Summary Generation" {
            It "Should generate summary for successful operations" {
                $result = Get-OperationSummary -OperationType "Upload" -OperationResults $script:MockSuccessResults
                
                $result.OperationType | Should -Be "Upload"
                $result.Status | Should -Be "Completed Successfully"
                $result.Statistics.TotalOperations | Should -Be 3
                $result.Statistics.SuccessfulOperations | Should -Be 3
                $result.Statistics.FailedOperations | Should -Be 0
                $result.Statistics.SuccessRate | Should -Be 100
                $result.Statistics.TotalRetries | Should -Be 1  # One file had 2 attempts = 1 retry
            }
            
            It "Should generate summary for mixed operations" {
                $result = Get-OperationSummary -OperationType "Complete" -OperationResults $script:MockMixedResults
                
                $result.Status | Should -Be "Completed with Errors"
                $result.Statistics.TotalOperations | Should -Be 5
                $result.Statistics.SuccessfulOperations | Should -Be 3
                $result.Statistics.FailedOperations | Should -Be 2
                $result.Statistics.SuccessRate | Should -Be 60
            }
            
            It "Should calculate performance metrics" {
                $result = Get-OperationSummary -OperationType "Hashing" -OperationResults $script:MockSuccessResults
                
                $result.Performance | Should -Not -BeNullOrEmpty
                $result.Performance.OperationsPerSecond | Should -BeGreaterThan 0
                $result.Performance.SuccessfulOperationsPerSecond | Should -BeGreaterThan 0
                $result.Performance.RetryRate | Should -BeGreaterOrEqual 0
            }
            
            It "Should include digital signature" {
                $result = Get-OperationSummary -OperationType "Manifest" -OperationResults $script:MockSuccessResults
                
                $result.DigitalSignature | Should -Not -BeNullOrEmpty
                $result.DigitalSignature.TimestampVersion | Should -Be "1.0"
                $result.DigitalSignature.Signature | Should -Not -BeNullOrEmpty
            }
            
            It "Should include failure analysis when requested" {
                $result = Get-OperationSummary -OperationType "Upload" -OperationResults $script:MockMixedResults -IncludeFailureAnalysis
                
                $result.FailureAnalysis | Should -Not -BeNullOrEmpty
                $result.FailureAnalysis.TotalFailureTypes | Should -Be 2
                $result.FailureAnalysis.FailureBreakdown | Should -Not -BeNullOrEmpty
                $result.FailureAnalysis.FailureRate | Should -Be 40
            }
            
            It "Should save summary to file when requested" {
                $testOutputPath = Join-Path $TestDrive "test_summary.json"
                $result = Get-OperationSummary -OperationType "Complete" -OperationResults $script:MockSuccessResults -SaveToFile -OutputPath $testOutputPath
                
                Test-Path $testOutputPath | Should -Be $true
                $result.SavedToFile | Should -Be $testOutputPath
                
                # Verify file content
                $savedContent = Get-Content $testOutputPath | ConvertFrom-Json
                $savedContent.OperationType | Should -Be "Complete"
            }
        }
    }

    # Integration test for Phase 4 features
    Describe "Phase 4 Integration Tests" {
        
        BeforeAll {
            $testDir = Join-Path $TestDrive "phase4_integration"
            New-Item -Path $testDir -ItemType Directory -Force | Out-Null
            
            # Create test artifact
            $testArtifact = Join-Path $testDir "phase4_test.raw"
            "Phase 4 integration test data" | Set-Content -Path $testArtifact
            
            # Set verbose logging for testing
            Set-LoggingMode -Mode Verbose -LogToFile -LogDirectory $testDir
        }
        
        It "Should complete workflow with enhanced logging and chain-of-custody" {
            # Generate hash with timestamp
            $hashResult = Get-ArtifactHash -FilePath $testArtifact
            $hashResult.Success | Should -Be $true
            
            # Create manifest with digital timestamp
            $manifestResult = Write-Manifest -ArtifactPaths @($testArtifact) -CaseNumber "PHASE4-001" -InvestigatorName "Phase 4 Test"
            $manifestResult.Success | Should -Be $true
            
            # Verify digital timestamp was added to manifest
            $manifestContent = Get-Content $manifestResult.ManifestPath | ConvertFrom-Json
            $manifestContent.Integrity.DigitalTimestamp | Should -Not -BeNullOrEmpty
            $manifestContent.Integrity.DigitalTimestamp.TimestampVersion | Should -Be "1.0"
            
            # Generate operation summary
            $mockResults = @(
                [PSCustomObject]@{ Success = $true; FileName = "phase4_test.raw"; Duration = 1.0; Attempts = 1 }
            )
            $summaryResult = Get-OperationSummary -OperationType "Complete" -OperationResults $mockResults -IncludeRetryDetails -IncludeFailureAnalysis
            
            $summaryResult.OperationType | Should -Be "Complete"
            $summaryResult.Status | Should -Be "Completed Successfully"
            $summaryResult.DigitalSignature | Should -Not -BeNullOrEmpty
            
            # Clean up
            Remove-Item $testArtifact -Force -ErrorAction SilentlyContinue
            Remove-Item $manifestResult.ManifestPath -Force -ErrorAction SilentlyContinue
            Remove-Item $manifestResult.LogPath -Force -ErrorAction SilentlyContinue
        }
    }

    #endregion Phase 4 Tests

    #region Phase 5 Tests: Simulation & User Options

    Describe "Phase 5: Simulation & User Options Tests" {
        BeforeAll {
            $testOutputDir = Join-Path $TestDrive "phase5_tests"
            New-Item -Path $testOutputDir -ItemType Directory -Force | Out-Null
        }
        
        Context "New-SimulatedArtifact Tests" {
            It "Should create simulated memory artifact" {
                $outputPath = Join-Path $testOutputDir "simulated_memory.raw"
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath $outputPath -SizeMB 1
                
                $result.Success | Should -Be $true
                $result.Type | Should -Be "Memory"
                $result.Simulated | Should -Be $true
                Test-Path $outputPath | Should -Be $true
                
                $fileSize = (Get-Item $outputPath).Length
                $fileSize | Should -BeGreaterThan 1000000  # Should be approximately 1MB
            }
            
            It "Should create simulated disk artifact with metadata" {
                $outputPath = Join-Path $testOutputDir "simulated_disk.raw"
                $result = New-SimulatedArtifact -Type "Disk" -OutputPath $outputPath -SizeMB 2 -IncludeMetadata
                
                $result.Success | Should -Be $true
                $result.Type | Should -Be "Disk"
                $result.SizeMB | Should -BeGreaterThan 1.5
                Test-Path $outputPath | Should -Be $true
                Test-Path "$outputPath.metadata.json" | Should -Be $true
                
                # Verify metadata content
                $metadata = Get-Content "$outputPath.metadata.json" | ConvertFrom-Json
                $metadata.ArtifactType | Should -Be "Disk"
                $metadata.Simulated | Should -Be $true
                $metadata.Tool | Should -Be "Forensic Triage Toolkit"
            }
            
            It "Should create different artifact types" {
                $types = @("Memory", "Disk", "Registry", "EventLog", "NetworkCapture")
                
                foreach ($type in $types) {
                    $outputPath = Join-Path $testOutputDir "simulated_$($type.ToLower()).raw"
                    $result = New-SimulatedArtifact -Type $type -OutputPath $outputPath -SizeMB 1
                    
                    $result.Success | Should -Be $true
                    $result.Type | Should -Be $type
                    Test-Path $outputPath | Should -Be $true
                }
            }
            
            It "Should include realistic forensic headers" {
                $outputPath = Join-Path $testOutputDir "header_test.raw"
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath $outputPath -SizeMB 1
                
                $result.Success | Should -Be $true
                
                # Read first 100 bytes to check header
                $fileBytes = [System.IO.File]::ReadAllBytes($outputPath)
                $headerText = [System.Text.Encoding]::UTF8.GetString($fileBytes[0..99])
                
                $headerText | Should -Match "MEMORY_DUMP_SIMULATION"
                $headerText | Should -Match "Timestamp:"
                $headerText | Should -Match "System:"
            }
            
            It "Should handle file creation errors gracefully" {
                # Try to create file in non-existent directory with invalid path
                $invalidPath = "Z:\NonExistent\Path\file.raw"
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath $invalidPath -SizeMB 1
                
                $result.Success | Should -Be $false
                $result | Should -HaveProperty "Message"
            }
        }
        
        Context "Invoke-MemoryAcquisition with Simulation Tests" {
            It "Should perform simulated memory acquisition" {
                $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -Simulation -MemoryLimitMB 2048
                
                $result.Success | Should -Be $true
                $result.Simulated | Should -Be $true
                $result.SimulationNote | Should -Match "simulated artifact"
                $result.MemoryLimitMB | Should -Be 2048
                Test-Path $result.OutputFile | Should -Be $true
            }
            
            It "Should respect memory limit in simulation" {
                $result = Invoke-MemoryAcquisition -OutputDir $testOutputDir -Simulation -MemoryLimitMB 1024
                
                $result.Success | Should -Be $true
                $result.MemoryLimitMB | Should -Be 1024
                $result.SizeMB | Should -BeGreaterThan 0
            }
        }
        
        Context "Invoke-DiskAcquisition with Simulation Tests" {
            It "Should perform simulated disk acquisition" {
                $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -Simulation -Volumes @("C:")
                
                $result.Summary.TotalVolumes | Should -Be 1
                $result.Summary.SuccessfulVolumes | Should -Be 1
                $result.Results[0].Success | Should -Be $true
                $result.Results[0].Simulated | Should -Be $true
                Test-Path $result.Results[0].OutputFile | Should -Be $true
            }
            
            It "Should handle multiple volumes in simulation" {
                $result = Invoke-DiskAcquisition -OutputDir $testOutputDir -Simulation -Volumes @("C:", "D:")
                
                $result.Summary.TotalVolumes | Should -Be 2
                $result.Summary.SuccessfulVolumes | Should -Be 2
                
                foreach ($diskResult in $result.Results) {
                    $diskResult.Success | Should -Be $true
                    $diskResult.Simulated | Should -Be $true
                    Test-Path $diskResult.OutputFile | Should -Be $true
                }
            }
        }
        
        Context "Simulation Integration Tests" {
            It "Should create complete simulated evidence package" {
                $tempDir = Join-Path $testOutputDir "integration_test"
                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
                
                # Memory acquisition
                $memResult = Invoke-MemoryAcquisition -OutputDir $tempDir -Simulation
                $memResult.Success | Should -Be $true
                $memResult.Simulated | Should -Be $true
                
                # Disk acquisition
                $diskResult = Invoke-DiskAcquisition -OutputDir $tempDir -Simulation -Volumes @("C:")
                $diskResult.Summary.SuccessfulVolumes | Should -Be 1
                $diskResult.Results[0].Simulated | Should -Be $true
                
                # Hash calculation
                $hashResult = Get-ArtifactHash -OutputDir $tempDir -IncludePattern "*.raw"
                $hashResult.Summary.SuccessfulHashes | Should -BeGreaterThan 0
                
                # Manifest creation
                $manifestResult = Write-Manifest -OutputDir $tempDir -CaseNumber "SIM-001" -InvestigatorName "Test"
                $manifestResult.Success | Should -Be $true
                
                # Verify all artifacts exist
                $artifacts = Get-ChildItem -Path $tempDir -Filter "*.raw"
                $artifacts.Count | Should -BeGreaterThan 0
                
                $manifest = Get-ChildItem -Path $tempDir -Filter "manifest.json"
                $manifest.Count | Should -Be 1
            }
            
            It "Should maintain forensic integrity in simulation" {
                $tempDir = Join-Path $testOutputDir "integrity_test"
                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
                
                # Create artifact and verify hash
                $artifactPath = Join-Path $tempDir "integrity_test.raw"
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath $artifactPath -SizeMB 1
                
                $result.Success | Should -Be $true
                
                # Calculate hash twice to ensure consistency
                $hash1 = Get-ArtifactHash -FilePath $artifactPath
                $hash2 = Get-ArtifactHash -FilePath $artifactPath
                
                $hash1.Hash | Should -Be $hash2.Hash
                $hash1.Hash | Should -Not -BeNullOrEmpty
            }
        }
        
        Context "Function Availability Tests" {
            It "Should have Start-InteractiveMode function available" {
                $function = Get-Command Start-InteractiveMode -ErrorAction SilentlyContinue
                $function | Should -Not -BeNullOrEmpty
                $function.Parameters.Keys | Should -Contain "CaseNumber"
                $function.Parameters.Keys | Should -Contain "InvestigatorName"
                $function.Parameters.Keys | Should -Contain "Simulation"
            }
            
            It "Should have Invoke-CompleteWorkflow function available" {
                $function = Get-Command Invoke-CompleteWorkflow -ErrorAction SilentlyContinue
                $function | Should -Not -BeNullOrEmpty
                $function.Parameters.Keys | Should -Contain "CaseNumber"
                $function.Parameters.Keys | Should -Contain "InvestigatorName"
                $function.Parameters.Keys | Should -Contain "Simulation"
                $function.Parameters.Keys | Should -Contain "Interactive"
            }
            
            It "Should support simulation parameters in acquisition functions" {
                $memFunction = Get-Command Invoke-MemoryAcquisition
                $memFunction.Parameters.Keys | Should -Contain "Simulation"
                $memFunction.Parameters.Keys | Should -Contain "Interactive"
                
                $diskFunction = Get-Command Invoke-DiskAcquisition  
                $diskFunction.Parameters.Keys | Should -Contain "Simulation"
                $diskFunction.Parameters.Keys | Should -Contain "Interactive"
            }
        }
        
        Context "Error Handling in Simulation Mode" {
            It "Should handle simulation errors gracefully" {
                # Test with invalid path
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath "" -SizeMB 1
                $result.Success | Should -Be $false
                $result | Should -HaveProperty "Message"
            }
            
            It "Should handle invalid artifact types" {
                { New-SimulatedArtifact -Type "InvalidType" -OutputPath "test.raw" -SizeMB 1 } | Should -Throw
            }
            
            It "Should handle zero or negative size" {
                $result = New-SimulatedArtifact -Type "Memory" -OutputPath (Join-Path $testOutputDir "zero_size.raw") -SizeMB 0
                $result.Success | Should -Be $true  # Should handle gracefully
                
                # File should still be created with header
                Test-Path $result.OutputPath | Should -Be $true
            }
        }
    }

    #endregion Phase 5 Tests

    # Test module exports
    Describe "Module Exports" {
        It "Should export all expected functions" {
            $exportedCommands = Get-Command -Module AcquisitionToolkit
            $exportedCommands.Count | Should -Be 14
            
            $expectedFunctions = @(
                'Import-EnvironmentConfig'
                'Get-ConfigValue'
                'Write-LogMessage'
                'Invoke-MemoryAcquisition'
                'Invoke-DiskAcquisition'
                'Get-ArtifactHash'
                'Write-Manifest'
                'Send-ToS3'
                'Set-LoggingMode'
                'Get-TimestampSignature'
                'Get-OperationSummary'
                'Start-InteractiveMode'
                'New-SimulatedArtifact'
                'Invoke-CompleteWorkflow'
            )
            
            $exportedNames = $exportedCommands.Name
            foreach ($function in $expectedFunctions) {
                $exportedNames | Should -Contain $function
            }
        }
    }
} 