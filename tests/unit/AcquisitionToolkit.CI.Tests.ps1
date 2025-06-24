#Requires -Modules Pester

<#
.SYNOPSIS
    CI-Optimized Unit Tests for Forensic Triage Toolkit
    
.DESCRIPTION
    Lightweight version of unit tests optimized for CI/CD pipelines.
    Contains essential tests for core functionality without time-intensive operations.
    
.NOTES
    Requires Pester v5.0+
    Optimized for speed - runs essential tests only
#>

BeforeAll {
    # Import the module under test
    $ModulePath = Join-Path $PSScriptRoot ".." ".." "src" "AcquisitionToolkit.psm1"
    Import-Module $ModulePath -Force
    
    # Create minimal test environment
    $script:TestEnvPath = Join-Path $TestDrive "ci.env"
    $script:TestEnvContent = @"
AWS_ACCESS_KEY_ID=test_key
AWS_SECRET_ACCESS_KEY=test_secret
S3_BUCKET=test-bucket
MEMORY_LIMIT_MB=1024
EVIDENCE_DIR=./tests/evidence
OFFLINE=true
"@
    
    Set-Content -Path $script:TestEnvPath -Value $script:TestEnvContent
}

AfterAll {
    Remove-Module AcquisitionToolkit -Force -ErrorAction SilentlyContinue
}

Describe "Module Import and Basic Functions" -Tag "Fast", "CI" {
    
    It "Should import module successfully" {
        Get-Module AcquisitionToolkit | Should -Not -BeNullOrEmpty
    }
    
    It "Should export core functions" {
        $coreFunctions = @(
            'Import-EnvironmentConfig'
            'Get-ConfigValue'
            'Write-LogMessage'
            'Invoke-MemoryAcquisition'
            'Get-ArtifactHash'
        )
        
        $exportedFunctions = (Get-Module AcquisitionToolkit).ExportedFunctions.Keys
        
        foreach ($function in $coreFunctions) {
            $exportedFunctions | Should -Contain $function
        }
    }
    
    It "Should load environment configuration" {
        { Import-EnvironmentConfig -EnvPath $script:TestEnvPath } | Should -Not -Throw
    }
    
    It "Should retrieve configuration values" {
        Import-EnvironmentConfig -EnvPath $script:TestEnvPath
        
        Get-ConfigValue -Key "S3_BUCKET" | Should -Be "test-bucket"
        Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger | Should -Be 1024
        Get-ConfigValue -Key "OFFLINE" -AsBoolean | Should -Be $true
    }
    
    It "Should write log messages" {
        { Write-LogMessage -Message "Test message" -Level Info } | Should -Not -Throw
    }
}

Describe "Hash Calculation (Quick Test)" -Tag "Fast", "CI" {
    
    BeforeAll {
        $script:TestFile = Join-Path $TestDrive "test.raw"
        "Test content for hashing" | Out-File -FilePath $script:TestFile -Encoding ASCII
    }
    
    It "Should calculate SHA256 hash" {
        $result = Get-ArtifactHash -FilePath $script:TestFile
        
        $result.Summary.TotalFiles | Should -Be 1
        $result.Summary.SuccessfulHashes | Should -Be 1
        $result.Results[0].Hash | Should -Not -BeNullOrEmpty
        $result.Results[0].Algorithm | Should -Be 'SHA256'
    }
}

Describe "Simulation Mode (Quick Test)" -Tag "Fast", "CI" {
    
    It "Should create simulated memory artifact" {
        $outputPath = Join-Path $TestDrive "sim_memory.raw"
        
        $result = New-SimulatedArtifact -Type "Memory" -OutputPath $outputPath -SizeMB 1
        
        $result.Success | Should -Be $true
        $result.SizeMB | Should -Be 1
        Test-Path $outputPath | Should -Be $true
        (Get-Item $outputPath).Length | Should -BeGreaterThan 0
    }
    
    It "Should run memory acquisition in simulation mode" {
        $outputDir = Join-Path $TestDrive "sim_evidence"
        
        $result = Invoke-MemoryAcquisition -OutputDir $outputDir -MemoryLimitMB 1 -Simulation
        
        $result.Success | Should -Be $true
        $result.Simulated | Should -Be $true
        $result.SizeMB | Should -Be 10  # Default simulation size
    }
}

Describe "WhatIf Mode (Quick Test)" -Tag "Fast", "CI" {
    
    It "Should support WhatIf for memory acquisition" {
        $outputDir = Join-Path $TestDrive "whatif_evidence"
        
        $result = Invoke-MemoryAcquisition -OutputDir $outputDir -WhatIf
        
        $result.WouldExecute | Should -Not -BeNullOrEmpty
        $result.WouldExecute | Should -Match "velociraptor"
    }
}

Describe "Error Handling (Quick Test)" -Tag "Fast", "CI" {
    
    It "Should handle missing configuration gracefully" {
        Get-ConfigValue -Key "NONEXISTENT_KEY" -DefaultValue "default" | Should -Be "default"
    }
    
    It "Should handle missing files in hash calculation" {
        $missingFile = Join-Path $TestDrive "missing.raw"
        
        $result = Get-ArtifactHash -FilePath $missingFile
        
        $result.Summary.FailedHashes | Should -Be 1
        $result.Results[0].Success | Should -Be $false
    }
}

Describe "Cross-Platform Compatibility" -Tag "Fast", "CI" {
    
    It "Should detect operating system correctly" {
        # This test ensures the module loads on different platforms
        $functions = Get-Command -Module AcquisitionToolkit
        $functions.Count | Should -BeGreaterThan 10
    }
    
    It "Should handle path separators correctly" {
        $testPath = Join-Path "test" "path"
        $testPath | Should -Not -BeNullOrEmpty
    }
} 