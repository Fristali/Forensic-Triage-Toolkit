#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Build script for Forensic Triage Toolkit
    
.DESCRIPTION
    Comprehensive build, test, and analysis script that:
    - Runs PSScriptAnalyzer for code quality
    - Executes Pester unit tests with coverage
    - Validates module structure and exports
    - Generates test reports and artifacts
    - Prepares package for distribution
    
.PARAMETER Task
    The build task to execute: Test, Analyze, Package, All
    
.PARAMETER Configuration
    Build configuration: Debug or Release
    
.PARAMETER OutputPath
    Path for build outputs and reports
    
.PARAMETER SkipAnalysis
    Skip PSScriptAnalyzer code analysis
    
.PARAMETER SkipTests
    Skip Pester unit tests
    
.PARAMETER GenerateReports
    Generate detailed HTML reports
    
.EXAMPLE
    .\build.ps1 -Task All -Configuration Release
    
.EXAMPLE
    .\build.ps1 -Task Test -GenerateReports
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Test', 'Analyze', 'Package', 'All')]
    [string]$Task = 'All',
    
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    
    [Parameter()]
    [string]$OutputPath = './build-output',
    
    [Parameter()]
    [switch]$SkipAnalysis,
    
    [Parameter()]
    [switch]$SkipTests,
    
    [Parameter()]
    [switch]$GenerateReports
)

# Set error action preference
$ErrorActionPreference = 'Stop'

# Build configuration
$script:BuildConfig = @{
    SourcePath = './src'
    TestPath = './tests'
    ModuleName = 'AcquisitionToolkit'
    ModuleFile = './src/AcquisitionToolkit.psm1'
    ManifestFile = './src/AcquisitionToolkit.psd1'
    OutputPath = $OutputPath
    Configuration = $Configuration
    StartTime = Get-Date
}

#region Helper Functions

function Write-BuildMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'Info' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $color
}

function Initialize-BuildEnvironment {
    [CmdletBinding()]
    param()
    
    Write-BuildMessage "Initializing build environment..." -Level Info
    
    # Create output directory
    if (Test-Path $script:BuildConfig.OutputPath) {
        Remove-Item -Path $script:BuildConfig.OutputPath -Recurse -Force
    }
    New-Item -Path $script:BuildConfig.OutputPath -ItemType Directory -Force | Out-Null
    
    # Verify required modules
    $requiredModules = @('Pester', 'PSScriptAnalyzer')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-BuildMessage "Installing required module: $module" -Level Warning
            Install-Module -Name $module -Force -Scope CurrentUser
        }
    }
    
    Write-BuildMessage "Build environment initialized" -Level Success
}

function Test-ModuleStructure {
    [CmdletBinding()]
    param()
    
    Write-BuildMessage "Validating module structure..." -Level Info
    
    $errors = @()
    
    # Check if module file exists
    if (-not (Test-Path $script:BuildConfig.ModuleFile)) {
        $errors += "Module file not found: $($script:BuildConfig.ModuleFile)"
    }
    
    # Check if source directory exists
    if (-not (Test-Path $script:BuildConfig.SourcePath)) {
        $errors += "Source directory not found: $($script:BuildConfig.SourcePath)"
    }
    
    # Check if test directory exists
    if (-not (Test-Path $script:BuildConfig.TestPath)) {
        $errors += "Test directory not found: $($script:BuildConfig.TestPath)"
    }
    
    # Try to import module
    try {
        Import-Module $script:BuildConfig.ModuleFile -Force
        $exportedFunctions = Get-Command -Module $script:BuildConfig.ModuleName
        Write-BuildMessage "Module imports successfully with $($exportedFunctions.Count) exported functions" -Level Success
    }
    catch {
        $errors += "Failed to import module: $($_.Exception.Message)"
    }
    
    if ($errors.Count -gt 0) {
        foreach ($error in $errors) {
            Write-BuildMessage $error -Level Error
        }
        throw "Module structure validation failed"
    }
    
    Write-BuildMessage "Module structure validation passed" -Level Success
}

#endregion Helper Functions

#region Build Tasks

function Invoke-CodeAnalysis {
    [CmdletBinding()]
    param()
    
    if ($SkipAnalysis) {
        Write-BuildMessage "Skipping code analysis (SkipAnalysis specified)" -Level Warning
        return
    }
    
    Write-BuildMessage "Running PSScriptAnalyzer..." -Level Info
    
    $analysisParams = @{
        Path = $script:BuildConfig.SourcePath
        Recurse = $true
        Settings = 'PSGallery'
        ReportSummary = $true
    }
    
    $analysisResults = Invoke-ScriptAnalyzer @analysisParams
    
    # Generate analysis report
    $reportPath = Join-Path $script:BuildConfig.OutputPath 'analysis-report.json'
    $analysisResults | ConvertTo-Json -Depth 3 | Out-File -Path $reportPath -Encoding UTF8
    
    # Categorize results
    $errors = $analysisResults | Where-Object { $_.Severity -eq 'Error' }
    $warnings = $analysisResults | Where-Object { $_.Severity -eq 'Warning' }
    $information = $analysisResults | Where-Object { $_.Severity -eq 'Information' }
    
    Write-BuildMessage "Analysis complete: $($errors.Count) errors, $($warnings.Count) warnings, $($information.Count) info" -Level Info
    
    # Display errors
    if ($errors.Count -gt 0) {
        Write-BuildMessage "Code analysis errors found:" -Level Error
        foreach ($error in $errors) {
            Write-BuildMessage "  $($error.RuleName): $($error.Message) (Line $($error.Line))" -Level Error
        }
        throw "Code analysis failed with $($errors.Count) errors"
    }
    
    # Display warnings
    if ($warnings.Count -gt 0) {
        Write-BuildMessage "Code analysis warnings found:" -Level Warning
        foreach ($warning in $warnings) {
            Write-BuildMessage "  $($warning.RuleName): $($warning.Message) (Line $($warning.Line))" -Level Warning
        }
    }
    
    Write-BuildMessage "Code analysis passed" -Level Success
}

function Invoke-UnitTests {
    [CmdletBinding()]
    param()
    
    if ($SkipTests) {
        Write-BuildMessage "Skipping unit tests (SkipTests specified)" -Level Warning
        return
    }
    
    Write-BuildMessage "Running Pester unit tests..." -Level Info
    
    # Configure Pester
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $script:BuildConfig.TestPath
    $pesterConfig.Run.PassThru = $true
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = Join-Path $script:BuildConfig.OutputPath 'test-results.xml'
    $pesterConfig.TestResult.OutputFormat = 'NUnitXml'
    $pesterConfig.CodeCoverage.Enabled = $true
    $pesterConfig.CodeCoverage.Path = $script:BuildConfig.ModuleFile
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $script:BuildConfig.OutputPath 'coverage.xml'
    $pesterConfig.CodeCoverage.OutputFormat = 'JaCoCo'
    $pesterConfig.Output.Verbosity = 'Detailed'
    
    # Run tests
    $testResults = Invoke-Pester -Configuration $pesterConfig
    
    # Generate test summary
    $summary = @{
        TotalTests = $testResults.TotalCount
        PassedTests = $testResults.PassedCount
        FailedTests = $testResults.FailedCount
        SkippedTests = $testResults.SkippedCount
        Duration = $testResults.Duration
        CodeCoverage = if ($testResults.CodeCoverage) {
            @{
                CoveredPercent = [math]::Round($testResults.CodeCoverage.CoveragePercent, 2)
                CoveredCommands = $testResults.CodeCoverage.CommandsExecutedCount
                TotalCommands = $testResults.CodeCoverage.CommandsAnalyzedCount
            }
        } else { $null }
    }
    
    $summaryPath = Join-Path $script:BuildConfig.OutputPath 'test-summary.json'
    $summary | ConvertTo-Json -Depth 3 | Out-File -Path $summaryPath -Encoding UTF8
    
    Write-BuildMessage "Test Results: $($summary.PassedTests)/$($summary.TotalTests) passed" -Level Info
    
    if ($summary.CodeCoverage) {
        Write-BuildMessage "Code Coverage: $($summary.CodeCoverage.CoveredPercent)%" -Level Info
    }
    
    # Check for test failures
    if ($testResults.FailedCount -gt 0) {
        Write-BuildMessage "Unit tests failed: $($testResults.FailedCount) failures" -Level Error
        
        # Display failed test details
        foreach ($failedTest in $testResults.Failed) {
            Write-BuildMessage "  FAILED: $($failedTest.ExpandedName)" -Level Error
            Write-BuildMessage "    $($failedTest.ErrorRecord.Exception.Message)" -Level Error
        }
        
        throw "Unit tests failed"
    }
    
    Write-BuildMessage "All unit tests passed" -Level Success
}

function New-PackageArtifacts {
    [CmdletBinding()]
    param()
    
    Write-BuildMessage "Creating package artifacts..." -Level Info
    
    $packageDir = Join-Path $script:BuildConfig.OutputPath 'package'
    New-Item -Path $packageDir -ItemType Directory -Force | Out-Null
    
    # Copy module files
    $modulePackageDir = Join-Path $packageDir $script:BuildConfig.ModuleName
    New-Item -Path $modulePackageDir -ItemType Directory -Force | Out-Null
    
    Copy-Item -Path $script:BuildConfig.ModuleFile -Destination $modulePackageDir
    
    # Create module manifest if it doesn't exist
    if (-not (Test-Path $script:BuildConfig.ManifestFile)) {
        $manifestParams = @{
            Path = Join-Path $modulePackageDir "$($script:BuildConfig.ModuleName).psd1"
            ModuleVersion = '1.0.0'
            Author = 'Forensic Triage Toolkit Team'
            Description = 'PowerShell module for automated forensic evidence acquisition'
            RootModule = "$($script:BuildConfig.ModuleName).psm1"
            PowerShellVersion = '7.0'
            Tags = @('Forensics', 'Evidence', 'Acquisition', 'Digital-Forensics')
            ProjectUri = 'https://github.com/your-org/forensic-triage-toolkit'
            LicenseUri = 'https://github.com/your-org/forensic-triage-toolkit/blob/main/LICENSE'
        }
        New-ModuleManifest @manifestParams
    } else {
        Copy-Item -Path $script:BuildConfig.ManifestFile -Destination $modulePackageDir
    }
    
    # Copy documentation
    $docsDir = Join-Path $packageDir 'docs'
    if (Test-Path './docs') {
        Copy-Item -Path './docs' -Destination $docsDir -Recurse
    }
    
    # Copy configuration examples
    if (Test-Path './config.env.example') {
        Copy-Item -Path './config.env.example' -Destination $packageDir
    }
    
    # Copy README
    if (Test-Path './README.md') {
        Copy-Item -Path './README.md' -Destination $packageDir
    }
    
    # Create ZIP package
    $zipPath = Join-Path $script:BuildConfig.OutputPath "$($script:BuildConfig.ModuleName)-v1.0.0.zip"
    Compress-Archive -Path "$packageDir\*" -DestinationPath $zipPath -Force
    
    Write-BuildMessage "Package created: $zipPath" -Level Success
}

function New-BuildReports {
    [CmdletBinding()]
    param()
    
    if (-not $GenerateReports) {
        Write-BuildMessage "Skipping report generation (GenerateReports not specified)" -Level Info
        return
    }
    
    Write-BuildMessage "Generating build reports..." -Level Info
    
    # Build summary
    $buildSummary = @{
        BuildDate = $script:BuildConfig.StartTime
        BuildDuration = (Get-Date) - $script:BuildConfig.StartTime
        Configuration = $script:BuildConfig.Configuration
        ModuleName = $script:BuildConfig.ModuleName
        Tasks = @()
    }
    
    if (Test-Path (Join-Path $script:BuildConfig.OutputPath 'analysis-report.json')) {
        $buildSummary.Tasks += 'Analysis'
    }
    
    if (Test-Path (Join-Path $script:BuildConfig.OutputPath 'test-results.xml')) {
        $buildSummary.Tasks += 'Tests'
    }
    
    if (Test-Path (Join-Path $script:BuildConfig.OutputPath 'package')) {
        $buildSummary.Tasks += 'Package'
    }
    
    $summaryPath = Join-Path $script:BuildConfig.OutputPath 'build-summary.json'
    $buildSummary | ConvertTo-Json -Depth 3 | Out-File -Path $summaryPath -Encoding UTF8
    
    Write-BuildMessage "Build reports generated" -Level Success
}

#endregion Build Tasks

#region Main Build Logic

function Invoke-Build {
    [CmdletBinding()]
    param()
    
    try {
        Write-BuildMessage "Starting build process..." -Level Info
        Write-BuildMessage "Task: $Task, Configuration: $Configuration" -Level Info
        
        Initialize-BuildEnvironment
        Test-ModuleStructure
        
        switch ($Task) {
            'Test' {
                Invoke-UnitTests
            }
            'Analyze' {
                Invoke-CodeAnalysis
            }
            'Package' {
                New-PackageArtifacts
            }
            'All' {
                Invoke-CodeAnalysis
                Invoke-UnitTests
                New-PackageArtifacts
                New-BuildReports
            }
        }
        
        $duration = (Get-Date) - $script:BuildConfig.StartTime
        Write-BuildMessage "Build completed successfully in $([math]::Round($duration.TotalSeconds, 2)) seconds" -Level Success
        
        # Display output summary
        Write-BuildMessage "Build outputs:" -Level Info
        Get-ChildItem -Path $script:BuildConfig.OutputPath -Recurse | ForEach-Object {
            Write-BuildMessage "  $($_.FullName)" -Level Info
        }
        
    }
    catch {
        $duration = (Get-Date) - $script:BuildConfig.StartTime
        Write-BuildMessage "Build failed after $([math]::Round($duration.TotalSeconds, 2)) seconds" -Level Error
        Write-BuildMessage "Error: $($_.Exception.Message)" -Level Error
        throw
    }
}

#endregion Main Build Logic

# Execute build
Invoke-Build 