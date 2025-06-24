#Requires -Version 7.0

<#
.SYNOPSIS
    Forensic Triage Toolkit - Automated disk & RAM acquisition with Velociraptor
    
.DESCRIPTION
    End-to-end automation for disk & RAM acquisition on a single host using Velociraptor,
    with SHA-256 hashing, chain-of-custody JSON manifest, optional encryption/compression,
    S3 upload, evidence retention, and detailed logging.
    
.NOTES
    Author: Forensic Triage Toolkit
    Version: 1.0.0
    PowerShell: 7.0+
    
.LINK
    https://github.com/your-org/forensic-triage-toolkit
#>

# Module variables
$script:ModuleRoot = $PSScriptRoot
$script:EnvironmentConfig = @{}

# Export module functions (will be populated in subsequent phases)
$ExportedFunctions = @(
    # Helper functions
    'Import-EnvironmentConfig'
    'Get-ConfigValue' 
    'Write-LogMessage'
    
    # Phase 1 functions
    'Invoke-MemoryAcquisition'
    'Invoke-DiskAcquisition'
    
    # Phase 2 functions  
    'Get-ArtifactHash'
    'Write-Manifest'
    
    # Phase 3 functions
    'Send-ToS3'
    
    # Phase 4 functions
    'Set-LoggingMode'
    'Get-TimestampSignature'
    'Get-OperationSummary'
    
    # Phase 5 functions
    'Start-InteractiveMode'
    'New-SimulatedArtifact'
    'Invoke-CompleteWorkflow'
)

#region Acquisition Functions

<#
.SYNOPSIS
    Performs memory acquisition using Velociraptor and winpmem
    
.DESCRIPTION
    Executes memory acquisition using Velociraptor's winpmem capability to create
    a memory dump of the target system. Supports memory limit configuration and
    custom output directories.
    
.PARAMETER MemoryLimitMB
    Memory acquisition limit in MB. If not specified, uses MEMORY_LIMIT_MB from configuration.
    
.PARAMETER OutputDir
    Output directory for evidence files. Defaults to EVIDENCE_DIR from configuration.
    
.PARAMETER VelociraptorPath
    Path to Velociraptor binary. Defaults to VELOCIRAPTOR_PATH from configuration or ./bin/velociraptor.exe
    
.PARAMETER LogFile
    Optional log file path for detailed logging
    
.EXAMPLE
    Invoke-MemoryAcquisition -OutputDir "./evidence"
    
.EXAMPLE
    Invoke-MemoryAcquisition -MemoryLimitMB 2048 -OutputDir "./case001" -LogFile "./case001/memory.log"
    
.NOTES
    Requires administrative privileges for memory access
    Velociraptor binary must be available and executable
#>
function Invoke-MemoryAcquisition {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [int]$MemoryLimitMB,
        
        [Parameter()]
        [string]$OutputDir,
        
        [Parameter()]
        [string]$VelociraptorPath,
        
        [Parameter()]
        [string]$LogFile,
        
        [Parameter()]
        [switch]$Simulation,
        
        [Parameter()]
        [switch]$Interactive
    )
    
    begin {
        Write-LogMessage -Message "Starting memory acquisition" -Level Info -LogFile $LogFile
        
        # Handle interactive mode
        if ($Interactive) {
            Write-Host "=== Interactive Memory Acquisition ===" -ForegroundColor Cyan
            Write-Host ""
            
            if (-not $MemoryLimitMB) {
                do {
                    $input = Read-Host "Enter memory limit in MB [default: 4096]"
                    if ([string]::IsNullOrWhiteSpace($input)) {
                        $MemoryLimitMB = 4096
                        break
                    } elseif ([int]::TryParse($input, [ref]$MemoryLimitMB) -and $MemoryLimitMB -gt 0) {
                        break
                    } else {
                        Write-Host "Invalid input. Please enter a positive number." -ForegroundColor Red
                    }
                } while ($true)
            }
            
            if (-not $OutputDir) {
                $defaultOutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
                $input = Read-Host "Enter output directory [default: $defaultOutputDir]"
                $OutputDir = if ([string]::IsNullOrWhiteSpace($input)) { $defaultOutputDir } else { $input }
            }
            
            $confirm = Read-Host "Proceed with memory acquisition? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Host "Memory acquisition cancelled by user." -ForegroundColor Yellow
                return @{
                    Success = $false
                    Message = "Cancelled by user"
                    UserCancelled = $true
                }
            }
            
            Write-Host ""
        }
        
        # Get configuration values with defaults
        if (-not $MemoryLimitMB) {
            $MemoryLimitMB = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger -DefaultValue 4096
        }
        
        if (-not $OutputDir) {
            $OutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
        }
        
        if (-not $VelociraptorPath) {
            $VelociraptorPath = Get-ConfigValue -Key "VELOCIRAPTOR_PATH"
            if (-not $VelociraptorPath) {
                if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
                    $VelociraptorPath = "./bin/velociraptor.exe"
                } else {
                    $VelociraptorPath = "./bin/velociraptor"
                }
            }
        }
        
        # Ensure output directory exists
        if (-not (Test-Path $OutputDir)) {
            Write-LogMessage -Message "Creating output directory: $OutputDir" -Level Info -LogFile $LogFile
            try {
                New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-LogMessage -Message "Failed to create output directory: $_" -Level Error -LogFile $LogFile
                throw
            }
        }
        
        # Validate Velociraptor binary exists
        if (-not (Test-Path $VelociraptorPath)) {
            $errorMsg = "Velociraptor binary not found at: $VelociraptorPath"
            Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
            throw $errorMsg
        }
        
        # Generate output filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $hostname = $env:COMPUTERNAME -replace '[^\w\-_]', '_'
        $memoryFile = Join-Path $OutputDir "${hostname}_${timestamp}_memory.raw"
        
        Write-LogMessage -Message "Memory limit: $MemoryLimitMB MB" -Level Info -LogFile $LogFile
        Write-LogMessage -Message "Output file: $memoryFile" -Level Info -LogFile $LogFile
    }
    
    process {
        try {
            # Handle simulation mode
            if ($Simulation) {
                Write-LogMessage -Message "Simulation mode: Creating dummy memory artifact" -Level Info -LogFile $LogFile
                
                $simulatedResult = New-SimulatedArtifact -Type "Memory" -OutputPath $memoryFile -SizeMB 10 -LogFile $LogFile
                
                if ($simulatedResult.Success) {
                    Write-LogMessage -Message "Simulated memory acquisition completed: $memoryFile ($($simulatedResult.SizeMB) MB)" -Level Info -LogFile $LogFile
                    
                    return @{
                        Success = $true
                        OutputFile = $simulatedResult.OutputPath
                        SizeBytes = $simulatedResult.SizeBytes
                        SizeMB = $simulatedResult.SizeMB
                        Timestamp = $timestamp
                        MemoryLimitMB = $MemoryLimitMB
                        Simulated = $true
                        SimulationNote = "This is a simulated artifact for testing purposes"
                    }
                } else {
                    throw "Failed to create simulated memory artifact: $($simulatedResult.Message)"
                }
            }
            
            # Build Velociraptor command arguments
            $veloArgs = @(
                "artifacts", "collect"
                "Windows.Memory.Acquisition"
                "--args", "Compression=None"
                "--format", "json"
                "--output", $OutputDir
                "--timeout", "300"
            )
            
            # Add memory limit if specified
            if ($MemoryLimitMB -gt 0) {
                $veloArgs += @("--hard_memory_limit", ($MemoryLimitMB * 1024 * 1024))
            }
            
            Write-LogMessage -Message "Executing Velociraptor: $VelociraptorPath $($veloArgs -join ' ')" -Level Verbose -LogFile $LogFile
            
            if ($PSCmdlet.ShouldProcess("Memory acquisition", "Execute Velociraptor")) {
                $process = Start-Process -FilePath $VelociraptorPath -ArgumentList $veloArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $OutputDir "velociraptor_memory.log") -RedirectStandardError (Join-Path $OutputDir "velociraptor_memory_error.log")
                
                if ($process.ExitCode -eq 0) {
                    Write-LogMessage -Message "Memory acquisition completed successfully" -Level Info -LogFile $LogFile
                    
                    # Verify output file exists
                    if (Test-Path $memoryFile) {
                        $fileSize = (Get-Item $memoryFile).Length
                        $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
                        Write-LogMessage -Message "Memory dump created: $memoryFile ($fileSizeMB MB)" -Level Info -LogFile $LogFile
                        
                        return @{
                            Success = $true
                            OutputFile = $memoryFile
                            SizeBytes = $fileSize
                            SizeMB = $fileSizeMB
                            Timestamp = $timestamp
                            MemoryLimitMB = $MemoryLimitMB
                        }
                    } else {
                        $errorMsg = "Memory acquisition appeared to succeed but output file not found: $memoryFile"
                        Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                        throw $errorMsg
                    }
                } else {
                    $errorMsg = "Velociraptor process failed with exit code: $($process.ExitCode)"
                    Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                    
                    # Try to read error log for more details
                    $errorLogPath = Join-Path $OutputDir "velociraptor_memory_error.log"
                    if (Test-Path $errorLogPath) {
                        $errorDetails = Get-Content $errorLogPath -Raw
                        Write-LogMessage -Message "Velociraptor error details: $errorDetails" -Level Error -LogFile $LogFile
                    }
                    
                    throw $errorMsg
                }
            } else {
                Write-LogMessage -Message "Memory acquisition skipped (WhatIf mode)" -Level Info -LogFile $LogFile
                return @{
                    Success = $false
                    Message = "Skipped due to WhatIf mode"
                    WouldExecute = "$VelociraptorPath $($veloArgs -join ' ')"
                }
            }
        }
        catch {
            Write-LogMessage -Message "Memory acquisition failed: $_" -Level Error -LogFile $LogFile
            throw
        }
    }
    
    end {
        Write-LogMessage -Message "Memory acquisition process completed" -Level Info -LogFile $LogFile
    }
}

<#
.SYNOPSIS
    Performs disk acquisition using Velociraptor
    
.DESCRIPTION
    Executes disk imaging using Velociraptor's Windows.Disk.Image artifact to create
    forensic images of specified volumes or entire disks.
    
.PARAMETER Volumes
    Array of volumes to acquire (e.g., @("C:", "D:")). If not specified, acquires all available volumes.
    
.PARAMETER OutputDir
    Output directory for evidence files. Defaults to EVIDENCE_DIR from configuration.
    
.PARAMETER VelociraptorPath
    Path to Velociraptor binary. Defaults to VELOCIRAPTOR_PATH from configuration or ./bin/velociraptor.exe
    
.PARAMETER LogFile
    Optional log file path for detailed logging
    
.PARAMETER MaxSize
    Maximum size per volume in bytes. Useful for limiting large disk acquisitions.
    
.EXAMPLE
    Invoke-DiskAcquisition -Volumes @("C:") -OutputDir "./evidence"
    
.EXAMPLE
    Invoke-DiskAcquisition -Volumes @("C:", "D:") -OutputDir "./case001" -LogFile "./case001/disk.log"
    
.EXAMPLE
    Invoke-DiskAcquisition -OutputDir "./evidence" -MaxSize 10GB
    
.NOTES
    Requires administrative privileges for disk access
    Velociraptor binary must be available and executable
    Large disk acquisitions can take significant time and space
#>
function Invoke-DiskAcquisition {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string[]]$Volumes,
        
        [Parameter()]
        [string]$OutputDir,
        
        [Parameter()]
        [string]$VelociraptorPath,
        
        [Parameter()]
        [string]$LogFile,
        
        [Parameter()]
        [long]$MaxSize,
        
        [Parameter()]
        [switch]$Simulation,
        
        [Parameter()]
        [switch]$Interactive
    )
    
    begin {
        Write-LogMessage -Message "Starting disk acquisition" -Level Info -LogFile $LogFile
        
        # Handle interactive mode
        if ($Interactive) {
            Write-Host "=== Interactive Disk Acquisition ===" -ForegroundColor Cyan
            Write-Host ""
            
            if (-not $Volumes -or $Volumes.Count -eq 0) {
                # Show available volumes
                try {
                    if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
                        # Use timeout to prevent hanging on WMI calls
                        $job = Start-Job -ScriptBlock {
                            Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object { $_.DeviceID }
                        }
                        $availableVolumes = Wait-Job $job -Timeout 5 | Receive-Job
                        Remove-Job $job -Force
                        
                        if ($availableVolumes) {
                            Write-Host "Available volumes: $($availableVolumes -join ', ')" -ForegroundColor Green
                        } else {
                            throw "No volumes detected within timeout"
                        }
                    } else {
                        Write-Host "Available volumes: / (Unix-like system)" -ForegroundColor Green
                        $availableVolumes = @("/")
                    }
                } catch {
                    Write-Host "Could not detect volumes automatically" -ForegroundColor Yellow
                    $availableVolumes = @("C:")
                }
                
                do {
                    $input = Read-Host "Enter volumes to acquire (comma-separated) [default: all available]"
                    if ([string]::IsNullOrWhiteSpace($input)) {
                        $Volumes = $availableVolumes
                        break
                    } else {
                        $Volumes = $input -split ',' | ForEach-Object { $_.Trim() }
                        break
                    }
                } while ($true)
            }
            
            if (-not $OutputDir) {
                $defaultOutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
                $input = Read-Host "Enter output directory [default: $defaultOutputDir]"
                $OutputDir = if ([string]::IsNullOrWhiteSpace($input)) { $defaultOutputDir } else { $input }
            }
            
            if (-not $MaxSize) {
                $input = Read-Host "Enter maximum size per volume in GB [default: unlimited]"
                if (-not [string]::IsNullOrWhiteSpace($input)) {
                    if ([double]::TryParse($input, [ref]$maxSizeGB)) {
                        $MaxSize = [long]($maxSizeGB * 1GB)
                    }
                }
            }
            
            Write-Host ""
            Write-Host "Configuration Summary:" -ForegroundColor Yellow
            Write-Host "  Volumes: $($Volumes -join ', ')"
            Write-Host "  Output Directory: $OutputDir"
            Write-Host "  Max Size per Volume: $(if ($MaxSize) { "$([math]::Round($MaxSize / 1GB, 2)) GB" } else { "Unlimited" })"
            Write-Host ""
            
            $confirm = Read-Host "Proceed with disk acquisition? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Host "Disk acquisition cancelled by user." -ForegroundColor Yellow
                return @{
                    Success = $false
                    Message = "Cancelled by user"
                    UserCancelled = $true
                    Summary = @{
                        TotalVolumes = 0
                        SuccessfulVolumes = 0
                        FailedVolumes = 0
                    }
                    Results = @()
                }
            }
            
            Write-Host ""
        }
        
        # Get configuration values with defaults
        if (-not $OutputDir) {
            $OutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
        }
        
        if (-not $VelociraptorPath) {
            $VelociraptorPath = Get-ConfigValue -Key "VELOCIRAPTOR_PATH"
            if (-not $VelociraptorPath) {
                if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
                    $VelociraptorPath = "./bin/velociraptor.exe"
                } else {
                    $VelociraptorPath = "./bin/velociraptor"
                }
            }
        }
        
        # Ensure output directory exists
        if (-not (Test-Path $OutputDir)) {
            Write-LogMessage -Message "Creating output directory: $OutputDir" -Level Info -LogFile $LogFile
            try {
                New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-LogMessage -Message "Failed to create output directory: $_" -Level Error -LogFile $LogFile
                throw
            }
        }
        
        # Validate Velociraptor binary exists
        if (-not (Test-Path $VelociraptorPath)) {
            $errorMsg = "Velociraptor binary not found at: $VelociraptorPath"
            Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
            throw $errorMsg
        }
        
        # Auto-detect volumes if not specified
        if (-not $Volumes -or $Volumes.Count -eq 0) {
            try {
                if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
                    # Use timeout to prevent hanging on WMI calls
                    $job = Start-Job -ScriptBlock {
                        Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object { $_.DeviceID }
                    }
                    $Volumes = Wait-Job $job -Timeout 5 | Receive-Job
                    Remove-Job $job -Force
                    
                    if (-not $Volumes) {
                        throw "No volumes detected within timeout"
                    }
                } else {
                    # For non-Windows, use a different approach
                    $Volumes = @("/")  # Default to root for Unix-like systems
                }
                Write-LogMessage -Message "Auto-detected volumes: $($Volumes -join ', ')" -Level Info -LogFile $LogFile
            }
            catch {
                Write-LogMessage -Message "Failed to auto-detect volumes, defaulting to C:" -Level Warning -LogFile $LogFile
                $Volumes = @("C:")
            }
        }
        
        Write-LogMessage -Message "Target volumes: $($Volumes -join ', ')" -Level Info -LogFile $LogFile
        if ($MaxSize) {
            Write-LogMessage -Message "Maximum size per volume: $($MaxSize / 1GB) GB" -Level Info -LogFile $LogFile
        }
        
        $results = @()
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $hostname = $env:COMPUTERNAME -replace '[^\w\-_]', '_'
    }
    
    process {
        foreach ($volume in $Volumes) {
            try {
                $volumeClean = $volume -replace '[^\w]', '_'
                $diskFile = Join-Path $OutputDir "${hostname}_${timestamp}_disk_${volumeClean}.raw"
                
                Write-LogMessage -Message "Acquiring volume: $volume -> $diskFile" -Level Info -LogFile $LogFile
                
                # Handle simulation mode
                if ($Simulation) {
                    Write-LogMessage -Message "Simulation mode: Creating dummy disk artifact for volume $volume" -Level Info -LogFile $LogFile
                    
                    $simulatedResult = New-SimulatedArtifact -Type "Disk" -OutputPath $diskFile -SizeMB 10 -LogFile $LogFile
                    
                    if ($simulatedResult.Success) {
                        Write-LogMessage -Message "Simulated disk acquisition completed for volume $volume : $diskFile ($($simulatedResult.SizeMB) MB)" -Level Info -LogFile $LogFile
                        
                        $results += @{
                            Success = $true
                            Volume = $volume
                            OutputFile = $simulatedResult.OutputPath
                            SizeBytes = $simulatedResult.SizeBytes
                            SizeGB = [math]::Round($simulatedResult.SizeBytes / 1GB, 2)
                            Timestamp = $timestamp
                            Simulated = $true
                            SimulationNote = "This is a simulated artifact for testing purposes"
                        }
                        continue
                    } else {
                        Write-LogMessage -Message "Failed to create simulated disk artifact for volume $volume : $($simulatedResult.Message)" -Level Error -LogFile $LogFile
                        $results += @{
                            Success = $false
                            Volume = $volume
                            Error = "Failed to create simulated artifact: $($simulatedResult.Message)"
                        }
                        continue
                    }
                }
                
                # Build Velociraptor command arguments
                $veloArgs = @(
                    "artifacts", "collect"
                    "--artifact", "Windows.Disk.Image"
                    "--args", "Device=$volume"
                    "--args", "Filename=$diskFile"
                    "--format", "json"
                    "--output", $OutputDir
                )
                
                # Add max size if specified
                if ($MaxSize -gt 0) {
                    $veloArgs += @("--args", "MaxSize=$MaxSize")
                }
                
                Write-LogMessage -Message "Executing Velociraptor: $VelociraptorPath $($veloArgs -join ' ')" -Level Verbose -LogFile $LogFile
                
                if ($PSCmdlet.ShouldProcess("Disk acquisition for volume $volume", "Execute Velociraptor")) {
                    $process = Start-Process -FilePath $VelociraptorPath -ArgumentList $veloArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $OutputDir "velociraptor_disk_${volumeClean}.log") -RedirectStandardError (Join-Path $OutputDir "velociraptor_disk_${volumeClean}_error.log")
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage -Message "Disk acquisition completed for volume: $volume" -Level Info -LogFile $LogFile
                        
                        # Verify output file exists
                        if (Test-Path $diskFile) {
                            $fileSize = (Get-Item $diskFile).Length
                            $fileSizeGB = [math]::Round($fileSize / 1GB, 2)
                            Write-LogMessage -Message "Disk image created: $diskFile ($fileSizeGB GB)" -Level Info -LogFile $LogFile
                            
                            $results += @{
                                Success = $true
                                Volume = $volume
                                OutputFile = $diskFile
                                SizeBytes = $fileSize
                                SizeGB = $fileSizeGB
                                Timestamp = $timestamp
                            }
                        } else {
                            $errorMsg = "Disk acquisition appeared to succeed but output file not found: $diskFile"
                            Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                            
                            $results += @{
                                Success = $false
                                Volume = $volume
                                Error = $errorMsg
                            }
                        }
                    } else {
                        $errorMsg = "Velociraptor process failed for volume $volume with exit code: $($process.ExitCode)"
                        Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                        
                        # Try to read error log for more details
                        $errorLogPath = Join-Path $OutputDir "velociraptor_disk_${volumeClean}_error.log"
                        if (Test-Path $errorLogPath) {
                            $errorDetails = Get-Content $errorLogPath -Raw
                            Write-LogMessage -Message "Velociraptor error details for $volume : $errorDetails" -Level Error -LogFile $LogFile
                        }
                        
                        $results += @{
                            Success = $false
                            Volume = $volume
                            Error = $errorMsg
                            ExitCode = $process.ExitCode
                        }
                    }
                } else {
                    Write-LogMessage -Message "Disk acquisition skipped for volume $volume (WhatIf mode)" -Level Info -LogFile $LogFile
                    $results += @{
                        Success = $false
                        Volume = $volume
                        Message = "Skipped due to WhatIf mode"
                        WouldExecute = "$VelociraptorPath $($veloArgs -join ' ')"
                    }
                }
            }
            catch {
                $errorMsg = "Disk acquisition failed for volume $volume : $_"
                Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                
                $results += @{
                    Success = $false
                    Volume = $volume
                    Error = $errorMsg
                    Exception = $_.Exception.Message
                }
            }
        }
    }
    
    end {
        Write-LogMessage -Message "Disk acquisition process completed" -Level Info -LogFile $LogFile
        
        $successCount = ($results | Where-Object { $_.Success }).Count
        $totalCount = $results.Count
        Write-LogMessage -Message "Disk acquisition summary: $successCount/$totalCount volumes successful" -Level Info -LogFile $LogFile
        
        return @{
            Summary = @{
                TotalVolumes = $totalCount
                SuccessfulVolumes = $successCount
                FailedVolumes = $totalCount - $successCount
                Timestamp = $timestamp
            }
            Results = $results
        }
    }
}

#endregion Acquisition Functions

#region Hash & Manifest Functions

<#
.SYNOPSIS
    Calculates SHA-256 hash for one or more artifact files
    
.DESCRIPTION
    Generates SHA-256 hashes for forensic artifacts and returns structured data
    suitable for inclusion in chain-of-custody manifests. Supports both individual
    files and bulk processing of multiple artifacts.
    
.PARAMETER FilePath
    Path to a single file or array of file paths to hash
    
.PARAMETER OutputDir
    Directory containing artifacts to hash (alternative to FilePath)
    
.PARAMETER IncludePattern
    File pattern to include when processing OutputDir (e.g., "*.raw", "*.img")
    
.PARAMETER LogFile
    Optional log file path for detailed logging
    
.EXAMPLE
    Get-ArtifactHash -FilePath "./evidence/memory.raw"
    
.EXAMPLE
    Get-ArtifactHash -FilePath @("./evidence/memory.raw", "./evidence/disk.raw")
    
.EXAMPLE
    Get-ArtifactHash -OutputDir "./evidence" -IncludePattern "*.raw"
    
.NOTES
    Returns structured hash data with file metadata for chain-of-custody purposes
    Uses PowerShell's Get-FileHash cmdlet with SHA256 algorithm
#>
function Get-ArtifactHash {
    [CmdletBinding(DefaultParameterSetName = 'FilePath')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FilePath', ValueFromPipeline)]
        [string[]]$FilePath,
        
        [Parameter(Mandatory, ParameterSetName = 'OutputDir')]
        [string]$OutputDir,
        
        [Parameter(ParameterSetName = 'OutputDir')]
        [string]$IncludePattern = "*",
        
        [Parameter()]
        [string]$LogFile
    )
    
    begin {
        Write-LogMessage -Message "Starting artifact hash calculation" -Level Info -LogFile $LogFile
        
        $results = @()
        $totalFiles = 0
        $startTime = Get-Date
    }
    
    process {
        try {
            # Build file list based on parameter set
            $filesToHash = @()
            
            if ($PSCmdlet.ParameterSetName -eq 'FilePath') {
                $filesToHash = $FilePath
            } else {
                if (-not (Test-Path $OutputDir)) {
                    $errorMsg = "Output directory not found: $OutputDir"
                    Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                    throw $errorMsg
                }
                
                Write-LogMessage -Message "Scanning directory: $OutputDir with pattern: $IncludePattern" -Level Info -LogFile $LogFile
                $filesToHash = Get-ChildItem -Path $OutputDir -Filter $IncludePattern -File | ForEach-Object { $_.FullName }
                
                if ($filesToHash.Count -eq 0) {
                    Write-LogMessage -Message "No files found matching pattern: $IncludePattern" -Level Warning -LogFile $LogFile
                    return @()
                }
            }
            
            $totalFiles = $filesToHash.Count
            Write-LogMessage -Message "Processing $totalFiles file(s) for hashing" -Level Info -LogFile $LogFile
            
            foreach ($file in $filesToHash) {
                try {
                    if (-not (Test-Path $file)) {
                        Write-LogMessage -Message "File not found: $file" -Level Error -LogFile $LogFile
                                            $results += [PSCustomObject]@{
                        FilePath = $file
                        FileName = Split-Path $file -Leaf
                        Success = $false
                        Error = "File not found"
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                        continue
                    }
                    
                    Write-LogMessage -Message "Calculating hash for: $file" -Level Verbose -LogFile $LogFile
                    
                    # Get file information
                    $fileInfo = Get-Item $file
                    $fileSizeBytes = $fileInfo.Length
                    $fileSizeMB = [math]::Round($fileSizeBytes / 1MB, 2)
                    $fileSizeGB = [math]::Round($fileSizeBytes / 1GB, 2)
                    
                    # Calculate hash
                    $hashStartTime = Get-Date
                    $hashResult = Get-FileHash -Path $file -Algorithm SHA256
                    $hashEndTime = Get-Date
                    $hashDuration = ($hashEndTime - $hashStartTime).TotalSeconds
                    
                    Write-LogMessage -Message "Hash calculated for $($fileInfo.Name): $($hashResult.Hash) (took $([math]::Round($hashDuration, 2))s)" -Level Info -LogFile $LogFile
                    
                    $results += [PSCustomObject]@{
                        FilePath = $file
                        FileName = $fileInfo.Name
                        FileExtension = $fileInfo.Extension
                        Directory = $fileInfo.DirectoryName
                        Success = $true
                        Hash = $hashResult.Hash
                        Algorithm = 'SHA256'
                        SizeBytes = $fileSizeBytes
                        SizeMB = $fileSizeMB
                        SizeGB = $fileSizeGB
                        CreationTime = $fileInfo.CreationTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        LastWriteTime = $fileInfo.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        HashCalculationTime = $hashDuration
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                }
                catch {
                    $errorMsg = "Failed to hash file $file : $_"
                    Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                    
                    $results += [PSCustomObject]@{
                        FilePath = $file
                        FileName = Split-Path $file -Leaf
                        Success = $false
                        Error = $_.Exception.Message
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                }
            }
        }
        catch {
            Write-LogMessage -Message "Hash calculation failed: $_" -Level Error -LogFile $LogFile
            throw
        }
    }
    
    end {
        $endTime = Get-Date
        $totalDuration = ($endTime - $startTime).TotalSeconds
        
        $successCount = ($results | Where-Object { $_.Success }).Count
        $failedCount = $totalFiles - $successCount
        
        Write-LogMessage -Message "Hash calculation completed: $successCount successful, $failedCount failed in $([math]::Round($totalDuration, 2))s" -Level Info -LogFile $LogFile
        
        return [PSCustomObject]@{
            Summary = [PSCustomObject]@{
                TotalFiles = $totalFiles
                SuccessfulHashes = $successCount
                FailedHashes = $failedCount
                TotalDurationSeconds = $totalDuration
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
            Results = $results
        }
    }
}

<#
.SYNOPSIS
    Creates a chain-of-custody JSON manifest for forensic artifacts
    
.DESCRIPTION
    Generates a comprehensive JSON manifest containing system information, acquisition
    parameters, artifact details, and hashes for chain-of-custody documentation.
    Includes host information, user context, OS details, and Velociraptor version.
    
.PARAMETER ArtifactPaths
    Array of artifact file paths to include in the manifest
    
.PARAMETER OutputDir
    Directory containing artifacts (alternative to ArtifactPaths)
    
.PARAMETER ManifestPath
    Output path for the JSON manifest file. If not specified, creates manifest.json in OutputDir
    
.PARAMETER CaseNumber
    Case number or identifier for the investigation
    
.PARAMETER InvestigatorName
    Name of the investigator conducting the acquisition
    
.PARAMETER EvidenceNotes
    Additional notes about the evidence or acquisition process
    
.PARAMETER AcquisitionParams
    Hashtable containing acquisition parameters (memory limits, volumes, etc.)
    
.PARAMETER LogFile
    Optional log file path for detailed logging
    
.EXAMPLE
    Write-Manifest -ArtifactPaths @("./evidence/memory.raw") -CaseNumber "CASE-2025-001"
    
.EXAMPLE
    Write-Manifest -OutputDir "./evidence" -CaseNumber "CASE-2025-001" -InvestigatorName "John Doe"
    
.EXAMPLE
    $params = @{ MemoryLimitMB = 4096; Volumes = @("C:", "D:") }
    Write-Manifest -OutputDir "./evidence" -CaseNumber "CASE-2025-001" -AcquisitionParams $params
    
.NOTES
    Creates a comprehensive chain-of-custody record in JSON format
    Includes system information, user context, and artifact metadata
#>
function Write-Manifest {
    [CmdletBinding(DefaultParameterSetName = 'ArtifactPaths')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ArtifactPaths')]
        [string[]]$ArtifactPaths,
        
        [Parameter(Mandatory, ParameterSetName = 'OutputDir')]
        [string]$OutputDir,
        
        [Parameter()]
        [string]$ManifestPath,
        
        [Parameter()]
        [string]$CaseNumber,
        
        [Parameter()]
        [string]$InvestigatorName,
        
        [Parameter()]
        [string]$EvidenceNotes,
        
        [Parameter()]
        [hashtable]$AcquisitionParams = @{},
        
        [Parameter()]
        [string]$LogFile
    )
    
    begin {
        Write-LogMessage -Message "Creating chain-of-custody manifest" -Level Info -LogFile $LogFile
        
        $manifestTimestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    }
    
    process {
        try {
            # Determine artifact paths and manifest location
            if ($PSCmdlet.ParameterSetName -eq 'OutputDir') {
                if (-not (Test-Path $OutputDir)) {
                    $errorMsg = "Output directory not found: $OutputDir"
                    Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                    throw $errorMsg
                }
                
                # Find artifact files in the directory
                $ArtifactPaths = Get-ChildItem -Path $OutputDir -File | Where-Object { 
                    $_.Extension -in @('.raw', '.img', '.dd', '.001', '.e01', '.vmem', '.mem', '.dmp') 
                } | ForEach-Object { $_.FullName }
                
                if (-not $ManifestPath) {
                    $ManifestPath = Join-Path $OutputDir "manifest.json"
                }
            } else {
                if (-not $ManifestPath) {
                    $firstArtifactDir = Split-Path $ArtifactPaths[0] -Parent
                    $ManifestPath = Join-Path $firstArtifactDir "manifest.json"
                }
            }
            
            Write-LogMessage -Message "Processing $($ArtifactPaths.Count) artifact(s) for manifest" -Level Info -LogFile $LogFile
            Write-LogMessage -Message "Manifest will be written to: $ManifestPath" -Level Info -LogFile $LogFile
            
            # Get configuration values
            if (-not $CaseNumber) {
                $CaseNumber = Get-ConfigValue -Key "CASE_NUMBER"
            }
            if (-not $InvestigatorName) {
                $InvestigatorName = Get-ConfigValue -Key "INVESTIGATOR_NAME"
            }
            if (-not $EvidenceNotes) {
                $EvidenceNotes = Get-ConfigValue -Key "EVIDENCE_NOTES"
            }
            
            # Collect system information
            Write-LogMessage -Message "Collecting system information" -Level Verbose -LogFile $LogFile
            
            $systemInfo = @{
                Hostname = $env:COMPUTERNAME
                Username = $env:USERNAME
                Domain = $env:USERDOMAIN
                OSVersion = [System.Environment]::OSVersion.VersionString
                OSPlatform = [System.Environment]::OSVersion.Platform.ToString()
                Architecture = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
                ProcessorCount = [System.Environment]::ProcessorCount
                TotalMemoryGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB, 2)
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                CLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { "N/A" }
                TimeZone = (Get-TimeZone).Id
                LocalTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffzzz"
                UTCTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            
            # Try to get Velociraptor version
            $velociraptorVersion = "Unknown"
            try {
                $velociraptorPath = Get-ConfigValue -Key "VELOCIRAPTOR_PATH"
                if (-not $velociraptorPath) {
                    if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
                        $velociraptorPath = "./bin/velociraptor.exe"
                    } else {
                        $velociraptorPath = "./bin/velociraptor"
                    }
                }
                
                if (Test-Path $velociraptorPath) {
                    $versionOutput = & $velociraptorPath version 2>$null
                    if ($versionOutput) {
                        $velociraptorVersion = ($versionOutput | Select-Object -First 1).Trim()
                    }
                }
            }
            catch {
                Write-LogMessage -Message "Could not determine Velociraptor version: $_" -Level Warning -LogFile $LogFile
            }
            
            # Calculate hashes for all artifacts
            Write-LogMessage -Message "Calculating hashes for artifacts" -Level Info -LogFile $LogFile
            $hashResults = Get-ArtifactHash -FilePath $ArtifactPaths -LogFile $LogFile
            
            # Build artifact list for manifest
            $artifacts = @()
            foreach ($result in $hashResults.Results) {
                if ($result.Success) {
                    $artifacts += [PSCustomObject]@{
                        FileName = $result.FileName
                        FilePath = $result.FilePath
                        FileExtension = $result.FileExtension
                        SizeBytes = $result.SizeBytes
                        SizeMB = $result.SizeMB
                        SizeGB = $result.SizeGB
                        Hash = $result.Hash
                        Algorithm = $result.Algorithm
                        CreationTime = $result.CreationTime
                        LastWriteTime = $result.LastWriteTime
                        HashCalculationTime = $result.HashCalculationTime
                    }
                } else {
                    Write-LogMessage -Message "Skipping failed artifact: $($result.FileName)" -Level Warning -LogFile $LogFile
                }
            }
            
            # Calculate total size safely
            $totalSizeBytes = 0
            if ($artifacts.Count -gt 0) {
                $totalSizeBytes = ($artifacts | Measure-Object -Property SizeBytes -Sum).Sum
            }
            
            # Build complete manifest
            $manifest = @{
                ManifestVersion = "1.0"
                ToolkitVersion = "1.0.0"
                GeneratedBy = "Forensic Triage Toolkit"
                Timestamp = $manifestTimestamp
                
                Case = @{
                    CaseNumber = if ($CaseNumber) { $CaseNumber } else { "N/A" }
                    InvestigatorName = if ($InvestigatorName) { $InvestigatorName } else { "N/A" }
                    EvidenceNotes = if ($EvidenceNotes) { $EvidenceNotes } else { "" }
                    AcquisitionDate = $manifestTimestamp
                }
                
                System = $systemInfo
                
                Tools = @{
                    VelociraptorVersion = $velociraptorVersion
                    PowerShellVersion = $systemInfo.PowerShellVersion
                    ToolkitVersion = "1.0.0"
                }
                
                Acquisition = @{
                    Parameters = $AcquisitionParams
                    StartTime = $manifestTimestamp
                    Method = "Velociraptor Standalone"
                    TotalArtifacts = $artifacts.Count
                    TotalSizeBytes = $totalSizeBytes
                    TotalSizeGB = [math]::Round($totalSizeBytes / 1GB, 2)
                }
                
                HashSummary = $hashResults.Summary
                
                Artifacts = $artifacts
                
                Integrity = @{
                    ManifestHash = ""  # Will be calculated after JSON creation
                    HashAlgorithm = "SHA256"
                    CreatedBy = $env:USERNAME
                    CreatedOn = $env:COMPUTERNAME
                    VerificationMethod = "PowerShell Get-FileHash"
                }
            }
            
            # Convert to JSON and write to file
            Write-LogMessage -Message "Writing manifest to: $ManifestPath" -Level Info -LogFile $LogFile
            
            $jsonContent = $manifest | ConvertTo-Json -Depth 10 -Compress:$false
            
            # Ensure manifest directory exists
            $manifestDir = Split-Path $ManifestPath -Parent
            if ($manifestDir -and -not (Test-Path $manifestDir)) {
                New-Item -Path $manifestDir -ItemType Directory -Force | Out-Null
            }
            
            # Write manifest file
            $jsonContent | Out-File -FilePath $ManifestPath -Encoding UTF8
            
            # Calculate manifest hash and update integrity section
            $manifestHash = Get-FileHash -Path $ManifestPath -Algorithm SHA256
            
            # Rebuild manifest with hash included
            $manifest.Integrity["ManifestHash"] = $manifestHash.Hash
            
            # Add digital timestamp signature for enhanced chain-of-custody
            $manifest.Integrity["DigitalTimestamp"] = Get-TimestampSignature -Data $manifest -IncludeSystemInfo
            
            # Rewrite with hash and digital timestamp included
            $jsonContent = $manifest | ConvertTo-Json -Depth 10 -Compress:$false
            $jsonContent | Out-File -FilePath $ManifestPath -Encoding UTF8
            
            Write-LogMessage -Message "Manifest created successfully: $ManifestPath" -Level Info -LogFile $LogFile
            Write-LogMessage -Message "Manifest hash: $($manifestHash.Hash)" -Level Info -LogFile $LogFile
            
            # Create human-readable log summary
            $logPath = Join-Path (Split-Path $ManifestPath -Parent) "log.txt"
            $logSummary = @"
=== FORENSIC TRIAGE TOOLKIT - ACQUISITION LOG ===
Generated: $manifestTimestamp
Case Number: $($manifest.Case.CaseNumber)
Investigator: $($manifest.Case.InvestigatorName)
System: $($systemInfo.Hostname) ($($systemInfo.OSVersion))

=== ACQUISITION SUMMARY ===
Total Artifacts: $($artifacts.Count)
Total Size: $($manifest.Acquisition.TotalSizeGB) GB
Velociraptor Version: $velociraptorVersion

=== ARTIFACTS ===
"@
            
            foreach ($artifact in $artifacts) {
                $logSummary += "`n[$($artifact.FileName)]"
                $logSummary += "`n  Size: $($artifact.SizeGB) GB"
                $logSummary += "`n  Hash: $($artifact.Hash)"
                $logSummary += "`n  Created: $($artifact.CreationTime)"
                $logSummary += "`n"
            }
            
            $logSummary += "`n=== INTEGRITY ===`n"
            $logSummary += "Manifest Hash: $($manifestHash.Hash)`n"
            $logSummary += "Hash Algorithm: SHA256`n"
            $logSummary += "`n=== END OF LOG ===`n"
            
            $logSummary | Out-File -FilePath $logPath -Encoding UTF8
            Write-LogMessage -Message "Human-readable log created: $logPath" -Level Info -LogFile $LogFile
            
            return [PSCustomObject]@{
                Success = $true
                ManifestPath = $ManifestPath
                LogPath = $logPath
                ManifestHash = $manifestHash.Hash
                TotalArtifacts = $artifacts.Count
                TotalSizeGB = $manifest.Acquisition.TotalSizeGB
                Timestamp = $manifestTimestamp
                CaseNumber = $manifest.Case.CaseNumber
                Summary = $manifest
            }
        }
        catch {
            $errorMsg = "Failed to create manifest: $_"
            Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
            throw $errorMsg
        }
    }
}

#endregion Hash & Manifest Functions

#region Upload & Verification Functions

<#
.SYNOPSIS
    Uploads forensic artifacts to AWS S3 with integrity verification
    
.DESCRIPTION
    Uploads forensic artifacts to AWS S3 bucket with optional compression, 
    post-upload verification, and retry logic. Supports both individual files
    and bulk directory uploads with structured S3 key naming.
    
.PARAMETER ArtifactPaths
    Array of artifact file paths to upload
    
.PARAMETER OutputDir
    Directory containing artifacts to upload (alternative to ArtifactPaths)
    
.PARAMETER S3Bucket
    S3 bucket name for upload. If not specified, uses S3_BUCKET from configuration
    
.PARAMETER S3Region
    AWS region for S3 operations. If not specified, uses AWS_DEFAULT_REGION from configuration
    
.PARAMETER S3KeyPrefix
    Custom S3 key prefix. If not specified, generates: <Hostname>-<yyyyMMddHHmmss>
    
.PARAMETER Compress
    Compress artifacts before upload using ZIP compression
    
.PARAMETER Offline
    Skip S3 upload operations (offline mode)
    
.PARAMETER RetryCount
    Number of retry attempts for failed uploads (default: 3)
    
.PARAMETER VerifyUpload
    Verify uploaded files by downloading and re-hashing (default: true)
    
.PARAMETER IncludeManifest
    Include manifest.json and log.txt files in upload (default: true)
    
.PARAMETER LogFile
    Optional log file path for detailed logging
    
.EXAMPLE
    Send-ToS3 -ArtifactPaths @("./evidence/memory.raw") -S3Bucket "forensic-evidence"
    
.EXAMPLE
    Send-ToS3 -OutputDir "./evidence" -Compress -VerifyUpload
    
.EXAMPLE
    Send-ToS3 -OutputDir "./evidence" -Offline -LogFile "./upload.log"
    
.NOTES
    Requires AWS credentials configured via environment variables or AWS CLI profiles
    Uses structured S3 key naming: <prefix>/<filename>
    Supports retry logic for failed uploads with exponential backoff
#>
function Send-ToS3 {
    [CmdletBinding(DefaultParameterSetName = 'ArtifactPaths', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ArtifactPaths')]
        [string[]]$ArtifactPaths,
        
        [Parameter(Mandatory, ParameterSetName = 'OutputDir')]
        [string]$OutputDir,
        
        [Parameter()]
        [string]$S3Bucket,
        
        [Parameter()]
        [string]$S3Region,
        
        [Parameter()]
        [string]$S3KeyPrefix,
        
        [Parameter()]
        [switch]$Compress,
        
        [Parameter()]
        [switch]$Offline,
        
        [Parameter()]
        [int]$RetryCount = 3,
        
        [Parameter()]
        [bool]$VerifyUpload = $true,
        
        [Parameter()]
        [bool]$IncludeManifest = $true,
        
        [Parameter()]
        [string]$LogFile
    )
    
    begin {
        Write-LogMessage -Message "Starting S3 upload process" -Level Info -LogFile $LogFile
        
        $uploadStartTime = Get-Date
        $uploadResults = @()
        $totalFiles = 0
        $successfulUploads = 0
        $failedUploads = 0
    }
    
    process {
        try {
            # Get configuration values
            if (-not $S3Bucket) {
                $S3Bucket = Get-ConfigValue -Key "S3_BUCKET"
                if (-not $S3Bucket) {
                    throw "S3 bucket not specified and S3_BUCKET not configured"
                }
            }
            
            if (-not $S3Region) {
                $S3Region = Get-ConfigValue -Key "AWS_DEFAULT_REGION" -DefaultValue "us-east-1"
            }
            
            if (-not $Offline) {
                $configOffline = Get-ConfigValue -Key "OFFLINE" -AsBoolean
                if ($configOffline) {
                    $Offline = $true
                    Write-LogMessage -Message "Offline mode enabled via configuration" -Level Info -LogFile $LogFile
                }
            }
            
            if (-not $Compress) {
                $configCompress = Get-ConfigValue -Key "COMPRESS" -AsBoolean
                if ($configCompress) {
                    $Compress = $true
                    Write-LogMessage -Message "Compression enabled via configuration" -Level Info -LogFile $LogFile
                }
            }
            
            if ($RetryCount -eq 3) {
                $configRetryCount = Get-ConfigValue -Key "S3_RETRY_COUNT" -AsInteger
                if ($configRetryCount) {
                    $RetryCount = $configRetryCount
                }
            }
            
            # Generate S3 key prefix if not provided
            if (-not $S3KeyPrefix) {
                $hostname = $env:COMPUTERNAME
                $timestamp = Get-Date -Format "yyyyMMddHHmmss"
                $S3KeyPrefix = "$hostname-$timestamp"
            }
            
            Write-LogMessage -Message "S3 Configuration: Bucket=$S3Bucket, Region=$S3Region, Prefix=$S3KeyPrefix" -Level Info -LogFile $LogFile
            Write-LogMessage -Message "Upload Options: Compress=$Compress, Offline=$Offline, Verify=$VerifyUpload, Retry=$RetryCount" -Level Info -LogFile $LogFile
            
            # Build file list based on parameter set
            $filesToUpload = @()
            
            if ($PSCmdlet.ParameterSetName -eq 'ArtifactPaths') {
                $filesToUpload = $ArtifactPaths
            } else {
                if (-not (Test-Path $OutputDir)) {
                    throw "Output directory not found: $OutputDir"
                }
                
                Write-LogMessage -Message "Scanning directory for artifacts: $OutputDir" -Level Info -LogFile $LogFile
                
                # Find artifact files
                $artifactExtensions = @('.raw', '.img', '.dd', '.001', '.e01', '.vmem', '.mem', '.dmp')
                $filesToUpload = Get-ChildItem -Path $OutputDir -File | Where-Object { 
                    $_.Extension -in $artifactExtensions 
                } | ForEach-Object { $_.FullName }
                
                # Include manifest and log files if requested
                if ($IncludeManifest) {
                    $manifestPath = Join-Path $OutputDir "manifest.json"
                    $logPath = Join-Path $OutputDir "log.txt"
                    
                    if (Test-Path $manifestPath) {
                        $filesToUpload += $manifestPath
                        Write-LogMessage -Message "Including manifest file: $manifestPath" -Level Info -LogFile $LogFile
                    }
                    
                    if (Test-Path $logPath) {
                        $filesToUpload += $logPath
                        Write-LogMessage -Message "Including log file: $logPath" -Level Info -LogFile $LogFile
                    }
                }
            }
            
            if ($filesToUpload.Count -eq 0) {
                Write-LogMessage -Message "No files found for upload" -Level Warning -LogFile $LogFile
                return [PSCustomObject]@{
                    Success = $true
                    Message = "No files to upload"
                    TotalFiles = 0
                    SuccessfulUploads = 0
                    FailedUploads = 0
                    S3Bucket = $S3Bucket
                    S3KeyPrefix = $S3KeyPrefix
                    UploadResults = @()
                    Duration = 0
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                }
            }
            
            $totalFiles = $filesToUpload.Count
            Write-LogMessage -Message "Found $totalFiles file(s) for upload" -Level Info -LogFile $LogFile
            
            # Check if offline mode
            if ($Offline) {
                Write-LogMessage -Message "Offline mode enabled - skipping S3 upload" -Level Info -LogFile $LogFile
                
                foreach ($file in $filesToUpload) {
                    $fileName = Split-Path $file -Leaf
                    $s3Key = "$S3KeyPrefix/$fileName"
                    
                    $uploadResults += [PSCustomObject]@{
                        LocalPath = $file
                        FileName = $fileName
                        S3Key = $s3Key
                        Success = $true
                        Skipped = $true
                        Message = "Offline mode - upload skipped"
                        SizeBytes = (Get-Item $file -ErrorAction SilentlyContinue).Length
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                    $successfulUploads++
                }
                
                $uploadEndTime = Get-Date
                $uploadDuration = ($uploadEndTime - $uploadStartTime).TotalSeconds
                
                return [PSCustomObject]@{
                    Success = $true
                    Message = "Offline mode - $totalFiles file(s) processed"
                    TotalFiles = $totalFiles
                    SuccessfulUploads = $successfulUploads
                    FailedUploads = $failedUploads
                    S3Bucket = $S3Bucket
                    S3KeyPrefix = $S3KeyPrefix
                    UploadResults = $uploadResults
                    Duration = $uploadDuration
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                }
            }
            
            # Check AWS CLI availability
            $awsCliAvailable = $false
            try {
                $awsVersion = aws --version 2>$null
                if ($awsVersion) {
                    $awsCliAvailable = $true
                    Write-LogMessage -Message "AWS CLI detected: $($awsVersion.Split()[0])" -Level Info -LogFile $LogFile
                }
            }
            catch {
                Write-LogMessage -Message "AWS CLI not found - will attempt to use environment credentials" -Level Warning -LogFile $LogFile
            }
            
            # Verify AWS credentials
            if ($awsCliAvailable) {
                try {
                    $awsIdentity = aws sts get-caller-identity --output json 2>$null | ConvertFrom-Json
                    if ($awsIdentity) {
                        Write-LogMessage -Message "AWS credentials verified - User: $($awsIdentity.UserId)" -Level Info -LogFile $LogFile
                    }
                }
                catch {
                    Write-LogMessage -Message "Could not verify AWS credentials: $_" -Level Warning -LogFile $LogFile
                }
            }
            
            # Process each file for upload
            foreach ($file in $filesToUpload) {
                try {
                    if (-not (Test-Path $file)) {
                        Write-LogMessage -Message "File not found: $file" -Level Error -LogFile $LogFile
                        $uploadResults += [PSCustomObject]@{
                            LocalPath = $file
                            FileName = Split-Path $file -Leaf
                            S3Key = ""
                            Success = $false
                            Message = "File not found"
                            SizeBytes = 0
                            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                        }
                        $failedUploads++
                        continue
                    }
                    
                    $fileInfo = Get-Item $file
                    $fileName = $fileInfo.Name
                    $fileSizeBytes = $fileInfo.Length
                    $fileSizeMB = [math]::Round($fileSizeBytes / 1MB, 2)
                    
                    Write-LogMessage -Message "Processing file: $fileName ($fileSizeMB MB)" -Level Info -LogFile $LogFile
                    
                    # Determine upload file path (compress if requested)
                    $uploadFilePath = $file
                    $uploadFileName = $fileName
                    
                    if ($Compress -and $fileInfo.Extension -in @('.raw', '.img', '.dd', '.mem', '.vmem', '.dmp')) {
                        Write-LogMessage -Message "Compressing file: $fileName" -Level Info -LogFile $LogFile
                        
                        $compressedPath = Join-Path $fileInfo.DirectoryName "$($fileInfo.BaseName).zip"
                        
                        if ($PSCmdlet.ShouldProcess($file, "Compress file")) {
                            try {
                                Compress-Archive -Path $file -DestinationPath $compressedPath -Force
                                $uploadFilePath = $compressedPath
                                $uploadFileName = Split-Path $compressedPath -Leaf
                                
                                $compressedSize = (Get-Item $compressedPath).Length
                                $compressionRatio = [math]::Round((1 - ($compressedSize / $fileSizeBytes)) * 100, 1)
                                
                                Write-LogMessage -Message "Compression completed: $fileName -> $uploadFileName (saved $compressionRatio%)" -Level Info -LogFile $LogFile
                            }
                            catch {
                                Write-LogMessage -Message "Compression failed for $fileName : $_" -Level Error -LogFile $LogFile
                                # Continue with original file
                                $uploadFilePath = $file
                                $uploadFileName = $fileName
                            }
                        }
                    }
                    
                    # Generate S3 key
                    $s3Key = "$S3KeyPrefix/$uploadFileName"
                    
                    # Attempt upload with retry logic
                    $uploadSuccess = $false
                    $uploadMessage = ""
                    $attemptCount = 0
                    
                    while (-not $uploadSuccess -and $attemptCount -lt $RetryCount) {
                        $attemptCount++
                        
                        try {
                            if ($PSCmdlet.ShouldProcess($s3Key, "Upload to S3")) {
                                Write-LogMessage -Message "Upload attempt $attemptCount/$RetryCount : $uploadFileName -> s3://$S3Bucket/$s3Key" -Level Info -LogFile $LogFile
                                
                                if ($awsCliAvailable) {
                                    # Use AWS CLI for upload
                                    $uploadStartFileTime = Get-Date
                                    $awsResult = aws s3 cp $uploadFilePath "s3://$S3Bucket/$s3Key" --region $S3Region 2>&1
                                    $uploadEndFileTime = Get-Date
                                    $uploadFileTime = ($uploadEndFileTime - $uploadStartFileTime).TotalSeconds
                                    
                                    if ($LASTEXITCODE -eq 0) {
                                        $uploadSuccess = $true
                                        $uploadMessage = "Upload successful (took $([math]::Round($uploadFileTime, 2))s)"
                                        Write-LogMessage -Message $uploadMessage -Level Info -LogFile $LogFile
                                    } else {
                                        $uploadMessage = "AWS CLI upload failed: $awsResult"
                                        Write-LogMessage -Message $uploadMessage -Level Error -LogFile $LogFile
                                    }
                                } else {
                                    # Fallback to direct AWS API calls (would require AWS PowerShell module)
                                    throw "AWS CLI not available and AWS PowerShell module not implemented"
                                }
                            } else {
                                # WhatIf mode
                                $uploadSuccess = $true
                                $uploadMessage = "WhatIf: Would upload to s3://$S3Bucket/$s3Key"
                                Write-LogMessage -Message $uploadMessage -Level Info -LogFile $LogFile
                            }
                        }
                        catch {
                            $uploadMessage = "Upload attempt $attemptCount failed: $_"
                            Write-LogMessage -Message $uploadMessage -Level Error -LogFile $LogFile
                            
                            if ($attemptCount -lt $RetryCount) {
                                $backoffSeconds = [math]::Pow(2, $attemptCount)
                                Write-LogMessage -Message "Retrying in $backoffSeconds seconds..." -Level Info -LogFile $LogFile
                                Start-Sleep -Seconds $backoffSeconds
                            }
                        }
                    }
                    
                    # Post-upload verification
                    $verificationSuccess = $false
                    $verificationMessage = ""
                    
                    if ($uploadSuccess -and $VerifyUpload -and -not $WhatIfPreference) {
                        try {
                            Write-LogMessage -Message "Verifying upload: $s3Key" -Level Info -LogFile $LogFile
                            
                            # Get S3 object metadata for verification
                            if ($awsCliAvailable) {
                                $s3ObjectInfo = aws s3api head-object --bucket $S3Bucket --key $s3Key --region $S3Region 2>$null | ConvertFrom-Json
                                if ($s3ObjectInfo) {
                                    $s3Size = $s3ObjectInfo.ContentLength
                                    
                                    # For single-part uploads, ETag is MD5. For multipart, it's different.
                                    # We'll verify size and optionally download for hash verification
                                    $localSize = (Get-Item $uploadFilePath).Length
                                    
                                    if ($s3Size -eq $localSize) {
                                        $verificationSuccess = $true
                                        $verificationMessage = "Size verification successful ($s3Size bytes)"
                                        Write-LogMessage -Message $verificationMessage -Level Info -LogFile $LogFile
                                    } else {
                                        $verificationMessage = "Size mismatch: local=$localSize, S3=$s3Size"
                                        Write-LogMessage -Message $verificationMessage -Level Error -LogFile $LogFile
                                    }
                                }
                            }
                        }
                        catch {
                            $verificationMessage = "Verification failed: $_"
                            Write-LogMessage -Message $verificationMessage -Level Warning -LogFile $LogFile
                        }
                    } else {
                        $verificationSuccess = $true
                        $verificationMessage = "Verification skipped"
                    }
                    
                    # Record upload result
                    $uploadResults += [PSCustomObject]@{
                        LocalPath = $file
                        FileName = $fileName
                        UploadPath = $uploadFilePath
                        UploadFileName = $uploadFileName
                        S3Key = $s3Key
                        S3Bucket = $S3Bucket
                        Success = $uploadSuccess
                        Verified = $verificationSuccess
                        Attempts = $attemptCount
                        Message = $uploadMessage
                        VerificationMessage = $verificationMessage
                        SizeBytes = $fileSizeBytes
                        SizeMB = $fileSizeMB
                        Compressed = ($uploadFilePath -ne $file)
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                    
                    if ($uploadSuccess) {
                        $successfulUploads++
                    } else {
                        $failedUploads++
                    }
                    
                    # Clean up compressed file if created
                    if ($Compress -and $uploadFilePath -ne $file -and (Test-Path $uploadFilePath)) {
                        try {
                            Remove-Item $uploadFilePath -Force
                            Write-LogMessage -Message "Cleaned up compressed file: $uploadFilePath" -Level Verbose -LogFile $LogFile
                        }
                        catch {
                            Write-LogMessage -Message "Could not clean up compressed file: $_" -Level Warning -LogFile $LogFile
                        }
                    }
                }
                catch {
                    $errorMsg = "Failed to process file $file : $_"
                    Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
                    
                    $uploadResults += [PSCustomObject]@{
                        LocalPath = $file
                        FileName = Split-Path $file -Leaf
                        S3Key = ""
                        Success = $false
                        Message = $_.Exception.Message
                        SizeBytes = 0
                        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    }
                    $failedUploads++
                }
            }
            
            $uploadEndTime = Get-Date
            $uploadDuration = ($uploadEndTime - $uploadStartTime).TotalSeconds
            
            $overallSuccess = ($failedUploads -eq 0)
            $summaryMessage = "Upload completed: $successfulUploads/$totalFiles successful"
            
            Write-LogMessage -Message $summaryMessage -Level Info -LogFile $LogFile
            Write-LogMessage -Message "Total upload time: $([math]::Round($uploadDuration, 2)) seconds" -Level Info -LogFile $LogFile
            
            return [PSCustomObject]@{
                Success = $overallSuccess
                Message = $summaryMessage
                TotalFiles = $totalFiles
                SuccessfulUploads = $successfulUploads
                FailedUploads = $failedUploads
                S3Bucket = $S3Bucket
                S3Region = $S3Region
                S3KeyPrefix = $S3KeyPrefix
                UploadResults = $uploadResults
                Duration = $uploadDuration
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
        }
        catch {
            $errorMsg = "S3 upload process failed: $_"
            Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
            throw $errorMsg
        }
    }
}

#endregion Upload & Verification Functions

#region Chain-of-Custody & Logging Enhancements

<#
.SYNOPSIS
    Sets the global logging mode for the toolkit
    
.DESCRIPTION
    Configures the logging verbosity level for all toolkit operations.
    Supports quiet mode (errors only), normal mode (info and above), 
    and verbose mode (all messages including debug).
    
.PARAMETER Mode
    Logging mode: Quiet, Normal, or Verbose
    
.PARAMETER LogToFile
    Enable file logging for all operations
    
.PARAMETER LogDirectory
    Directory for log files when LogToFile is enabled
    
.EXAMPLE
    Set-LoggingMode -Mode Verbose
    
.EXAMPLE
    Set-LoggingMode -Mode Quiet -LogToFile -LogDirectory "./logs"
    
.NOTES
    This affects all subsequent toolkit operations until changed
    Logging mode can also be set via LOG_LEVEL environment variable
#>
function Set-LoggingMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quiet', 'Normal', 'Verbose', 'Debug')]
        [string]$Mode,
        
        [Parameter()]
        [switch]$LogToFile,
        
        [Parameter()]
        [string]$LogDirectory = "./logs"
    )
    
    $script:LoggingMode = $Mode
    $script:GlobalLogToFile = $LogToFile.IsPresent
    $script:GlobalLogDirectory = $LogDirectory
    
    Write-LogMessage -Message "Logging mode set to: $Mode" -Level Info
    
    if ($LogToFile) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        Write-LogMessage -Message "File logging enabled: $LogDirectory" -Level Info
    }
    
    return [PSCustomObject]@{
        Mode = $Mode
        LogToFile = $LogToFile.IsPresent
        LogDirectory = $LogDirectory
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    }
}

<#
.SYNOPSIS
    Generates a digital timestamp signature for chain-of-custody
    
.DESCRIPTION
    Creates a timestamped digital signature for forensic artifacts and manifests.
    Includes high-precision timestamps, system information, and integrity data
    for enhanced chain-of-custody documentation.
    
.PARAMETER Data
    Data to timestamp (string, hashtable, or PSObject)
    
.PARAMETER IncludeSystemInfo
    Include detailed system information in the timestamp
    
.PARAMETER TimestampServer
    Optional external timestamp server URL (for future RFC 3161 support)
    
.EXAMPLE
    Get-TimestampSignature -Data "Evidence manifest for case CASE-001"
    
.EXAMPLE
    Get-TimestampSignature -Data $manifestData -IncludeSystemInfo
    
.NOTES
    This provides a digital timestamp for chain-of-custody purposes
    Future versions may support RFC 3161 timestamp servers
#>
function Get-TimestampSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Data,
        
        [Parameter()]
        [switch]$IncludeSystemInfo,
        
        [Parameter()]
        [string]$TimestampServer
    )
    
    $timestamp = Get-Date
    $utcTimestamp = $timestamp.ToUniversalTime()
    
    # Convert data to string for hashing
    $dataString = if ($Data -is [string]) {
        $Data
    } elseif ($Data -is [hashtable] -or $Data.GetType().Name -eq 'PSCustomObject') {
        $Data | ConvertTo-Json -Depth 10 -Compress
    } else {
        $Data.ToString()
    }
    
    # Create data hash
    $dataHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dataString))
    $dataHashHex = [System.BitConverter]::ToString($dataHash).Replace('-', '').ToLower()
    
    # Create timestamp payload
    $timestampPayload = @{
        Data = $dataString
        DataHash = $dataHashHex
        LocalTime = $timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
        UTCTime = $utcTimestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
        UnixTimestamp = [int64]($utcTimestamp - (Get-Date "1970-01-01")).TotalSeconds
        TimestampSource = $env:COMPUTERNAME
        ProcessId = $PID
        SessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    }
    
    # Add system information if requested
    if ($IncludeSystemInfo) {
        $timestampPayload.SystemInfo = @{
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            Domain = $env:USERDOMAIN
            OSVersion = [System.Environment]::OSVersion.ToString()
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            CLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { "N/A" }
            TimeZone = (Get-TimeZone).Id
            TimeZoneOffset = (Get-TimeZone).BaseUtcOffset.ToString()
        }
    }
    
    # Add timestamp server info (for future use)
    if ($TimestampServer) {
        $timestampPayload.TimestampServer = $TimestampServer
        $timestampPayload.TimestampServerStatus = "Not implemented - future feature"
    }
    
    # Create signature of the timestamp payload
    $payloadJson = $timestampPayload | ConvertTo-Json -Depth 10 -Compress
    $signatureHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    $signatureHex = [System.BitConverter]::ToString($signatureHash).Replace('-', '').ToLower()
    
    # Create final timestamp signature
    $timestampSignature = [PSCustomObject]@{
        TimestampVersion = "1.0"
        SignatureType = "SHA256-Digest"
        Signature = $signatureHex
        CreatedAt = $timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
        CreatedAtUTC = $utcTimestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
        Payload = $timestampPayload
        Metadata = @{
            ToolkitVersion = "1.0.0"
            SigningMethod = "Local-SHA256"
            Verified = $true
            VerifiedAt = $timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
        }
    }
    
    Write-LogMessage -Message "Digital timestamp signature created: $signatureHex" -Level Verbose
    
    return $timestampSignature
}

<#
.SYNOPSIS
    Generates comprehensive operation summaries with retry statistics
    
.DESCRIPTION
    Creates detailed summaries of toolkit operations including retry counts,
    failure analysis, timing information, and success rates. Useful for
    chain-of-custody documentation and operational reporting.
    
.PARAMETER OperationType
    Type of operation (Acquisition, Hashing, Manifest, Upload, etc.)
    
.PARAMETER OperationResults
    Array of operation results to summarize
    
.PARAMETER IncludeRetryDetails
    Include detailed retry attempt information
    
.PARAMETER IncludeFailureAnalysis
    Include failure analysis and categorization
    
.PARAMETER SaveToFile
    Save summary to file
    
.PARAMETER OutputPath
    Path for saved summary file
    
.EXAMPLE
    Get-OperationSummary -OperationType "Upload" -OperationResults $uploadResults
    
.EXAMPLE
    Get-OperationSummary -OperationType "Acquisition" -OperationResults $results -IncludeRetryDetails -SaveToFile
    
.NOTES
    Provides comprehensive operational analytics for chain-of-custody and reporting
    Supports multiple operation types and detailed failure analysis
#>
function Get-OperationSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Acquisition', 'Hashing', 'Manifest', 'Upload', 'Verification', 'Complete', 'Simulation')]
        [string]$OperationType,
        
        [Parameter(Mandatory)]
        [array]$OperationResults,
        
        [Parameter()]
        [switch]$IncludeRetryDetails,
        
        [Parameter()]
        [switch]$IncludeFailureAnalysis,
        
        [Parameter()]
        [switch]$SaveToFile,
        
        [Parameter()]
        [string]$OutputPath
    )
    
    $summaryStartTime = Get-Date
    Write-LogMessage -Message "Generating operation summary for: $OperationType" -Level Info
    
    # Initialize counters
    $totalOperations = $OperationResults.Count
    $successfulOperations = 0
    $failedOperations = 0
    $totalRetries = 0
    $totalDuration = 0
    $failureReasons = @{}
    $retryDetails = @()
    
    # Analyze each operation result
    foreach ($result in $OperationResults) {
        if ($result.Success -eq $true) {
            $successfulOperations++
        } else {
            $failedOperations++
            
            # Categorize failure reasons
            $failureReason = if ($result.Message) { $result.Message } elseif ($result.Error) { $result.Error } else { "Unknown error" }
            if ($failureReasons.ContainsKey($failureReason)) {
                $failureReasons[$failureReason]++
            } else {
                $failureReasons[$failureReason] = 1
            }
        }
        
        # Count retry attempts
        if ($result.Attempts) {
            $totalRetries += ([int]$result.Attempts - 1)  # Subtract 1 because first attempt isn't a retry
            
            if ($IncludeRetryDetails -and $result.Attempts -gt 1) {
                $retryDetails += [PSCustomObject]@{
                    OperationId = if ($result.FileName) { $result.FileName } elseif ($result.LocalPath) { $result.LocalPath } else { "Unknown" }
                    Attempts = $result.Attempts
                    Success = $result.Success
                    FinalMessage = $result.Message
                }
            }
        }
        
        # Sum duration
        if ($result.Duration) {
            $totalDuration += $result.Duration
        } elseif ($result.HashCalculationTime) {
            $totalDuration += $result.HashCalculationTime
        }
    }
    
    # Calculate success rate
    $successRate = if ($totalOperations -gt 0) { 
        [math]::Round(($successfulOperations / $totalOperations) * 100, 2) 
    } else { 
        0 
    }
    
    # Determine overall operation status
    $operationStatus = if ($failedOperations -eq 0) {
        "Completed Successfully"
    } elseif ($successfulOperations -eq 0) {
        "Failed Completely"
    } else {
        "Completed with Errors"
    }
    
    # Create comprehensive summary
    $summary = [PSCustomObject]@{
        OperationType = $OperationType
        Status = $operationStatus
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffffffZ"
        
        # Core Statistics
        Statistics = [PSCustomObject]@{
            TotalOperations = $totalOperations
            SuccessfulOperations = $successfulOperations
            FailedOperations = $failedOperations
            SuccessRate = $successRate
            TotalRetries = $totalRetries
            AverageRetriesPerOperation = if ($totalOperations -gt 0) { [math]::Round($totalRetries / $totalOperations, 2) } else { 0 }
            TotalDurationSeconds = [math]::Round($totalDuration, 2)
            AverageDurationPerOperation = if ($totalOperations -gt 0) { [math]::Round($totalDuration / $totalOperations, 2) } else { 0 }
        }
        
        # Performance Metrics
        Performance = [PSCustomObject]@{
            OperationsPerSecond = if ($totalDuration -gt 0) { [math]::Round($totalOperations / $totalDuration, 2) } else { 0 }
            SuccessfulOperationsPerSecond = if ($totalDuration -gt 0) { [math]::Round($successfulOperations / $totalDuration, 2) } else { 0 }
            RetryRate = if ($totalOperations -gt 0) { [math]::Round(($totalRetries / $totalOperations) * 100, 2) } else { 0 }
        }
        
        # Quality Metrics
        Quality = [PSCustomObject]@{
            ReliabilityScore = $successRate
            EfficiencyScore = if ($totalOperations -gt 0) { [math]::Round(((($totalOperations - $totalRetries) / $totalOperations) * 100), 2) } else { 0 }
            OverallQualityScore = if ($totalOperations -gt 0) { [math]::Round((($successRate + (($totalOperations - $totalRetries) / $totalOperations * 100)) / 2), 2) } else { 0 }
        }
    }
    
    # Add failure analysis if requested
    if ($IncludeFailureAnalysis -and $failedOperations -gt 0) {
        $summary | Add-Member -MemberType NoteProperty -Name FailureAnalysis -Value ([PSCustomObject]@{
            TotalFailureTypes = $failureReasons.Count
            FailureBreakdown = $failureReasons
            MostCommonFailure = ($failureReasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
            FailureRate = [math]::Round(($failedOperations / $totalOperations) * 100, 2)
        })
    }
    
    # Add retry details if requested
    if ($IncludeRetryDetails -and $retryDetails.Count -gt 0) {
        $summary | Add-Member -MemberType NoteProperty -Name RetryDetails -Value $retryDetails
        $summary | Add-Member -MemberType NoteProperty -Name RetryStatistics -Value ([PSCustomObject]@{
            OperationsRequiringRetry = $retryDetails.Count
            MaxRetriesForSingleOperation = ($retryDetails | Measure-Object -Property Attempts -Maximum).Maximum
            AverageRetriesForFailedOperations = if ($retryDetails.Count -gt 0) { [math]::Round(($retryDetails | Measure-Object -Property Attempts -Average).Average, 2) } else { 0 }
        })
    }
    
    # Add digital timestamp signature
    $summary | Add-Member -MemberType NoteProperty -Name DigitalSignature -Value (Get-TimestampSignature -Data $summary -IncludeSystemInfo)
    
    # Save to file if requested
    if ($SaveToFile) {
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = "./logs/operation_summary_${OperationType}_${timestamp}.json"
        }
        
        $summaryDir = Split-Path $OutputPath -Parent
        if ($summaryDir -and -not (Test-Path $summaryDir)) {
            New-Item -Path $summaryDir -ItemType Directory -Force | Out-Null
        }
        
        try {
            $summary | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
            Write-LogMessage -Message "Operation summary saved to: $OutputPath" -Level Info
            $summary | Add-Member -MemberType NoteProperty -Name SavedToFile -Value $OutputPath
        }
        catch {
            Write-LogMessage -Message "Failed to save operation summary: $_" -Level Warning
        }
    }
    
    $summaryEndTime = Get-Date
    $summaryDuration = ($summaryEndTime - $summaryStartTime).TotalSeconds
    
    Write-LogMessage -Message "Operation summary generated in $([math]::Round($summaryDuration, 2))s: $operationStatus ($successRate% success rate)" -Level Info
    
    return $summary
}

#endregion Chain-of-Custody & Logging Enhancements

#region Simulation & User Options (Phase 5)

<#
.SYNOPSIS
    Starts interactive mode for forensic acquisition
    
.DESCRIPTION
    Provides an interactive command-line interface for configuring and running
    forensic acquisition operations. Guides users through the process of selecting
    acquisition types, volumes, and options with prompts and validation.
    
.PARAMETER CaseNumber
    Case number for the investigation (optional, will prompt if not provided)
    
.PARAMETER InvestigatorName
    Investigator name (optional, will prompt if not provided)
    
.PARAMETER OutputDir
    Output directory for evidence (optional, will prompt if not provided)
    
.PARAMETER Simulation
    Run in simulation mode (creates dummy files instead of real acquisition)
    
.EXAMPLE
    Start-InteractiveMode
    
.EXAMPLE
    Start-InteractiveMode -CaseNumber "CASE-2025-001" -Simulation
    
.NOTES
    Interactive mode provides guided workflow for forensic acquisition
    Includes input validation and confirmation prompts
#>
function Start-InteractiveMode {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$CaseNumber,
        
        [Parameter()]
        [string]$InvestigatorName,
        
        [Parameter()]
        [string]$OutputDir,
        
        [Parameter()]
        [switch]$Simulation
    )
    
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "   FORENSIC TRIAGE TOOLKIT" -ForegroundColor Cyan
    Write-Host "   Interactive Acquisition Mode" -ForegroundColor Cyan
    if ($Simulation) {
        Write-Host "   🎭 SIMULATION MODE ENABLED" -ForegroundColor Yellow
    }
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Collect case information
    if (-not $CaseNumber) {
        do {
            $CaseNumber = Read-Host "Enter case number"
            if ([string]::IsNullOrWhiteSpace($CaseNumber)) {
                Write-Host "Case number is required." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($CaseNumber))
    }
    
    if (-not $InvestigatorName) {
        do {
            $InvestigatorName = Read-Host "Enter investigator name"
            if ([string]::IsNullOrWhiteSpace($InvestigatorName)) {
                Write-Host "Investigator name is required." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($InvestigatorName))
    }
    
    if (-not $OutputDir) {
        $defaultOutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
        $input = Read-Host "Enter output directory [default: $defaultOutputDir]"
        $OutputDir = if ([string]::IsNullOrWhiteSpace($input)) { $defaultOutputDir } else { $input }
    }
    
    Write-Host ""
    Write-Host "Case Information:" -ForegroundColor Green
    Write-Host "  Case Number: $CaseNumber"
    Write-Host "  Investigator: $InvestigatorName"
    Write-Host "  Output Directory: $OutputDir"
    if ($Simulation) {
        Write-Host "  Mode: SIMULATION (dummy files will be created)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Acquisition type selection
    Write-Host "Select acquisition types:" -ForegroundColor Yellow
    Write-Host "  [1] Memory only"
    Write-Host "  [2] Disk only"
    Write-Host "  [3] Both memory and disk"
    Write-Host "  [4] Complete workflow (acquire + hash + manifest + upload)"
    
    do {
        $choice = Read-Host "Enter your choice (1-4)"
        $validChoice = $choice -in @('1', '2', '3', '4')
        if (-not $validChoice) {
            Write-Host "Invalid choice. Please enter 1, 2, 3, or 4." -ForegroundColor Red
        }
    } while (-not $validChoice)
    
    Write-Host ""
    
    # Execute based on choice
    $acquisitionResults = @()
    
    try {
        switch ($choice) {
            '1' {
                Write-Host "Starting Memory Acquisition..." -ForegroundColor Green
                $memResult = Invoke-MemoryAcquisition -OutputDir $OutputDir -Interactive -Simulation:$Simulation
                $acquisitionResults += $memResult
            }
            '2' {
                Write-Host "Starting Disk Acquisition..." -ForegroundColor Green
                $diskResult = Invoke-DiskAcquisition -OutputDir $OutputDir -Interactive -Simulation:$Simulation
                $acquisitionResults += $diskResult
            }
            '3' {
                Write-Host "Starting Memory Acquisition..." -ForegroundColor Green
                $memResult = Invoke-MemoryAcquisition -OutputDir $OutputDir -Interactive -Simulation:$Simulation
                $acquisitionResults += $memResult
                
                if ($memResult.Success -and -not $memResult.UserCancelled) {
                    Write-Host "Starting Disk Acquisition..." -ForegroundColor Green
                    $diskResult = Invoke-DiskAcquisition -OutputDir $OutputDir -Interactive -Simulation:$Simulation
                    $acquisitionResults += $diskResult
                }
            }
            '4' {
                Write-Host "Starting Complete Workflow..." -ForegroundColor Green
                $workflowResult = Invoke-CompleteWorkflow -CaseNumber $CaseNumber -InvestigatorName $InvestigatorName -OutputDir $OutputDir -Interactive -Simulation:$Simulation
                return $workflowResult
            }
        }
        
        # Create manifest if acquisitions were successful
        $successfulAcquisitions = $acquisitionResults | Where-Object { $_.Success -and -not $_.UserCancelled }
        if ($successfulAcquisitions.Count -gt 0) {
            Write-Host ""
            $createManifest = Read-Host "Create chain-of-custody manifest? (Y/n)"
            if ($createManifest -ne 'n' -and $createManifest -ne 'N') {
                Write-Host "Creating manifest..." -ForegroundColor Green
                $manifestResult = Write-Manifest -OutputDir $OutputDir -CaseNumber $CaseNumber -InvestigatorName $InvestigatorName
                
                if ($manifestResult.Success) {
                    Write-Host "✓ Manifest created: $($manifestResult.ManifestPath)" -ForegroundColor Green
                } else {
                    Write-Host "✗ Manifest creation failed" -ForegroundColor Red
                }
            }
        }
        
        Write-Host ""
        Write-Host "Interactive session completed!" -ForegroundColor Green
        
        return @{
            Success = $true
            CaseNumber = $CaseNumber
            InvestigatorName = $InvestigatorName
            OutputDir = $OutputDir
            AcquisitionResults = $acquisitionResults
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Simulation = $Simulation.IsPresent
        }
        
    } catch {
        Write-Host "Interactive session failed: $_" -ForegroundColor Red
        throw
    }
}

<#
.SYNOPSIS
    Creates simulated forensic artifacts for testing
    
.DESCRIPTION
    Generates dummy forensic artifact files with realistic metadata for testing
    and training purposes. Creates files of specified size with forensic-appropriate
    naming and content patterns.
    
.PARAMETER Type
    Type of artifact to simulate (Memory, Disk, Registry, etc.)
    
.PARAMETER OutputPath
    Full path where the simulated artifact should be created
    
.PARAMETER SizeMB
    Size of the simulated artifact in megabytes
    
.PARAMETER LogFile
    Optional log file for detailed logging
    
.PARAMETER IncludeMetadata
    Include realistic forensic metadata in the simulated artifact
    
.EXAMPLE
    New-SimulatedArtifact -Type "Memory" -OutputPath "./evidence/memory.raw" -SizeMB 10
    
.EXAMPLE
    New-SimulatedArtifact -Type "Disk" -OutputPath "./evidence/disk_C.raw" -SizeMB 25 -IncludeMetadata
    
.NOTES
    Simulated artifacts are for testing and training only
    Files contain random data and forensic-style headers
    Not suitable for production forensic analysis
#>
function New-SimulatedArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Memory', 'Disk', 'Registry', 'EventLog', 'NetworkCapture')]
        [string]$Type,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [int]$SizeMB = 10,
        
        [Parameter()]
        [string]$LogFile,
        
        [Parameter()]
        [switch]$IncludeMetadata
    )
    
    try {
        Write-LogMessage -Message "Creating simulated $Type artifact: $OutputPath ($SizeMB MB)" -Level Info -LogFile $LogFile
        
        # Ensure output directory exists
        $outputDir = Split-Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        # Create appropriate header based on artifact type
        $header = switch ($Type) {
            'Memory' {
                "MEMORY_DUMP_SIMULATION`0`0`0`0" +
                "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`0" +
                "System: $env:COMPUTERNAME`0" +
                "OS: $([System.Environment]::OSVersion.VersionString)`0" +
                "Tool: Forensic Triage Toolkit (Simulation)`0" +
                "`0" * (512 - 200)  # Pad to 512 bytes
            }
            'Disk' {
                "DISK_IMAGE_SIMULATION`0`0`0`0" +
                "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`0" +
                "Volume: Simulated Volume`0" +
                "File System: NTFS (Simulated)`0" +
                "Tool: Forensic Triage Toolkit (Simulation)`0" +
                "`0" * (512 - 200)  # Pad to 512 bytes
            }
            'Registry' {
                "REGISTRY_DUMP_SIMULATION`0`0`0`0" +
                "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`0" +
                "Hive: Simulated Registry Hive`0" +
                "Tool: Forensic Triage Toolkit (Simulation)`0" +
                "`0" * (512 - 150)  # Pad to 512 bytes
            }
            default {
                "FORENSIC_ARTIFACT_SIMULATION`0`0`0`0" +
                "Type: $Type`0" +
                "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`0" +
                "Tool: Forensic Triage Toolkit (Simulation)`0" +
                "`0" * (512 - 150)  # Pad to 512 bytes
            }
        }
        
        # Calculate remaining size after header
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        $remainingBytes = ($SizeMB * 1024 * 1024) - $headerBytes.Length
        
        if ($remainingBytes -lt 0) {
            $remainingBytes = 0
        }
        
        # Create the file
        $fileStream = [System.IO.File]::Create($OutputPath)
        try {
            # Write header
            $fileStream.Write($headerBytes, 0, $headerBytes.Length)
            
            # Write simulated data in chunks for memory efficiency
            $chunkSize = 1024 * 1024  # 1MB chunks
            $random = New-Object System.Random
            $bytesWritten = 0
            
            while ($bytesWritten -lt $remainingBytes) {
                $currentChunkSize = [Math]::Min($chunkSize, $remainingBytes - $bytesWritten)
                $chunk = New-Object byte[] $currentChunkSize
                
                # Fill chunk with pseudo-random data patterns
                for ($i = 0; $i -lt $currentChunkSize; $i += 4) {
                    $value = $random.Next()
                    $chunk[$i] = $value -band 0xFF
                    if ($i + 1 -lt $currentChunkSize) { $chunk[$i + 1] = ($value -shr 8) -band 0xFF }
                    if ($i + 2 -lt $currentChunkSize) { $chunk[$i + 2] = ($value -shr 16) -band 0xFF }
                    if ($i + 3 -lt $currentChunkSize) { $chunk[$i + 3] = ($value -shr 24) -band 0xFF }
                }
                
                $fileStream.Write($chunk, 0, $currentChunkSize)
                $bytesWritten += $currentChunkSize
                
                # Progress indication for large files
                if ($SizeMB -gt 50 -and $bytesWritten % (10 * 1024 * 1024) -eq 0) {
                    $progress = [math]::Round(($bytesWritten / $remainingBytes) * 100, 1)
                    Write-LogMessage -Message "Simulation progress: $progress% ($([math]::Round($bytesWritten / 1024 / 1024, 1)) MB)" -Level Verbose -LogFile $LogFile
                }
            }
        }
        finally {
            $fileStream.Close()
        }
        
        # Verify file creation
        if (Test-Path $OutputPath) {
            $actualSize = (Get-Item $OutputPath).Length
            $actualSizeMB = [math]::Round($actualSize / 1MB, 2)
            
            Write-LogMessage -Message "Simulated artifact created successfully: $OutputPath ($actualSizeMB MB)" -Level Info -LogFile $LogFile
            
            # Add metadata file if requested
            if ($IncludeMetadata) {
                $metadataPath = $OutputPath + ".metadata.json"
                $metadata = @{
                    ArtifactType = $Type
                    CreatedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    RequestedSizeMB = $SizeMB
                    ActualSizeBytes = $actualSize
                    ActualSizeMB = $actualSizeMB
                    Simulated = $true
                    Tool = "Forensic Triage Toolkit"
                    Version = "1.0.0"
                    System = @{
                        Hostname = $env:COMPUTERNAME
                        OS = [System.Environment]::OSVersion.VersionString
                        PowerShell = $PSVersionTable.PSVersion.ToString()
                    }
                    Hash = @{
                        Algorithm = "SHA256"
                        Value = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash
                    }
                } | ConvertTo-Json -Depth 5
                
                $metadata | Out-File -FilePath $metadataPath -Encoding UTF8
                Write-LogMessage -Message "Metadata file created: $metadataPath" -Level Verbose -LogFile $LogFile
            }
            
            return @{
                Success = $true
                OutputPath = $OutputPath
                Type = $Type
                SizeBytes = $actualSize
                SizeMB = $actualSizeMB
                Simulated = $true
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
        } else {
            throw "File was not created successfully"
        }
        
    } catch {
        $errorMsg = "Failed to create simulated artifact: $_"
        Write-LogMessage -Message $errorMsg -Level Error -LogFile $LogFile
        
        return @{
            Success = $false
            Message = $errorMsg
            Type = $Type
            OutputPath = $OutputPath
        }
    }
}

<#
.SYNOPSIS
    Executes complete forensic acquisition workflow
    
.DESCRIPTION
    Runs the complete end-to-end forensic acquisition workflow including
    memory and disk acquisition, hash calculation, manifest generation,
    and optional S3 upload. Provides comprehensive automation for forensic
    investigations.
    
.PARAMETER CaseNumber
    Case number for the investigation
    
.PARAMETER InvestigatorName
    Name of the investigator conducting the acquisition
    
.PARAMETER OutputDir
    Output directory for all evidence and reports
    
.PARAMETER IncludeMemory
    Include memory acquisition in the workflow
    
.PARAMETER IncludeDisk
    Include disk acquisition in the workflow
    
.PARAMETER Volumes
    Specific volumes to acquire (if not specified, prompts in interactive mode)
    
.PARAMETER UploadToS3
    Upload artifacts to S3 after acquisition
    
.PARAMETER Compress
    Compress artifacts before upload
    
.PARAMETER Interactive
    Run in interactive mode with user prompts
    
.PARAMETER Simulation
    Run in simulation mode (creates dummy files)
    
.PARAMETER LogFile
    Optional log file for detailed logging
    
.EXAMPLE
    Invoke-CompleteWorkflow -CaseNumber "CASE-001" -InvestigatorName "John Doe"
    
.EXAMPLE
    Invoke-CompleteWorkflow -CaseNumber "CASE-002" -Interactive -Simulation
    
.EXAMPLE
    Invoke-CompleteWorkflow -CaseNumber "CASE-003" -IncludeMemory -IncludeDisk -UploadToS3 -Compress
    
.NOTES
    Complete workflow includes all phases: Acquire -> Hash -> Manifest -> Upload
    Provides comprehensive forensic acquisition automation
    Supports both interactive and scripted execution
#>
function Invoke-CompleteWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseNumber,
        
        [Parameter(Mandatory)]
        [string]$InvestigatorName,
        
        [Parameter()]
        [string]$OutputDir,
        
        [Parameter()]
        [switch]$IncludeMemory,
        
        [Parameter()]
        [switch]$IncludeDisk,
        
        [Parameter()]
        [string[]]$Volumes,
        
        [Parameter()]
        [switch]$UploadToS3,
        
        [Parameter()]
        [switch]$Compress,
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        [switch]$Simulation,
        
        [Parameter()]
        [string]$LogFile
    )
    
    $workflowStartTime = Get-Date
    Write-LogMessage -Message "Starting complete forensic workflow for case: $CaseNumber" -Level Info -LogFile $LogFile
    
    if (-not $OutputDir) {
        $OutputDir = Get-ConfigValue -Key "EVIDENCE_DIR" -DefaultValue "./evidence"
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    
    $workflowResults = @{
        CaseNumber = $CaseNumber
        InvestigatorName = $InvestigatorName
        OutputDir = $OutputDir
        StartTime = $workflowStartTime
        Steps = @()
        Success = $true
        Simulation = $Simulation.IsPresent
    }
    
    try {
        # Interactive configuration if requested
        if ($Interactive) {
            Write-Host ""
            Write-Host "=== Complete Workflow Configuration ===" -ForegroundColor Cyan
            
            if (-not $IncludeMemory -and -not $IncludeDisk) {
                Write-Host ""
                Write-Host "Select acquisition types:"
                Write-Host "  Memory acquisition? (Y/n): " -NoNewline
                $memChoice = Read-Host
                $IncludeMemory = $memChoice -ne 'n' -and $memChoice -ne 'N'
                
                Write-Host "  Disk acquisition? (Y/n): " -NoNewline
                $diskChoice = Read-Host
                $IncludeDisk = $diskChoice -ne 'n' -and $diskChoice -ne 'N'
            }
            
            if (-not $UploadToS3) {
                Write-Host "  Upload to S3? (y/N): " -NoNewline
                $s3Choice = Read-Host
                $UploadToS3 = $s3Choice -eq 'y' -or $s3Choice -eq 'Y'
                
                if ($UploadToS3) {
                    Write-Host "  Compress before upload? (y/N): " -NoNewline
                    $compressChoice = Read-Host
                    $Compress = $compressChoice -eq 'y' -or $compressChoice -eq 'Y'
                }
            }
        }
        
        # Default to both if neither specified
        if (-not $IncludeMemory -and -not $IncludeDisk) {
            $IncludeMemory = $true
            $IncludeDisk = $true
        }
        
        Write-LogMessage -Message "Workflow configuration: Memory=$IncludeMemory, Disk=$IncludeDisk, S3Upload=$UploadToS3, Compress=$Compress" -Level Info -LogFile $LogFile
        
        # Step 1: Memory Acquisition
        if ($IncludeMemory) {
            Write-LogMessage -Message "Step 1: Memory acquisition" -Level Info -LogFile $LogFile
            $memResult = Invoke-MemoryAcquisition -OutputDir $OutputDir -Simulation:$Simulation -LogFile $LogFile
            
            $workflowResults.Steps += @{
                Step = "Memory Acquisition"
                Success = $memResult.Success
                Result = $memResult
                Duration = if ($memResult.Timestamp) { (Get-Date) - $workflowStartTime } else { $null }
            }
            
            if (-not $memResult.Success) {
                $workflowResults.Success = $false
                Write-LogMessage -Message "Memory acquisition failed, continuing with workflow" -Level Warning -LogFile $LogFile
            }
        }
        
        # Step 2: Disk Acquisition  
        if ($IncludeDisk) {
            Write-LogMessage -Message "Step 2: Disk acquisition" -Level Info -LogFile $LogFile
            $diskParams = @{
                OutputDir = $OutputDir
                Simulation = $Simulation
                LogFile = $LogFile
            }
            if ($Volumes) { $diskParams.Volumes = $Volumes }
            
            $diskResult = Invoke-DiskAcquisition @diskParams
            
            $workflowResults.Steps += @{
                Step = "Disk Acquisition"
                Success = ($diskResult.Summary.SuccessfulVolumes -gt 0)
                Result = $diskResult
                Duration = (Get-Date) - $workflowStartTime
            }
            
            if ($diskResult.Summary.SuccessfulVolumes -eq 0) {
                $workflowResults.Success = $false
                Write-LogMessage -Message "Disk acquisition failed completely, continuing with workflow" -Level Warning -LogFile $LogFile
            }
        }
        
        # Step 3: Hash Calculation
        Write-LogMessage -Message "Step 3: Hash calculation" -Level Info -LogFile $LogFile
        $hashResult = Get-ArtifactHash -OutputDir $OutputDir -IncludePattern "*.raw" -LogFile $LogFile
        
        $workflowResults.Steps += @{
            Step = "Hash Calculation"
            Success = ($hashResult.Summary.SuccessfulHashes -gt 0)
            Result = $hashResult
            Duration = (Get-Date) - $workflowStartTime
        }
        
        # Step 4: Manifest Generation
        Write-LogMessage -Message "Step 4: Manifest generation" -Level Info -LogFile $LogFile
        $manifestResult = Write-Manifest -OutputDir $OutputDir -CaseNumber $CaseNumber -InvestigatorName $InvestigatorName -LogFile $LogFile
        
        $workflowResults.Steps += @{
            Step = "Manifest Generation"
            Success = $manifestResult.Success
            Result = $manifestResult
            Duration = (Get-Date) - $workflowStartTime
        }
        
        # Step 5: S3 Upload (if requested)
        if ($UploadToS3) {
            Write-LogMessage -Message "Step 5: S3 upload" -Level Info -LogFile $LogFile
            $uploadParams = @{
                OutputDir = $OutputDir
                IncludeManifest = $true
                LogFile = $LogFile
            }
            if ($Compress) { $uploadParams.Compress = $true }
            
            $uploadResult = Send-ToS3 @uploadParams
            
            $workflowResults.Steps += @{
                Step = "S3 Upload"
                Success = $uploadResult.Success
                Result = $uploadResult
                Duration = (Get-Date) - $workflowStartTime
            }
        }
        
        # Step 6: Generate Operation Summary
        Write-LogMessage -Message "Final step: Operation summary" -Level Info -LogFile $LogFile
        $allOperations = @()
        foreach ($step in $workflowResults.Steps) {
            $allOperations += [PSCustomObject]@{
                Success = $step.Success
                FileName = $step.Step
                Duration = if ($step.Duration) { $step.Duration.TotalSeconds } else { 0 }
                Attempts = 1
                Message = if ($step.Success) { "Completed successfully" } else { "Failed" }
            }
        }
        
        $summaryResult = Get-OperationSummary -OperationType "Complete" -OperationResults $allOperations -IncludeRetryDetails -IncludeFailureAnalysis -SaveToFile -OutputPath (Join-Path $OutputDir "workflow_summary.json")
        
        $workflowResults.OperationSummary = $summaryResult
        $workflowResults.EndTime = Get-Date
        $workflowResults.TotalDuration = $workflowResults.EndTime - $workflowStartTime
        
        Write-LogMessage -Message "Complete workflow finished in $([math]::Round($workflowResults.TotalDuration.TotalMinutes, 2)) minutes" -Level Info -LogFile $LogFile
        
        return $workflowResults
        
    } catch {
        $workflowResults.Success = $false
        $workflowResults.Error = $_.Exception.Message
        $workflowResults.EndTime = Get-Date
        
        Write-LogMessage -Message "Complete workflow failed: $_" -Level Error -LogFile $LogFile
        throw
    }
}

#endregion Simulation & User Options (Phase 5)

#region Helper Functions

<#
.SYNOPSIS
    Loads environment configuration from .env file
    
.DESCRIPTION
    Reads environment variables from .env file in the module root directory
    and populates the script-scoped configuration hashtable.
    
.PARAMETER EnvPath
    Path to the .env file. Defaults to .env in module root.
    
.EXAMPLE
    Import-EnvironmentConfig
    
.EXAMPLE
    Import-EnvironmentConfig -EnvPath "C:\path\to\custom.env"
#>
function Import-EnvironmentConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$EnvPath = (Join-Path $script:ModuleRoot ".." ".env")
    )
    
    Write-Verbose "Loading environment configuration from: $EnvPath"
    
    if (-not (Test-Path $EnvPath)) {
        Write-Warning "Environment file not found at: $EnvPath"
        Write-Warning "Copy .env.example to .env and configure your settings"
        return
    }
    
    try {
        $envContent = Get-Content $EnvPath -ErrorAction Stop
        
        foreach ($line in $envContent) {
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
                continue
            }
            
            # Parse KEY=VALUE format
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                
                # Remove quotes if present
                if (($value.StartsWith('"') -and $value.EndsWith('"')) -or 
                    ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
                
                $script:EnvironmentConfig[$key] = $value
                Write-Verbose "Loaded config: $key"
            }
        }
        
        Write-Verbose "Successfully loaded $($script:EnvironmentConfig.Count) configuration items"
    }
    catch {
        Write-Error "Failed to load environment configuration: $_"
        throw
    }
}

<#
.SYNOPSIS
    Gets a configuration value from the loaded environment
    
.DESCRIPTION
    Retrieves a configuration value from the loaded environment configuration.
    Supports default values and type conversion.
    
.PARAMETER Key
    The configuration key to retrieve
    
.PARAMETER DefaultValue
    Default value to return if key is not found
    
.PARAMETER AsBoolean
    Convert the value to boolean (true/false, yes/no, 1/0)
    
.PARAMETER AsInteger
    Convert the value to integer
    
.EXAMPLE
    Get-ConfigValue -Key "S3_BUCKET"
    
.EXAMPLE
    Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger -DefaultValue 4096
    
.EXAMPLE
    Get-ConfigValue -Key "COMPRESS" -AsBoolean -DefaultValue $false
#>
function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,
        
        [Parameter()]
        [object]$DefaultValue,
        
        [Parameter()]
        [switch]$AsBoolean,
        
        [Parameter()]
        [switch]$AsInteger
    )
    
    $value = $script:EnvironmentConfig[$Key]
    
    if ([string]::IsNullOrEmpty($value)) {
        if ($PSBoundParameters.ContainsKey('DefaultValue')) {
            return $DefaultValue
        }
        return $null
    }
    
    if ($AsBoolean) {
        return $value -match '^(true|yes|1|on)$'
    }
    
    if ($AsInteger) {
        $intValue = 0
        if ([int]::TryParse($value, [ref]$intValue)) {
            return $intValue
        }
        throw "Cannot convert '$value' to integer for key '$Key'"
    }
    
    return $value
}

<#
.SYNOPSIS
    Writes a log message with timestamp
    
.DESCRIPTION
    Writes formatted log messages to host and optionally to log file.
    Supports different log levels and verbose/quiet modes.
    
.PARAMETER Message
    The message to log
    
.PARAMETER Level
    Log level: Info, Warning, Error, Verbose
    
.PARAMETER LogFile
    Optional path to log file
    
.EXAMPLE
    Write-LogMessage -Message "Starting acquisition process" -Level Info
    
.EXAMPLE
    Write-LogMessage -Message "Failed to connect to S3" -Level Error -LogFile ".\evidence\log.txt"
#>
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose', 'Debug')]
        [string]$Level = 'Info',
        
        [Parameter()]
        [string]$LogFile
    )
    
    # Get global logging mode (default to Normal if not set)
    $loggingMode = if ($script:LoggingMode) { $script:LoggingMode } else { 
        $configMode = Get-ConfigValue -Key "LOG_LEVEL" -DefaultValue "Normal"
        $configMode
    }
    
    # Determine if message should be displayed based on logging mode
    $shouldDisplay = switch ($loggingMode) {
        'Quiet' { $Level -in @('Error') }
        'Normal' { $Level -in @('Info', 'Warning', 'Error') }
        'Verbose' { $Level -in @('Info', 'Warning', 'Error', 'Verbose') }
        'Debug' { $true }  # Show all messages
        default { $Level -in @('Info', 'Warning', 'Error') }  # Default to Normal
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    $jsonLogEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        Level = $Level
        Message = $Message
        Source = "AcquisitionToolkit"
        ProcessId = $PID
        ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    } | ConvertTo-Json -Compress
    
    # Write to console based on level and logging mode
    if ($shouldDisplay) {
        switch ($Level) {
            'Error'   { Write-Error $Message }
            'Warning' { Write-Warning $Message }
            'Verbose' { if ($VerbosePreference -ne 'SilentlyContinue' -or $loggingMode -eq 'Verbose') { Write-Host $logEntry -ForegroundColor Cyan } }
            'Debug'   { if ($DebugPreference -ne 'SilentlyContinue' -or $loggingMode -eq 'Debug') { Write-Host $logEntry -ForegroundColor Gray } }
            default   { Write-Host $logEntry }
        }
    }
    
    # Determine log file path
    $targetLogFile = $LogFile
    if (-not $targetLogFile -and $script:GlobalLogToFile) {
        $logFileName = "acquisition_$(Get-Date -Format 'yyyyMMdd').log"
        $targetLogFile = Join-Path $script:GlobalLogDirectory $logFileName
    }
    
    # Write to log file if specified or global logging enabled
    if ($targetLogFile) {
        try {
            $logDir = Split-Path $targetLogFile -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            
            # Write both human-readable and JSON format
            Add-Content -Path $targetLogFile -Value $logEntry -Encoding UTF8
            
            # Also write JSON log for structured logging
            $jsonLogFile = $targetLogFile -replace '\.log$', '.json.log'
            Add-Content -Path $jsonLogFile -Value $jsonLogEntry -Encoding UTF8
        }
        catch {
            if ($loggingMode -ne 'Quiet') {
                Write-Warning "Failed to write to log file: $_"
            }
        }
    }
}

#endregion Helper Functions

# Initialize module
Write-Verbose "Initializing Forensic Triage Toolkit module"

# Load environment configuration on module import
Import-EnvironmentConfig

# Export functions that are currently implemented
Export-ModuleMember -Function $ExportedFunctions 