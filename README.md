# Forensic Triage Toolkit

**End-to-end automation for disk & RAM acquisition** using Velociraptor with SHA-256 hashing, chain-of-custody JSON manifest, optional encryption/compression, S3 upload, evidence retention, and detailed logging.

[![CI/CD Pipeline](https://github.com/Fristali/Forensic-Triage-Toolkit/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/Fristali/Forensic-Triage-Toolkit/actions)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://your-org.github.io/forensic-triage-toolkit/)
[![Coverage](https://img.shields.io/badge/coverage-85%25+-brightgreen.svg)](#)
[![Security](https://img.shields.io/badge/security-scanned-green.svg)](#)

## 🎯 Quick Start

### Prerequisites

**Required Software:**
- **PowerShell 7.0+** - [Download here](https://github.com/PowerShell/PowerShell/releases)
- **Velociraptor** - [Download standalone binary](https://github.com/Velocidex/velociraptor/releases)
- **AWS CLI** (optional) - [Installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

**System Requirements:**
- Windows 10/11 or Windows Server (primary support)
- Linux/macOS (via PowerShell Core)
- Administrative privileges for memory/disk acquisition
- Internet connectivity for S3 uploads (unless using `-Offline` mode)

**AWS Setup:**
- S3 bucket with appropriate IAM permissions
- AWS credentials configured via AWS CLI or environment variables

### Installation & Setup

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Fristali/Forensic-Triage-Toolkit
   cd forensic-triage-toolkit
   ```

2. **Install Velociraptor binary:**
   ```powershell
   # Create bin directory and download Velociraptor
   New-Item -Path "./bin" -ItemType Directory -Force
   # Download velociraptor.exe to ./bin/ directory
   # Or set VELOCIRAPTOR_PATH in .env to custom location
   ```

3. **Configure environment:**
   ```powershell
   # Copy and edit configuration
   Copy-Item ".env.example" ".env"
   notepad .env  # Edit with your settings
   ```

4. **Import the module:**
   ```powershell
   Import-Module "./src/AcquisitionToolkit.psm1" -Force
   ```

### Basic Usage

```powershell
# Import the module
Import-Module "./src/AcquisitionToolkit.psm1" -Force

# Verify configuration loaded
Get-ConfigValue -Key "S3_BUCKET"

# Example usage (Phase 1 - Available now):
Invoke-MemoryAcquisition -OutputDir "./evidence" -MemoryLimitMB 2048
Invoke-DiskAcquisition -Volumes @("C:", "D:") -OutputDir "./evidence"
```

## 📁 Project Structure

```
forensic-triage-toolkit/
├── src/
│   └── AcquisitionToolkit.psm1    # Main PowerShell module
├── bin/                           # Velociraptor binaries (user-provided)
├── tests/                         # Unit and integration tests
├── evidence/                      # Default output directory
├── .env.example                   # Environment configuration template
├── .env                          # Your configuration (create from example)
├── Phases.md                     # Implementation roadmap
└── README.md                     # This file
```

## ⚙️ Configuration

Edit `.env` file with your settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `S3_BUCKET` | AWS S3 bucket for evidence storage | `forensic-evidence` |
| `AWS_DEFAULT_REGION` | AWS region | `us-east-1` |
| `MEMORY_LIMIT_MB` | Memory acquisition limit in MB | `4096` |
| `EVIDENCE_DIR` | Local evidence directory | `./evidence` |
| `COMPRESS` | Compress artifacts before upload | `false` |
| `OFFLINE` | Skip S3 upload (offline mode) | `false` |

See `.env.example` for complete configuration options.

## 🧪 Testing & Build

### Automated Testing
```powershell
# Run comprehensive build with all tests
.\build.ps1 -Task All -Configuration Release

# Run only unit tests
.\build.ps1 -Task Test

# Run code analysis only
.\build.ps1 -Task Analyze

# Generate detailed reports
.\build.ps1 -Task All -GenerateReports
```

### Manual Testing
```powershell
# Run Pester tests manually
Invoke-Pester -Path "./tests/"

# Run Phase 5 verification
.\test_phase5.ps1
```

### CI/CD Pipeline
The project includes comprehensive GitHub Actions workflows:
- **Multi-platform testing** (Windows, Linux, macOS)
- **Code quality analysis** (PSScriptAnalyzer)
- **Security scanning** (Trivy)
- **Automated package building**
- **Documentation publishing**

## 🚀 Development Phases

This toolkit is developed in phases:

- ✅ **Phase 0**: Project Skeleton & Config *(complete)*
- ✅ **Phase 1**: Acquisition Core (Velociraptor integration) *(complete)*
- ✅ **Phase 2**: Hash & Manifest generation *(complete)*
- ✅ **Phase 3**: S3 Upload & Verification *(complete)*
- ✅ **Phase 4**: Chain-of-Custody & Enhanced logging *(complete)*
- ✅ **Phase 5**: Simulation & User Options *(complete)*
- ✅ **Phase 6**: Documentation & CI/CD *(complete)*

See `Phases.md` for detailed implementation plan.

## 📋 Current Capabilities (Phase 0 + 1 + 2 + 3 + 4 + 5)

### Available Functions

**Configuration & Logging:**
- `Import-EnvironmentConfig` - Load configuration from `.env` file
- `Get-ConfigValue` - Retrieve configuration values with type conversion
- `Write-LogMessage` - Enhanced structured logging with verbosity modes and JSON output

**Forensic Acquisition (Phase 1):**
- `Invoke-MemoryAcquisition` - Memory acquisition using Velociraptor
- `Invoke-DiskAcquisition` - Disk imaging using Velociraptor

**Hash & Manifest (Phase 2):**
- `Get-ArtifactHash` - SHA-256 hash calculation for forensic artifacts
- `Write-Manifest` - Chain-of-custody JSON manifest with digital timestamps

**S3 Upload & Verification (Phase 3):**
- `Send-ToS3` - AWS S3 upload with integrity verification, retry logic, and optional compression

**Chain-of-Custody & Logging Enhancements (Phase 4):**
- `Set-LoggingMode` - Configure logging verbosity (Quiet, Normal, Verbose, Debug)
- `Get-TimestampSignature` - Generate digital timestamp signatures for forensic evidence
- `Get-OperationSummary` - Create comprehensive operation reports with retry statistics

**Simulation & User Options (Phase 5):**
- `Start-InteractiveMode` - Interactive guided acquisition with user prompts and validation
- `New-SimulatedArtifact` - Create realistic dummy forensic artifacts for testing and training
- `Invoke-CompleteWorkflow` - End-to-end automated workflow (acquire → hash → manifest → upload)
- Enhanced acquisition functions with `-Simulation` and `-Interactive` parameters

### Example Usage

```powershell
# Import the module
Import-Module "./src/AcquisitionToolkit.psm1" -Force

# Memory acquisition
$memResult = Invoke-MemoryAcquisition -OutputDir "./evidence" -MemoryLimitMB 2048
Write-Host "Memory acquisition: $($memResult.Success)"
Write-Host "Output file: $($memResult.OutputFile)"
Write-Host "Size: $($memResult.SizeMB) MB"

# Disk acquisition
$diskResult = Invoke-DiskAcquisition -Volumes @("C:", "D:") -OutputDir "./evidence"
Write-Host "Disk acquisition: $($diskResult.Summary.SuccessfulVolumes)/$($diskResult.Summary.TotalVolumes) volumes"

# Hash calculation (Phase 2)
$hashResult = Get-ArtifactHash -OutputDir "./evidence" -IncludePattern "*.raw"
Write-Host "Hashed $($hashResult.Summary.SuccessfulHashes) artifacts"
foreach ($artifact in $hashResult.Results) {
    Write-Host "  $($artifact.FileName): $($artifact.Hash)"
}

# Manifest generation (Phase 2)
$manifestResult = Write-Manifest -OutputDir "./evidence" -CaseNumber "CASE-2025-001" -InvestigatorName "John Doe"
Write-Host "Manifest created: $($manifestResult.ManifestPath)"
Write-Host "Total artifacts: $($manifestResult.TotalArtifacts)"
Write-Host "Total size: $($manifestResult.TotalSizeGB) GB"

# S3 Upload (Phase 3)
$uploadResult = Send-ToS3 -OutputDir "./evidence" -IncludeManifest $true -Compress
Write-Host "Upload completed: $($uploadResult.SuccessfulUploads)/$($uploadResult.TotalFiles) files"
Write-Host "S3 Location: s3://$($uploadResult.S3Bucket)/$($uploadResult.S3KeyPrefix)/"

# Offline mode (no S3 upload)
$offlineResult = Send-ToS3 -OutputDir "./evidence" -Offline
Write-Host "Offline processing: $($offlineResult.TotalFiles) files prepared for upload"

# Enhanced Logging & Chain-of-Custody (Phase 4)
# Set verbose logging with file output
Set-LoggingMode -Mode Verbose -LogToFile -LogDirectory "./logs"

# Generate digital timestamp for evidence
$evidenceTimestamp = Get-TimestampSignature -Data "Evidence package CASE-2025-001" -IncludeSystemInfo
Write-Host "Digital signature: $($evidenceTimestamp.Signature)"

# Create comprehensive operation summary
$summaryResult = Get-OperationSummary -OperationType "Complete" -OperationResults @($memResult, $diskResult) -IncludeRetryDetails -SaveToFile
Write-Host "Operation summary: $($summaryResult.Status) ($($summaryResult.Statistics.SuccessRate)% success rate)"

# Simulation & Interactive Mode (Phase 5)
# Interactive guided acquisition
$interactiveResult = Start-InteractiveMode -Simulation
Write-Host "Interactive session completed: $($interactiveResult.Success)"

# Create simulated artifacts for testing
$simulatedMem = New-SimulatedArtifact -Type "Memory" -OutputPath "./test/simulated_memory.raw" -SizeMB 10 -IncludeMetadata
Write-Host "Simulated memory artifact: $($simulatedMem.OutputPath) ($($simulatedMem.SizeMB) MB)"

# Complete end-to-end workflow automation
$workflowResult = Invoke-CompleteWorkflow -CaseNumber "CASE-2025-001" -InvestigatorName "John Doe" -IncludeMemory -IncludeDisk -UploadToS3 -Simulation
Write-Host "Complete workflow: $($workflowResult.Success) in $([math]::Round($workflowResult.TotalDuration.TotalMinutes, 2)) minutes"

# Memory acquisition with simulation and interactive prompts
$simMemResult = Invoke-MemoryAcquisition -Interactive -Simulation -OutputDir "./test"
Write-Host "Simulated memory acquisition: $($simMemResult.Simulated)"

# Disk acquisition with simulation for multiple volumes
$simDiskResult = Invoke-DiskAcquisition -Simulation -Volumes @("C:", "D:") -OutputDir "./test"
Write-Host "Simulated disk acquisition: $($simDiskResult.Summary.SuccessfulVolumes) volumes"

# Configuration loading
$bucket = Get-ConfigValue -Key "S3_BUCKET"
$memLimit = Get-ConfigValue -Key "MEMORY_LIMIT_MB" -AsInteger -DefaultValue 4096
$compress = Get-ConfigValue -Key "COMPRESS" -AsBoolean

# Enhanced logging with different verbosity levels
Set-LoggingMode -Mode Quiet  # Only errors
Write-LogMessage -Message "Starting forensic acquisition" -Level Info
Write-LogMessage -Message "Configuration loaded" -Level Verbose -LogFile "./evidence/log.txt"
```

## 🔒 Security Considerations

- **Administrative Privileges**: Required for memory and disk access
- **Evidence Integrity**: SHA-256 hashing and chain-of-custody manifest
- **Data Protection**: Optional encryption before S3 upload
- **Access Control**: Secure AWS credentials and S3 bucket permissions

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/forensic-triage-toolkit/issues)
- **Documentation**: See `Phases.md` for technical implementation details
- **Contributing**: Follow the phased development approach outlined in `Phases.md`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚠️ Important**: This toolkit is designed for authorized digital forensics and incident response activities. Ensure you have proper legal authorization before using on any systems. 