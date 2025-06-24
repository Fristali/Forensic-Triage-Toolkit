# Forensic Triage Toolkit - Architecture Documentation

## 🏗️ System Architecture

The Forensic Triage Toolkit is designed as a modular, PowerShell-based automation system for digital forensic evidence acquisition. The architecture follows a pipeline pattern with clear separation of concerns.

### High-Level Component Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Input    │───▶│  Configuration  │───▶│  Acquisition    │
│                 │    │    Manager      │    │    Engine       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Evidence      │◀───│   Hash & Chain  │◀───│   Velociraptor  │
│   Storage       │    │   of Custody    │    │   Integration   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │
        ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   S3 Upload     │    │   Logging &     │
│   & Verify      │    │   Reporting     │
└─────────────────┘    └─────────────────┘
```

## 📦 Module Structure

### Core PowerShell Module: `AcquisitionToolkit.psm1`

```powershell
AcquisitionToolkit.psm1
├── Configuration Functions
│   ├── Import-EnvironmentConfig
│   └── Get-ConfigValue
├── Acquisition Functions
│   ├── Invoke-MemoryAcquisition
│   └── Invoke-DiskAcquisition
├── Hash & Manifest Functions
│   ├── Get-ArtifactHash
│   └── Write-Manifest
├── Upload & Verification
│   └── Send-ToS3
├── Chain-of-Custody & Logging
│   ├── Set-LoggingMode
│   ├── Get-TimestampSignature
│   └── Get-OperationSummary
├── Simulation & Automation
│   ├── Start-InteractiveMode
│   ├── New-SimulatedArtifact
│   └── Invoke-CompleteWorkflow
└── Helper Functions
    └── Write-LogMessage
```

## 🔧 Component Details

### 1. Configuration Manager

**Purpose:** Centralized configuration loading and validation.

**Components:**
- Environment variable loader (`.env` file support)
- Configuration validation and type conversion
- Default value management

**Key Functions:**
- `Import-EnvironmentConfig`: Loads `.env` file into memory
- `Get-ConfigValue`: Retrieves typed configuration values with defaults

### 2. Acquisition Engine

**Purpose:** Core evidence acquisition orchestration.

**Integration Points:**
- **Velociraptor**: Standalone binary execution for memory and disk imaging
- **WinPMem**: Memory acquisition via Velociraptor
- **Disk Imaging**: Volume-level acquisition

**Key Functions:**
- `Invoke-MemoryAcquisition`: Memory dump creation with size limits
- `Invoke-DiskAcquisition`: Multi-volume disk imaging

**Parameters:**
- Memory limit configuration
- Volume selection (automatic detection or manual specification)
- Output directory management
- Simulation mode for testing

### 3. Hash & Chain of Custody

**Purpose:** Evidence integrity and forensic documentation.

**Features:**
- SHA-256 hash calculation for all artifacts
- JSON manifest generation with metadata
- Digital timestamps (non-cryptographic)
- System information collection

**Key Functions:**
- `Get-ArtifactHash`: Parallel hash calculation
- `Write-Manifest`: Comprehensive chain-of-custody documentation

**Manifest Schema:**
```json
{
  "CaseInfo": {
    "CaseNumber": "string",
    "InvestigatorName": "string",
    "AcquisitionDate": "ISO-8601",
    "SystemHostname": "string"
  },
  "SystemInfo": {
    "OperatingSystem": "string",
    "Version": "string",
    "Architecture": "string",
    "Username": "string"
  },
  "Tools": {
    "Velociraptor": "version",
    "PowerShell": "version",
    "AcquisitionToolkit": "version"
  },
  "Artifacts": [
    {
      "FileName": "string",
      "FilePath": "string",
      "SizeMB": "number",
      "Hash": "SHA-256",
      "Type": "Memory|Disk|Other",
      "CreatedAt": "ISO-8601"
    }
  ],
  "Integrity": {
    "ManifestHash": "SHA-256",
    "DigitalTimestamp": "hex-string",
    "TotalArtifacts": "number",
    "TotalSizeGB": "number"
  }
}
```

### 4. Evidence Storage & Upload

**Purpose:** Secure evidence storage and integrity verification.

**Features:**
- AWS S3 integration with retry logic
- Upload verification via re-download and hash comparison
- Optional compression before upload
- Offline mode for disconnected environments

**Key Functions:**
- `Send-ToS3`: Upload with integrity verification

**S3 Structure:**
```
s3://bucket-name/
└── HOSTNAME-YYYYMMDD-HHMMSS/
    ├── memory.raw
    ├── disk_C_.raw
    ├── disk_D_.raw
    ├── manifest.json
    └── log.txt
```

### 5. Logging & Reporting

**Purpose:** Comprehensive operation logging and audit trails.

**Features:**
- Multiple verbosity levels (Quiet, Normal, Verbose, Debug)
- JSON structured logging
- File-based logging with rotation
- Operation summaries with statistics

**Key Functions:**
- `Set-LoggingMode`: Configure logging behavior
- `Write-LogMessage`: Structured logging with levels
- `Get-OperationSummary`: Generate operation reports

### 6. Simulation & Testing

**Purpose:** Safe testing and training environment.

**Features:**
- Realistic dummy artifact generation
- Complete workflow simulation
- Interactive guided mode
- Training scenarios

**Key Functions:**
- `New-SimulatedArtifact`: Generate test evidence
- `Start-InteractiveMode`: Guided acquisition
- `Invoke-CompleteWorkflow`: End-to-end automation

## 🔐 Security Architecture

### Evidence Integrity
- **SHA-256 hashing** for all artifacts
- **Chain-of-custody** documentation
- **Digital timestamps** for temporal verification
- **Upload verification** via re-download and hash comparison

### Access Control
- **AWS IAM** integration for S3 access
- **Least privilege** access patterns
- **Credential management** via environment variables or AWS profiles

### Data Protection
- **Optional encryption** before upload
- **Secure transport** (HTTPS/TLS)
- **Evidence isolation** (dedicated S3 buckets)

## 📊 Performance Characteristics

### Scalability
- **Parallel hash calculation** for multiple artifacts
- **Streaming uploads** for large files
- **Memory-efficient** processing

### Reliability
- **Retry logic** for network operations (3 attempts)
- **Error handling** with graceful degradation
- **Operation summaries** for failure analysis

### Monitoring
- **Structured logging** for analysis
- **Progress reporting** for long operations
- **Success/failure metrics** in summaries

## 🔄 Workflow Patterns

### Standard Acquisition Workflow
1. **Configuration Loading** - Environment variables and defaults
2. **Memory Acquisition** - RAM dump creation
3. **Disk Acquisition** - Volume imaging
4. **Hash Calculation** - Integrity verification
5. **Manifest Generation** - Chain-of-custody documentation
6. **Upload & Verification** - S3 storage with integrity check
7. **Summary Generation** - Operation reporting

### Simulation Workflow
1. **Simulation Artifact Creation** - Generate test evidence
2. **Hash & Manifest** - Process as real evidence
3. **Upload Simulation** - Test S3 connectivity without real data
4. **Training Validation** - Verify learning outcomes

### Interactive Workflow
1. **User Guidance** - Prompt for acquisition parameters
2. **Validation** - Verify user inputs
3. **Confirmation** - Display planned actions
4. **Execution** - Run standard workflow
5. **Results Display** - Show outcomes and next steps

## 🎯 Design Principles

### Modularity
- **Single responsibility** for each function
- **Clear interfaces** between components
- **Pluggable architecture** for extensions

### Reliability
- **Defensive programming** with input validation
- **Error recovery** where possible
- **Comprehensive logging** for troubleshooting

### Forensic Soundness
- **Evidence integrity** maintained throughout
- **Chain-of-custody** documented
- **Audit trails** for all operations
- **Non-destructive** operations only

### Usability
- **Simple CLI interface** for automation
- **Interactive mode** for guided operations
- **Clear error messages** and help text
- **Comprehensive documentation**

---

*Last updated: 2025-06-22* 