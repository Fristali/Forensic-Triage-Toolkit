# Chain-of-Custody Specification

## 📋 Overview

The Forensic Triage Toolkit implements a comprehensive chain-of-custody system to ensure evidence integrity and maintain forensic standards. This document defines the specifications, procedures, and technical implementation of the chain-of-custody process.

## 🎯 Objectives

1. **Evidence Integrity**: Ensure digital evidence remains unaltered from acquisition to storage
2. **Forensic Accountability**: Maintain detailed audit trails of all evidence handling
3. **Legal Admissibility**: Meet requirements for evidence presentation in legal proceedings
4. **Process Transparency**: Provide clear documentation of acquisition procedures

## 📄 Chain-of-Custody Manifest Schema

### JSON Structure

The toolkit generates a comprehensive JSON manifest for each acquisition session:

```json
{
  "FormatVersion": "1.0",
  "CaseInfo": {
    "CaseNumber": "CASE-2025-001",
    "InvestigatorName": "John Doe",
    "InvestigatorID": "INV-001",
    "AcquisitionDate": "2025-06-22T22:15:51.8526046-04:00",
    "SystemHostname": "FORENSIC-WS-01",
    "Description": "Routine forensic acquisition",
    "LegalAuthority": "Search Warrant #2025-SW-001"
  },
  "SystemInfo": {
    "OperatingSystem": "Microsoft Windows 11 Pro",
    "Version": "10.0.22631",
    "Architecture": "AMD64",
    "Username": "forensic.analyst",
    "Domain": "FORENSICS.LOCAL",
    "SystemUptime": "2 days, 14 hours",
    "TimeZone": "Eastern Standard Time",
    "SystemTime": "2025-06-22T22:15:51.8526046-04:00"
  },
  "Tools": {
    "Velociraptor": "0.6.8",
    "PowerShell": "7.4.0",
    "AcquisitionToolkit": "1.0.0",
    "Platform": "Windows PowerShell"
  },
  "AcquisitionParameters": {
    "MemoryLimitMB": 4096,
    "TargetVolumes": ["C:", "D:"],
    "OutputDirectory": "./evidence",
    "CompressionEnabled": false,
    "EncryptionEnabled": false,
    "SimulationMode": false
  },
  "Artifacts": [
    {
      "FileName": "FORENSIC-WS-01_20250622_221551_memory.raw",
      "FilePath": "C:\\Evidence\\FORENSIC-WS-01_20250622_221551_memory.raw",
      "Type": "Memory",
      "SizeMB": 4096.0,
      "Hash": "7A72502954DD281A340006773D4C9AABFC656F26B8BF054244AD387F7FD81CC4",
      "HashAlgorithm": "SHA-256",
      "CreatedAt": "2025-06-22T22:15:51.8526046-04:00",
      "ModifiedAt": "2025-06-22T22:15:51.8526046-04:00",
      "AcquisitionTool": "Velociraptor",
      "AcquisitionMethod": "WinPMem",
      "CompressionRatio": null,
      "Encrypted": false
    },
    {
      "FileName": "FORENSIC-WS-01_20250622_221551_disk_C_.raw",
      "FilePath": "C:\\Evidence\\FORENSIC-WS-01_20250622_221551_disk_C_.raw",
      "Type": "Disk",
      "SizeMB": 102400.0,
      "Hash": "058E2E2A49A775E997E5E746F17DCD282557173F12E306EFA187E054A8045688",
      "HashAlgorithm": "SHA-256",
      "CreatedAt": "2025-06-22T22:16:15.1234567-04:00",
      "ModifiedAt": "2025-06-22T22:16:15.1234567-04:00",
      "AcquisitionTool": "Velociraptor",
      "AcquisitionMethod": "dd-like imaging",
      "SourceVolume": "C:",
      "VolumeSize": "465GB",
      "FileSystem": "NTFS",
      "CompressionRatio": null,
      "Encrypted": false
    }
  ],
  "Integrity": {
    "ManifestHash": "32361917CA71B1BA8A2201A404C3E1281CFE5580440849E290D7C997D489ED4C",
    "ManifestHashAlgorithm": "SHA-256",
    "DigitalTimestamp": "2219f8f25985c789587c160468db850c28d571a4fd65649da87d6805c047b3da",
    "TimestampVersion": "1.0",
    "TotalArtifacts": 2,
    "TotalSizeGB": 106.496,
    "AcquisitionDuration": "00:24:12",
    "ValidationStatus": "VERIFIED"
  },
  "Upload": {
    "Enabled": true,
    "S3Bucket": "forensic-evidence-prod",
    "S3KeyPrefix": "FORENSIC-WS-01-20250622-221551",
    "UploadedAt": "2025-06-22T22:40:03.1234567-04:00",
    "UploadDuration": "00:15:51",
    "VerificationStatus": "PASSED",
    "RetryCount": 0
  },
  "Signatures": {
    "InvestigatorSignature": {
      "Name": "John Doe",
      "ID": "INV-001",
      "Timestamp": "2025-06-22T22:40:03.1234567-04:00",
      "Statement": "I certify that this evidence was acquired in accordance with established forensic procedures."
    },
    "ChainOfCustody": [
      {
        "Action": "ACQUIRED",
        "Timestamp": "2025-06-22T22:15:51.8526046-04:00",
        "Person": "John Doe (INV-001)",
        "Location": "Forensic Lab A",
        "Purpose": "Initial evidence acquisition"
      },
      {
        "Action": "UPLOADED",
        "Timestamp": "2025-06-22T22:40:03.1234567-04:00",
        "Person": "John Doe (INV-001)",
        "Location": "AWS S3 (forensic-evidence-prod)",
        "Purpose": "Secure evidence storage"
      }
    ]
  }
}
```

## 🔐 Digital Timestamps

### Implementation

The toolkit implements non-cryptographic digital timestamps for evidence temporal integrity:

```powershell
function Get-TimestampSignature {
    param(
        [string]$Data,
        [switch]$IncludeSystemInfo
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffffffK"
    $systemInfo = if ($IncludeSystemInfo) {
        @{
            Hostname = $env:COMPUTERNAME
            User = $env:USERNAME
            ProcessId = $PID
            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        } | ConvertTo-Json -Compress
    } else { "" }
    
    $combined = "$Data|$timestamp|$systemInfo"
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)
    $hashBytes = $hash.ComputeHash($bytes)
    $signature = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    
    return @{
        Signature = $signature.ToLower()
        Timestamp = $timestamp
        Data = $Data
        Version = "1.0"
    }
}
```

### Properties

- **Algorithm**: SHA-256 hash of data + timestamp + system info
- **Format**: Hexadecimal string (64 characters)
- **Precision**: Microsecond-level timestamp precision
- **Scope**: Per-evidence and per-manifest signatures

## 📊 Evidence Integrity Verification

### Hash Calculation Process

1. **Primary Hash**: SHA-256 calculated immediately after acquisition
2. **Verification Hash**: SHA-256 recalculated before upload
3. **Upload Verification**: SHA-256 calculated after S3 download
4. **Manifest Hash**: SHA-256 of the complete manifest JSON

### Verification Workflow

```powershell
# 1. Calculate hash immediately after acquisition
$primaryHash = Get-FileHash -Path $artifactPath -Algorithm SHA256

# 2. Store in manifest
$artifact.Hash = $primaryHash.Hash

# 3. Verify before upload
$verificationHash = Get-FileHash -Path $artifactPath -Algorithm SHA256
if ($verificationHash.Hash -ne $artifact.Hash) {
    throw "Hash mismatch detected before upload"
}

# 4. Upload and re-download for verification
$uploadResult = Send-ToS3 -FilePath $artifactPath
$downloadedFile = Download-FromS3 -S3Key $uploadResult.S3Key
$downloadHash = Get-FileHash -Path $downloadedFile -Algorithm SHA256

# 5. Final verification
if ($downloadHash.Hash -ne $artifact.Hash) {
    throw "Upload integrity verification failed"
}
```

## 🔄 Chain-of-Custody Events

### Event Types

| Event Type | Description | Required Fields |
|------------|-------------|-----------------|
| `ACQUIRED` | Initial evidence acquisition | Person, Timestamp, Location, Method |
| `HASHED` | Hash calculation completed | Hash, Algorithm, Timestamp |
| `PACKAGED` | Evidence packaged for storage | Compression, Encryption, Size |
| `UPLOADED` | Evidence uploaded to storage | Destination, Duration, Verification |
| `ACCESSED` | Evidence accessed/downloaded | Person, Purpose, Timestamp |
| `TRANSFERRED` | Evidence custody transferred | From, To, Purpose, Authorization |

### Event Recording

```powershell
function Add-ChainOfCustodyEvent {
    param(
        [string]$Action,
        [string]$Person,
        [string]$Location,
        [string]$Purpose,
        [hashtable]$AdditionalData = @{}
    )
    
    $event = @{
        Action = $Action.ToUpper()
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffffffK"
        Person = $Person
        Location = $Location
        Purpose = $Purpose
    }
    
    # Add any additional data
    foreach ($key in $AdditionalData.Keys) {
        $event[$key] = $AdditionalData[$key]
    }
    
    return $event
}
```

## 📝 Legal and Compliance Requirements

### Federal Rules of Evidence (US)

The chain-of-custody implementation addresses:

- **Rule 901(b)(9)**: Authentication of digital evidence
- **Rule 1001-1008**: Best Evidence Rule for electronic records
- **Rule 403**: Relevance and reliability

### ISO 27037:2012 Compliance

The toolkit aligns with international standards:

- **Section 7.3**: Digital evidence acquisition
- **Section 7.4**: Documentation requirements
- **Section 8**: Chain of custody procedures

### NIST SP 800-86 Guidelines

Implementation follows NIST recommendations:

- **Section 3.1.3**: Evidence integrity verification
- **Section 3.1.4**: Chain of custody documentation
- **Section 4.2**: Acquisition procedures

## 🛡️ Security Considerations

### Access Control

- **Investigator Authentication**: Required for all operations
- **Role-Based Access**: Different permission levels for operations
- **Audit Logging**: All access attempts logged

### Data Protection

- **Encryption at Rest**: Optional AES-256 encryption
- **Encryption in Transit**: TLS 1.2+ for all network operations
- **Access Logging**: Complete audit trail of evidence access

### Backup and Recovery

- **Multiple Copies**: Evidence stored in multiple S3 regions
- **Versioning**: S3 versioning enabled for evidence files
- **Immutable Storage**: S3 Object Lock for evidence preservation

## 🔍 Quality Assurance

### Validation Procedures

1. **Pre-Acquisition Checks**
   - System time synchronization
   - Tool version verification
   - Storage capacity validation

2. **Acquisition Monitoring**
   - Real-time hash calculation
   - Progress tracking
   - Error detection and handling

3. **Post-Acquisition Verification**
   - Hash comparison
   - File integrity checks
   - Manifest validation

### Testing and Certification

- **Simulation Mode**: Safe testing environment
- **Unit Tests**: Comprehensive function testing
- **Integration Tests**: End-to-end workflow validation
- **Performance Tests**: Large-scale acquisition testing

## 📚 References

1. NIST Special Publication 800-86: "Guide to Integrating Forensic Techniques into Incident Response"
2. ISO/IEC 27037:2012: "Guidelines for identification, collection, acquisition and preservation of digital evidence"
3. Federal Rules of Evidence, Rules 901, 1001-1008
4. ACPO Good Practice Guide for Digital Evidence v5.0
5. RFC 3161: "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)"

---

*Last updated: 2025-06-22* 