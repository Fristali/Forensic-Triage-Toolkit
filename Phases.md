# Forensic Triage Toolkit – Phased Implementation Plan

> **Purpose:** end‑to‑end automation for disk & RAM acquisition on a single host using Velociraptor, with SHA‑256 hashing, chain‑of‑custody JSON manifest, optional encryption/compression, S3 upload, evidence retention, and detailed logging.

---

## 📜 High‑Level Architecture

```text
┌──────────┐  Acquire   ┌──────────────────────────────────┐
│  Wrapper │──────────▶│  Velociraptor (stand‑alone mode) │
└──────────┘           └──────────────────────────────────┘
      │  Image paths                     ▲
      ▼                                  │
┌──────────┐  Hash (SHA‑256)             │
│  Hasher  │─────────────────────────────┘
└──────────┘
      │  JSON manifest  
      ▼
┌──────────┐  Encrypt / Compress (opt)  
│ Packager │
└──────────┘
      │  Upload via boto3 (or AWS PS)  
      ▼
┌──────────┐
│   S3     │  <- flat structure /<timestamp>_<host>_*.*
└──────────┘
      │
      ▼
Local evidence folder  ./evidence/
```

* **Primary language**: PowerShell 7 (cross‑platform) with helper Python (boto3, hashing, JSON) if simpler.
* **Target OS**: Windows 10/11 & Windows Server (priority). Linux/macOS support via PowerShell 7 core commands.
* **Dependencies**: Velociraptor executable pre‑installed (or in ./bin), AWS CLI profile OR access keys via `.env`.
* **Config**: `.env` file loaded at runtime (S3 bucket, creds, options).

---

## ⚙️ Tooling & Libraries

| Domain            | Tool / Library                                                        | Purpose                                       |
| ----------------- | --------------------------------------------------------------------- | --------------------------------------------- |
| Acquisition       | Velociraptor stand‑alone binary (`velociraptor.exe` / `velociraptor`) | Disk & RAM imaging                            |
| Hashing           | PowerShell `Get-FileHash` or Python `hashlib`                         | SHA‑256 generation                            |
| Upload            | `aws s3` via AWS CLI **or** `boto3`                                   | Evidence upload & post‑upload integrity check |
| Manifest          | PowerShell `ConvertTo‑Json`                                           | Chain‑of‑custody record                       |
| Encryption (opt)  | `cryptography` Python lib or `openssl` CLI                            | ZIP/AES256 before upload                      |
| Compression (opt) | `Compress‑Archive`                                                    | Zip packaging                                 |
| Logging           | Built‑in PS logging + Serilog style JSON logs                         | Verbose / non‑verbose modes                   |

---

## 🎯 Phases Overview

### **Phase 0 – Project Skeleton & Config**

* Deliverables

  * `src/` directory with blank PowerShell module `AcquisitionToolkit.psm1`
  * `.env.example` with all variables (bucket, region, creds, options)
  * `README.md` Quick Start + prerequisites
  * `tests/` initial pytest that just checks env loader

### **Phase 1 – Acquisition Core**

* Implement PowerShell cmdlets:

  * `Invoke-MemoryAcquisition` (winpmem via Velociraptor)
  * `Invoke-DiskAcquisition`   (Velociraptor `collect --artifact Windows.Disk.Image`)
  * Params: `‑MemoryLimitMB`, `‑Volumes` (array), `‑OutputDir ./evidence`
* Unit tests: mock Velociraptor binary, assert file paths exist.

### **Phase 2 – Hash & Manifest**

* Add `Get-ArtifactHash` → returns SHA‑256 JSON object.
* `Write-Manifest` combines:

  * host, user, OS build, Velociraptor version, acquisition params
  * artifact list (name, size, hash)
  * timestamp (local system)
* Human‑readable log file (`$OutputDir/log.txt`).

### **Phase 3 – Upload & Verification**

* Integrate AWS upload cmdlet `Send-ToS3`:

  * Reads creds from env / AWS profile.
  * Uploads artifacts then re‑downloads & re‑hashes for verification.
  * Retry logic (3×) then error out.
* Flat prefix `<Host>-<yyyyMMddHHmmss>` in bucket.
* Option flags: `‑Offline` (skip upload), `‑Compress` (zip before upload).

### **Phase 4 – Chain‑of‑Custody & Logging Enhancements**

* JSON manifest digitally timestamped (no signing).
* Verbose vs quiet mode.
* Retry summary and failure flag.
* Unit tests with local MinIO (s3‑compatible) container.

### **Phase 5 – Simulation & User Options**

* `‑Simulation` flag outputs fake 10 MB dummy files instead of real acquisition.
* `‑Interactive` flag prompts for volumes & mem limit, else run non‑interactive with defaults from `.env`.

### **Phase 6 – Docs, Packaging & CI**

* ✅ Update README usage, diagrams, badges.
* ✅ Publish `docs/` for architecture and chain‑of‑custody spec.
* ✅ GitHub Action: `pwsh -File build.ps1` that runs Pester tests + PSScriptAnalyzer.
* ✅ Multi-platform CI/CD pipeline (Windows, Linux, macOS).
* ✅ Security scanning with Trivy vulnerability assessment.
* ✅ Automated package generation and distribution.
* ✅ Documentation publishing to GitHub Pages.

---

## 🚀 Future / Planned Features

* Integration with Velociraptor server hunts.
* Optional PDF report generation (pandoc).
* Proxy support & advanced S3 encryption keys.
* SOAR webhook notification after upload.

---

## 🔑 Environment Variables (`.env`)

```
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=forensic-evidence
MEMORY_LIMIT_MB=4096
EVIDENCE_DIR=./evidence
COMPRESS=false
OFFLINE=false
```

---

## 🧪 Testing Strategy

* **Unit Tests (Pester + pytest)**: validate function outputs without external calls.
* **Integration Tests**: docker‑compose spins local MinIO, runs acquisition in Simulation mode, uploads, verifies.
* **Coverage Target**: ≥ 85 % across PS & Python code.

---

## 🎯 Current Project Status (Updated 2025-06-22)

- ✅ **Phase 0**: Project Skeleton & Config *(complete)*
- ✅ **Phase 1**: Acquisition Core (Velociraptor integration) *(complete)*
- ✅ **Phase 2**: Hash & Manifest generation *(complete)*
- ✅ **Phase 3**: S3 Upload & Verification *(complete)*
- ✅ **Phase 4**: Chain-of-Custody & Enhanced logging *(complete)*
- ✅ **Phase 5**: Simulation & User Options *(complete)*
- ✅ **Phase 6**: Documentation & CI/CD *(complete)*

**🎉 ALL PHASES COMPLETED - PROJECT READY FOR PRODUCTION!**

---

*Last updated: 2025‑06‑22*
