# Androguard-Go

Go implementation of [Androguard](https://github.com/androguard/androguard) - Android APK reverse engineering and analysis tool.

## Features

- **APK Parsing**: Read and parse APK files, extract contents
- **AndroidManifest.xml**: Parse binary XML manifest files
- **DEX Files**: Parse Dalvik Executable files (v035-v043)
- **ODEX Files**: Parse Optimized DEX files
- **ARSC Resources**: Parse Android resource table files
- **X.509 Certificates**: Extract and verify signing certificates
- **APK Signatures**: Verify v1 (JAR), v2, and v3 signatures
- **Code Analysis**: Cross-references, basic blocks, string analysis
- **Bytecode**: Disassembly, CFG export (DOT/JSON)
- **Command Line Interface**: CLI for APK analysis

## Installation

```bash
go install github.com/grassto/androguard-go/cli@latest
```

Or build from source:

```bash
git clone https://github.com/grassto/androguard-go.git
cd androguard-go
go build -o androguard ./cli
```

## Usage

### CLI Commands

```bash
# Show APK information
androguard info app.apk

# Show AndroidManifest.xml (pretty-printed XML)
androguard manifest app.apk

# Parse standalone AXML file
androguard axml AndroidManifest.xml

# Parse standalone ARSC file
androguard arsc resources.arsc
```

### Go Library

```go
package main

import (
    "fmt"
    "log"

    "github.com/grassto/androguard-go/core/apk"
    "github.com/grassto/androguard-go/core/dex"
    "github.com/grassto/androguard-go/core/analysis"
)

func main() {
    // Open an APK file
    a, err := apk.Open("app.apk")
    if err != nil {
        log.Fatal(err)
    }

    // Get basic info
    fmt.Printf("Package: %s\n", a.GetPackageName())
    fmt.Printf("Version: %s\n", a.GetVersionName())
    fmt.Printf("Min SDK: %s\n", a.GetMinSDKVersion())
    fmt.Printf("Target SDK: %s\n", a.GetTargetSDKVersion())
    fmt.Printf("App Name: %s\n", a.GetAppName())

    // Get permissions
    for _, perm := range a.GetPermissions() {
        fmt.Printf("Permission: %s\n", perm)
    }

    // Get activities, services, receivers, providers
    for _, act := range a.GetActivities() {
        fmt.Printf("Activity: %s\n", act)
    }

    // Get certificates
    for _, cert := range a.GetCertificates() {
        fmt.Printf("Certificate: %s\n", cert.Subject)
    }

    // Check signatures
    fmt.Printf("Signed V1: %v\n", a.IsSignedV1())
    fmt.Printf("Signed V2: %v\n", a.IsSignedV2())
    fmt.Printf("Signed V3: %v\n", a.IsSignedV3())

    // Get DEX files and run analysis
    dx := analysis.New(a.GetDexFiles()[0])
    fmt.Printf("Classes: %d\n", len(dx.GetClasses()))
    fmt.Printf("Methods: %d\n", len(dx.GetMethods()))

    // Find classes by pattern
    for _, c := range dx.FindClasses(".*Activity") {
        fmt.Printf("Activity class: %s\n", c.Name)
    }
}
```

## Project Structure

```
androguard-go/
├── cli/
│   └── main.go              # CLI tool
├── core/
│   ├── analysis/            # Code analysis (xrefs, basic blocks)
│   │   ├── analysis.go
│   │   ├── analysis_enhanced.go
│   │   └── basic_blocks.go
│   ├── apk/                 # APK file parsing
│   │   ├── apk.go
│   │   ├── apk_enhanced.go
│   │   ├── apk_missing.go
│   │   ├── apk_signatures.go
│   │   └── file.go
│   ├── axml/                # Android Binary XML parser
│   │   ├── axml.go
│   │   ├── axml_enhanced.go
│   │   ├── axml_missing.go
│   │   └── printer.go
│   ├── bytecode/            # Pretty printing & export
│   │   └── bytecode.go
│   ├── certs/               # X.509 certificate parsing
│   │   └── certs.go
│   ├── config/              # Configuration & file detection
│   │   └── config.go
│   ├── dex/                 # DEX file parser
│   │   ├── dex.go
│   │   ├── dex_enhanced.go
│   │   ├── dex_missing.go
│   │   ├── disasm.go
│   │   ├── annotations.go
│   │   ├── bytecode.go
│   │   ├── class_manager.go
│   │   ├── code.go
│   │   ├── debug.go
│   │   ├── opcodes.go
│   │   └── payloads.go
│   ├── mutf8/               # Modified UTF-8 encoding
│   │   └── mutf8.go
│   └── resources/           # ARSC resource table parser
│       ├── arsc.go
│       └── resources_missing.go
├── internal/
│   └── leb128/              # LEB128 encoding/decoding
│       └── leb128.go
├── go.mod
├── PLAN.md
└── README.md
```

## Modules

### APK (`core/apk`)
Parses Android APK files. Handles ZIP reading, manifest parsing, certificate extraction, and APK signature verification (v1/v2/v3).

### AXML (`core/axml`)
Parses Android Binary XML format used in AndroidManifest.xml and other compiled XML files. Includes pretty printer for human-readable output.

### DEX (`core/dex`)
Parses Dalvik Executable (DEX) files containing compiled Java/Kotlin bytecode. Supports disassembly, annotations, debug info, and class data parsing.

### Analysis (`core/analysis`)
Provides code analysis features: cross-references (xrefs), basic block construction, class/method/field/string analysis, call graph generation.

### Resources (`core/resources`)
Parses Android Resource Table files (resources.arsc) containing compiled resources. Supports querying by type, locale, and configuration.

### Bytecode (`core/bytecode`)
Pretty printing of basic blocks, DOT graph export for control flow graphs, JSON export for method analysis.

### Config (`core/config`)
Global configuration management and Android file type detection.

### Certs (`core/certs`)
X.509 certificate parsing and extraction from APK signature blocks.

### MUTF8 (`core/mutf8`)
Modified UTF-8 encoding/decoding used in DEX string tables.

### LEB128 (`internal/leb128`)
LEB128 variable-length integer encoding used extensively in DEX format.

## Supported Formats

| Format | Description | Status |
|--------|-------------|--------|
| APK | Android Package | ✅ Full support |
| DEX | Dalvik Executable v035-v043 | ✅ Full support |
| ODEX | Optimized DEX | ⚠️ Basic support |
| AXML | Android Binary XML | ✅ Full support |
| ARSC | Android Resource Table | ✅ Full support |

## Requirements

- Go 1.22 or later

## License

Apache License 2.0 (same as original Androguard)

## Credits

Go port of [Androguard](https://github.com/androguard/androguard) by Anthony Desnos and contributors.
