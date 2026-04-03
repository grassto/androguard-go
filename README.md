# GoAndroGuard

Go implementation of [Androguard](https://github.com/androguard/androguard) - Android APK reverse engineering and analysis tool.

## Features

- **APK Parsing**: Read and parse APK files (ZIP format)
- **AndroidManifest.xml**: Parse binary XML manifest files
- **DEX Files**: Parse Dalvik Executable files
- **ARSC Resources**: Parse Android resource table files
- **X.509 Certificates**: Extract and verify signing certificates
- **APK Signatures**: Verify v1 (JAR), v2, and v3 signatures
- **Command Line Interface**: Powerful CLI for APK analysis

## Installation

```bash
go install github.com/goandroguard/goandroguard/cmd/androguard@latest
```

Or build from source:

```bash
git clone https://github.com/goandroguard/goandroguard.git
cd goandroguard
go build -o androguard ./cmd/androguard
```

## Usage

### CLI Commands

```bash
# Show APK information
androguard info app.apk

# Show AndroidManifest.xml
androguard manifest app.apk

# List permissions
androguard permissions app.apk
androguard permissions --details app.apk  # With danger level

# List components (activities, services, receivers, providers)
androguard components app.apk

# Show certificates
androguard certificates app.apk

# DEX file analysis
androguard dex app.apk                    # DEX summary
androguard dex --classes app.apk          # List classes
androguard dex --methods app.apk          # List methods
androguard dex --fields app.apk           # List fields

# List files in APK
androguard files app.apk

# Show signature information
androguard signatures app.apk
```

### Go Library

```go
package main

import (
    "fmt"
    "log"

    "github.com/goandroguard/goandroguard/pkg/apk"
    "github.com/goandroguard/goandroguard/pkg/dex"
)

func main() {
    // Open an APK file
    a, err := apk.OpenFile("app.apk")
    if err != nil {
        log.Fatal(err)
    }

    // Get basic info
    fmt.Printf("Package: %s\n", a.GetPackageName())
    fmt.Printf("Version: %s\n", a.GetVersionName())
    fmt.Printf("Min SDK: %s\n", a.GetMinSDKVersion())

    // Get permissions
    for _, perm := range a.GetPermissions() {
        fmt.Printf("Permission: %s\n", perm)
    }

    // Get DEX files
    for i, df := range a.GetDexFiles() {
        fmt.Printf("DEX #%d: %d classes\n", i+1, df.Header.ClassDefsSize)
    }

    // Parse DEX directly
    dexData, _ := a.GetFile("classes.dex")
    df, _ := dex.Parse(dexData)
    for i := uint32(0); i < df.Header.ClassDefsSize; i++ {
        className := df.GetClassName(i)
        fmt.Printf("Class: %s\n", className)
    }
}
```

## Project Structure

```
goandroguard/
├── cmd/
│   └── androguard/        # CLI tool
│       └── main.go
├── pkg/
│   ├── apk/               # APK file parsing
│   │   ├── apk.go
│   │   └── file.go
│   ├── axml/              # Android Binary XML parser
│   │   └── axml.go
│   ├── arsc/              # Android Resource Table parser
│   │   └── arsc.go
│   ├── certs/             # X.509 certificate parsing
│   │   └── certs.go
│   └── dex/               # DEX file parser
│       └── dex.go
├── internal/
│   └── leb128/            # LEB128 encoding/decoding
│       └── leb128.go
├── go.mod
└── README.md
```

## Modules

### APK (`pkg/apk`)
Parses Android APK files. Handles ZIP reading, manifest parsing, certificate extraction, and APK signature verification.

### AXML (`pkg/axml`)
Parses Android Binary XML format used in AndroidManifest.xml and other compiled XML files.

### ARSC (`pkg/arsc`)
Parses Android Resource Table files (resources.arsc) containing compiled resources.

### DEX (`pkg/dex`)
Parses Dalvik Executable (DEX) files containing compiled Java/Kotlin bytecode.

### Certs (`pkg/certs`)
Provides X.509 certificate parsing and PKCS#7 signature extraction.

### LEB128 (`internal/leb128`)
Implements LEB128 variable-length encoding used extensively in DEX format.

## Supported Formats

- APK (Android Package)
- DEX (Dalvik Executable) v035-v039
- ODEX (Optimized DEX)
- AXML (Android Binary XML)
- ARSC (Android Resource Table)

## Requirements

- Go 1.21 or later

## License

Apache License 2.0 (same as original Androguard)

## Credits

This is a Go port of [Androguard](https://github.com/androguard/androguard) by Anthony Desnos and contributors.
