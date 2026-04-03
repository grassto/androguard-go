// Package config provides configuration management for androguard-go.
package config

import (
	"os"
	"strings"
)

// Version is the current androguard-go version.
const Version = "0.1.0"

// Config holds global configuration for androguard.
type Config struct {
	// DefaultAPI is the default Android API level when specific API is not available.
	DefaultAPI int

	// TempDir is the path to temporary directory.
	TempDir string

	// Colors holds color configuration for terminal output.
	Colors ColorConfig
}

// ColorConfig holds color settings for terminal output.
type ColorConfig struct {
	Offset          string
	OffsetAddr      string
	InstructionName string
	BranchFalse     string
	BranchTrue      string
	Branch          string
	Exception       string
	BB              string
	Note            string
	Normal          string
	Output          OutputColors
}

// OutputColors holds colors for different output types.
type OutputColors struct {
	Normal    string
	Registers string
	Literal   string
	Offset    string
	Raw       string
	String    string
	Method    string
	Type      string
	Field     string
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		DefaultAPI: 16,
		TempDir:    os.TempDir(),
		Colors: ColorConfig{
			Offset:          "\033[33m", // Yellow
			OffsetAddr:      "\033[32m", // Green
			InstructionName: "\033[33m", // Yellow
			BranchFalse:     "\033[31m", // Red
			BranchTrue:      "\033[32m", // Green
			Branch:          "\033[34m", // Blue
			Exception:       "\033[36m", // Cyan
			BB:              "\033[35m", // Magenta
			Note:            "\033[31m", // Red
			Normal:          "\033[0m",  // Reset
			Output: OutputColors{
				Normal:    "\033[0m",
				Registers: "\033[33m",
				Literal:   "\033[32m",
				Offset:    "\033[35m",
				Raw:       "\033[31m",
				String:    "\033[31m",
				Method:    "\033[36m",
				Type:      "\033[34m",
				Field:     "\033[32m",
			},
		},
	}
}

// Global is the default configuration instance.
var Global = Default()

// DetectFileType detects the type of Android file from raw bytes.
// Returns one of: "APK", "DEX", "DEY", "AXML", "ARSC", or "".
func DetectFileType(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// APK: ZIP signature + AndroidManifest.xml
	if data[0] == 0x50 && data[1] == 0x4b { // "PK"
		if bytesContains(data, []byte("AndroidManifest.xml")) {
			return "APK"
		}
		return "ZIP" // Regular ZIP, not APK
	}

	// DEX
	if len(data) >= 8 && string(data[0:3]) == "dex" {
		return "DEX"
	}

	// ODEX
	if len(data) >= 8 && string(data[0:3]) == "dey" {
		return "DEY"
	}

	// AXML
	if (data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00) ||
		(data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00) {
		return "AXML"
	}

	// ARSC
	if data[0] == 0x02 && data[1] == 0x00 && data[2] == 0x0C && data[3] == 0x00 {
		return "ARSC"
	}

	return ""
}

// DetectFileTypeFromPath detects the type of Android file from a path.
func DetectFileTypeFromPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return DetectFileType(data)
}

// IsASCIIProblem tests if a string contains non-ASCII characters.
func IsASCIIProblem(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func bytesContains(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}
