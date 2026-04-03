package apk

import (
	"testing"
)

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected string
	}{
		{"dex", []byte("dex\n035\x00\x00"), "dex"},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04, 0x00}, "zip"},
		{"elf", []byte{0x7F, 'E', 'L', 'F', 0x00}, "elf"},
		{"png", []byte{0x89, 'P', 'N', 'G', '\r'}, "png"},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}, "jpeg"},
		{"gif", []byte("GIF89a"), "gif"},
		{"xml", []byte("<?xml "), "xml"},
		{"arsc ext", []byte{0x00, 0x00, 0x00, 0x00}, "arsc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := "test."
			if tt.name == "arsc ext" {
				name = "test.arsc"
			}
			got := detectFileType(tt.buf, name)
			if got != tt.expected {
				t.Errorf("detectFileType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetDigestAlgorithmName(t *testing.T) {
	tests := []struct {
		id       uint32
		expected string
	}{
		{0x0101, "SHA-256"},
		{0x0102, "SHA-512"},
		{0x0201, "SHA-256"},
		{0xFFFF, "unknown(0xffff)"},
	}

	for _, tt := range tests {
		got := GetDigestAlgorithmName(tt.id)
		if got != tt.expected {
			t.Errorf("GetDigestAlgorithmName(0x%x) = %v, want %v", tt.id, got, tt.expected)
		}
	}
}

func TestParseColorValue(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"#FFFFFF", 0xFFFFFFFF},
		{"#FF0000", 0xFFFF0000},
		{"#00FF00", 0xFF00FF00},
		{"#0000FF", 0xFF0000FF},
		{"#80FFFFFF", 0x80FFFFFF},
		{"invalid", 0},
	}

	for _, tt := range tests {
		got := parseColorValue(tt.input)
		if got != tt.expected {
			t.Errorf("parseColorValue(%q) = 0x%08X, want 0x%08X", tt.input, got, tt.expected)
		}
	}
}
