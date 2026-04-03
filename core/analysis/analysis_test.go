package analysis

import (
	"testing"
)

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"not.an.ip", false},
		{"192.168.1", false},
		{"192.168.1.1.1", false},
		{"abc.def.ghi.jkl", false},
	}

	for _, tt := range tests {
		result := isIPAddress(tt.input)
		if result != tt.expected {
			t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestIsLikelyEncrypted(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"aGVsbG8gd29ybGQ=", false}, // short base64
		{"aGVsbG8gd29ybGQhIHdlbGNvbWUgdG8gdGhlIHdvcmxkIG9mIGVuY3J5cHRpb24=", true}, // long base64
		{"plaintext string", false},
		{"AKDJ38djJD92kd92KD02kd", true},
		{"short", false},
	}

	for _, tt := range tests {
		result := isLikelyEncrypted(tt.input)
		if result != tt.expected {
			t.Errorf("isLikelyEncrypted(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestXRefTypeString(t *testing.T) {
	tests := []struct {
		input    XRefType
		expected string
	}{
		{XRefCall, "call"},
		{XRefRead, "read"},
		{XRefWrite, "write"},
		{XRefString, "string"},
		{XRefTypeOf, "typeof"},
	}

	for _, tt := range tests {
		result := tt.input.String()
		if result != tt.expected {
			t.Errorf("XRefType(%d).String() = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
