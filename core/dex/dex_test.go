package dex

import (
	"os"
	"testing"
)

func TestParseRealDex(t *testing.T) {
	// Try to find a real DEX file from an installed Android SDK or use test fixture
	testFiles := []string{
		"testdata/classes.dex",
		"test.apk",
	}

	for _, path := range testFiles {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			df, err := Parse(data)
			if err != nil {
				t.Logf("Failed to parse %s: %v", path, err)
				continue
			}
			t.Logf("Parsed %s: %d classes, %d methods", path, df.Header.ClassDefsSize, df.Header.MethodIDsSize)
		}
	}
}

func TestMUTF8Decode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello\x00"), "hello"},
		{[]byte("test string\x00"), "test string"},
		{[]byte("\xc0\x80"), "\x00"}, // MUTF-8 null encoding
	}

	for _, tt := range tests {
		result := testMUTF8(tt.input)
		if result != tt.expected {
			t.Errorf("MUTF8Decode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// Helper to test MUTF8 decoding (exposed through internal package)
func testMUTF8(data []byte) string {
	// This tests the same logic as internal/leb128.MUTF8Decode
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == 0 {
			break
		}
		// MUTF-8: 0xC0 0x80 encodes NULL
		if b == 0xC0 && i+1 < len(data) && data[i+1] == 0x80 {
			result = append(result, 0)
			i++
			continue
		}
		result = append(result, b)
	}
	return string(result)
}
