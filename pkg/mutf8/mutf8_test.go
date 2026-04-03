package mutf8

import (
	"testing"
)

func TestDecodeEncode(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"ascii", "hello world"},
		{"null_byte", "hello\x00world"},
		{"unicode", "你好世界"},
		{"emoji", "😀🎉"},
		{"mixed", "Hello 世界 😀"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Encode(tt.input)
			decoded, err := Decode(encoded)
			if err != nil {
				t.Errorf("Decode(Encode(%q)) error: %v", tt.input, err)
				return
			}
			if decoded != tt.input {
				t.Errorf("Decode(Encode(%q)) = %q, want %q", tt.input, decoded, tt.input)
			}
		})
	}
}

func TestDecodeNullEncoding(t *testing.T) {
	// MUTF-8 encodes NULL as 0xC0 0x80
	data := []byte{0xC0, 0x80}
	decoded, err := Decode(data)
	if err != nil {
		t.Errorf("Decode failed: %v", err)
		return
	}
	if decoded != "\x00" {
		t.Errorf("Decode([0xC0, 0x80]) = %q, want %q", decoded, "\x00")
	}
}

func TestEncodeNullByte(t *testing.T) {
	encoded := Encode("\x00")
	if len(encoded) != 2 || encoded[0] != 0xC0 || encoded[1] != 0x80 {
		t.Errorf("Encode(\"\\x00\") = %v, want [0xC0, 0x80]", encoded)
	}
}

func TestByteCount(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"a", 1},
		{"ab", 2},
		{"\x00", 2}, // NULL is 2 bytes in MUTF-8
		{"中文", 6},  // 3 bytes each
	}

	for _, tt := range tests {
		got := ByteCount(tt.input)
		if got != tt.want {
			t.Errorf("ByteCount(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestValid(t *testing.T) {
	tests := []struct {
		data  []byte
		valid bool
	}{
		{[]byte("hello"), true},
		{[]byte{0xC0, 0x80}, true},      // MUTF-8 NULL
		{[]byte{0x80, 0x80}, false},      // Invalid start byte
		{[]byte{0xC0}, false},            // Truncated
		{[]byte{0xE0, 0x80}, false},      // Truncated 3-byte
	}

	for _, tt := range tests {
		got := Valid(tt.data)
		if got != tt.valid {
			t.Errorf("Valid(%v) = %v, want %v", tt.data, got, tt.valid)
		}
	}
}

func TestUTF16(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"ascii", "hello"},
		{"unicode", "你好"},
		{"emoji", "😀"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeUTF16(tt.input)
			decoded, err := DecodeUTF16(encoded)
			if err != nil {
				t.Errorf("DecodeUTF16(EncodeUTF16(%q)) error: %v", tt.input, err)
				return
			}
			if decoded != tt.input {
				t.Errorf("Roundtrip failed: got %q, want %q", decoded, tt.input)
			}
		})
	}
}

func TestTrimNullTerminator(t *testing.T) {
	tests := []struct {
		input []byte
		want  int // Expected length
	}{
		{[]byte("hello\x00"), 5},
		{[]byte("hello"), 5},
		{[]byte{0xC0, 0x80}, 0},
		{[]byte("a"), 1},
		{[]byte{}, 0},
	}

	for _, tt := range tests {
		got := TrimNullTerminator(tt.input)
		if len(got) != tt.want {
			t.Errorf("TrimNullTerminator(%v) length = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}
