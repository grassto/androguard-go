// Package mutf8 implements Modified UTF-8 (MUTF-8) encoding and decoding.
// MUTF-8 is used in DEX files and Java class files.
// It differs from standard UTF-8 in that:
// - The NULL byte (U+0000) is encoded as 0xC0 0x80 instead of 0x00
// - Supplementary characters (U+10000 and above) are encoded as surrogate pairs
package mutf8

import (
	"errors"
	"unicode/utf16"
)

// Errors
var (
	ErrInvalidMUTF8       = errors.New("mutf8: invalid MUTF-8 encoding")
	ErrTruncatedMUTF8     = errors.New("mutf8: truncated MUTF-8 sequence")
	ErrInvalidSurrogate   = errors.New("mutf8: invalid surrogate pair")
)

// Decode decodes a Modified UTF-8 byte slice into a Go string.
// MUTF-8 encodes NULL as 0xC0 0x80 and supports surrogate pairs.
func Decode(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	buf := make([]rune, 0, len(data))
	i := 0

	for i < len(data) {
		b := data[i]

		if b == 0 {
			// In MUTF-8, a bare 0 byte should not appear in valid strings
			// But some implementations treat it as end of string
			break
		}

		switch {
		case b&0x80 == 0:
			// 1-byte sequence: 0xxxxxxx (1-127)
			buf = append(buf, rune(b))
			i++

		case b&0xE0 == 0xC0:
			// 2-byte sequence: 110xxxxx 10xxxxxx
			if i+1 >= len(data) {
				return "", ErrTruncatedMUTF8
			}
			b2 := data[i+1]
			if b2&0xC0 != 0x80 {
				return "", ErrInvalidMUTF8
			}
			r := rune(b&0x1F)<<6 | rune(b2&0x3F)
			buf = append(buf, r)
			i += 2

		case b&0xF0 == 0xE0:
			// 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx
			if i+2 >= len(data) {
				return "", ErrTruncatedMUTF8
			}
			b2 := data[i+1]
			b3 := data[i+2]
			if b2&0xC0 != 0x80 || b3&0xC0 != 0x80 {
				return "", ErrInvalidMUTF8
			}
			r := rune(b&0x0F)<<12 | rune(b2&0x3F)<<6 | rune(b3&0x3F)

			// Check for high surrogate
			if utf16.IsSurrogate(r) {
				// MUTF-8 encodes supplementary characters as surrogate pairs
				// Try to read the low surrogate (also a 3-byte sequence)
				if i+5 < len(data) {
					b4 := data[i+3]
					b5 := data[i+4]
					b6 := data[i+5]
					if b4&0xF0 == 0xE0 && b5&0xC0 == 0x80 && b6&0xC0 == 0x80 {
						r2 := rune(b4&0x0F)<<12 | rune(b5&0x3F)<<6 | rune(b6&0x3F)
						if utf16.IsSurrogate(r2) {
							// Valid surrogate pair - decode to single codepoint
							decoded := utf16.DecodeRune(r, r2)
							buf = append(buf, decoded)
							i += 6
							continue
						}
					}
				}
				// Invalid surrogate pair - keep the high surrogate
				buf = append(buf, r)
			} else {
				buf = append(buf, r)
			}
			i += 3

		default:
			// Invalid byte
			return "", ErrInvalidMUTF8
		}
	}

	return string(buf), nil
}

// Encode encodes a Go string into Modified UTF-8 bytes.
// NULL bytes are encoded as 0xC0 0x80.
// Supplementary characters are encoded as surrogate pairs.
func Encode(s string) []byte {
	buf := make([]byte, 0, len(s)*3/2)

	for _, r := range s {
		switch {
		case r == 0:
			// NULL is encoded as 0xC0 0x80 in MUTF-8
			buf = append(buf, 0xC0, 0x80)

		case r >= 1 && r <= 0x7F:
			// 1-byte sequence
			buf = append(buf, byte(r))

		case r >= 0x80 && r <= 0x7FF:
			// 2-byte sequence
			buf = append(buf, 0xC0|byte(r>>6), 0x80|byte(r&0x3F))

		case r >= 0x800 && r <= 0xFFFF:
			// 3-byte sequence
			buf = append(buf, 0xE0|byte(r>>12), 0x80|byte((r>>6)&0x3F), 0x80|byte(r&0x3F))

		case r >= 0x10000 && r <= 0x10FFFF:
			// Supplementary character - encode as surrogate pair in MUTF-8
			// Each surrogate is encoded as a 3-byte sequence
			hi, lo := utf16.EncodeRune(r)
			// High surrogate: 0xED 0xA0+ 0x80+
			buf = append(buf, 0xE0|byte(hi>>12), 0x80|byte((hi>>6)&0x3F), 0x80|byte(hi&0x3F))
			// Low surrogate: 0xED 0xB0+ 0x80+
			buf = append(buf, 0xE0|byte(lo>>12), 0x80|byte((lo>>6)&0x3F), 0x80|byte(lo&0x3F))

		default:
			// Invalid codepoint - skip
		}
	}

	return buf
}

// DecodeUTF16 decodes UTF-16 LE bytes to a Go string.
func DecodeUTF16(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	if len(data)%2 != 0 {
		return "", errors.New("mutf8: odd length UTF-16 data")
	}

	runes := make([]uint16, len(data)/2)
	for i := 0; i < len(runes); i++ {
		runes[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}

	return string(utf16.Decode(runes)), nil
}

// EncodeUTF16 encodes a Go string to UTF-16 LE bytes.
func EncodeUTF16(s string) []byte {
	runes := utf16.Encode([]rune(s))
	data := make([]byte, len(runes)*2)
	for i, r := range runes {
		data[i*2] = byte(r)
		data[i*2+1] = byte(r >> 8)
	}
	return data
}

// DecodeUTF16BE decodes UTF-16 BE bytes to a Go string.
func DecodeUTF16BE(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	if len(data)%2 != 0 {
		return "", errors.New("mutf8: odd length UTF-16 data")
	}

	runes := make([]uint16, len(data)/2)
	for i := 0; i < len(runes); i++ {
		runes[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
	}

	return string(utf16.Decode(runes)), nil
}

// ByteCount returns the number of bytes needed to encode s in MUTF-8.
func ByteCount(s string) int {
	count := 0
	for _, r := range s {
		switch {
		case r == 0:
			count += 2
		case r >= 1 && r <= 0x7F:
			count++
		case r >= 0x80 && r <= 0x7FF:
			count += 2
		case r >= 0x800 && r <= 0xFFFF:
			count += 3
		case r >= 0x10000 && r <= 0x10FFFF:
			count += 6 // Surrogate pair
		}
	}
	return count
}

// Valid reports whether data consists of valid MUTF-8 encoding.
func Valid(data []byte) bool {
	_, err := Decode(data)
	return err == nil
}

// UTF16Count returns the number of UTF-16 code units in the MUTF-8 encoded data.
func UTF16Count(data []byte) (int, error) {
	s, err := Decode(data)
	if err != nil {
		return 0, err
	}
	return RuneCountUTF16(s), nil
}

// RuneCountUTF16 returns the number of UTF-16 code units needed to encode s.
func RuneCountUTF16(s string) int {
	count := 0
	for _, r := range s {
		count++
		if r >= 0x10000 {
			count++ // Supplementary characters need 2 UTF-16 code units
		}
	}
	return count
}

// Compare compares two MUTF-8 encoded byte slices lexicographically.
func Compare(a, b []byte) int {
	sa, errA := Decode(a)
	sb, errB := Decode(b)

	if errA != nil || errB != nil {
		// Fall back to byte comparison
		minLen := len(a)
		if len(b) < minLen {
			minLen = len(b)
		}
		for i := 0; i < minLen; i++ {
			if a[i] < b[i] {
				return -1
			}
			if a[i] > b[i] {
				return 1
			}
		}
		return len(a) - len(b)
	}

	if sa < sb {
		return -1
	}
	if sa > sb {
		return 1
	}
	return 0
}

// TrimNullTerminator removes a null terminator from the end of MUTF-8 data.
func TrimNullTerminator(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == 0 {
		return data[:len(data)-1]
	}
	// Check for MUTF-8 encoded null (0xC0 0x80)
	if len(data) >= 2 && data[len(data)-2] == 0xC0 && data[len(data)-1] == 0x80 {
		return data[:len(data)-2]
	}
	return data
}
