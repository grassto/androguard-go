// Package leb128 implements LEB128 (Little Endian Base 128) variable-length
// encoding for signed and unsigned integers, used extensively in DEX format.
package leb128

import (
	"encoding/binary"
	"io"
)

// ReadULEB128 reads an unsigned LEB128 value from a byte slice.
// Returns the value and the number of bytes consumed.
func ReadULEB128(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return result, len(data)
}

// ReadULEB128FromReader reads an unsigned LEB128 value from a reader.
func ReadULEB128FromReader(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint
	buf := make([]byte, 1)
	for {
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
}

// ReadSLEB128 reads a signed LEB128 value from a byte slice.
// Returns the value and the number of bytes consumed.
func ReadSLEB128(data []byte) (int64, int) {
	var result int64
	var shift uint
	for i, b := range data {
		result |= int64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && (b&0x40) != 0 {
				result |= -(1 << shift)
			}
			return result, i + 1
		}
	}
	return result, len(data)
}

// ReadSLEB128FromReader reads a signed LEB128 value from a reader.
func ReadSLEB128FromReader(r io.Reader) (int64, error) {
	var result int64
	var shift uint
	buf := make([]byte, 1)
	for {
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= int64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && (b&0x40) != 0 {
				result |= -(1 << shift)
			}
			return result, nil
		}
	}
}

// ReadUleb128p1 reads a ULEB128 value and subtracts 1 (used in debug info).
func ReadUleb128p1(data []byte) (int64, int) {
	val, n := ReadULEB128(data)
	return int64(val) - 1, n
}

// ReadUint16 reads a little-endian uint16 from data.
func ReadUint16(data []byte) uint16 {
	return binary.LittleEndian.Uint16(data)
}

// ReadUint32 reads a little-endian uint32 from data.
func ReadUint32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

// ReadUint64 reads a little-endian uint64 from data.
func ReadUint64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

// MUTF8Decode decodes Modified UTF-8 (MUTF-8) byte sequence to a Go string.
// MUTF-8 is used in DEX files and differs from standard UTF-8:
// - NULL bytes are encoded as 0xC0 0x80
// - Supplementary characters are encoded as surrogate pairs
func MUTF8Decode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	runes := make([]rune, 0, len(data))
	i := 0
	for i < len(data) {
		b := data[i]
		if b == 0 {
			break
		}

		switch {
		case b&0x80 == 0:
			// 1-byte: 0xxxxxxx
			runes = append(runes, rune(b))
			i++
		case b&0xE0 == 0xC0:
			// 2-byte: 110xxxxx 10xxxxxx
			if i+1 >= len(data) {
				return string(runes)
			}
			b2 := data[i+1]
			r := rune(b&0x1F)<<6 | rune(b2&0x3F)
			runes = append(runes, r)
			i += 2
		case b&0xF0 == 0xE0:
			// 3-byte: 1110xxxx 10xxxxxx 10xxxxxx
			if i+2 >= len(data) {
				return string(runes)
			}
			b2 := data[i+1]
			b3 := data[i+2]
			r := rune(b&0x0F)<<12 | rune(b2&0x3F)<<6 | rune(b3&0x3F)
			// Handle surrogate pairs
			if r >= 0xD800 && r <= 0xDBFF && i+5 < len(data) {
				if data[i+3] == 0xED {
					b4 := data[i+4]
					b5 := data[i+5]
					if b4 >= 0xB0 && b4 <= 0xBF {
						r2 := rune(b4&0x0F)<<6 | rune(b5&0x3F)
						r = 0x10000 + (r-0xD800)*0x400 + (r2 - 0xDC00)
						i += 6
						runes = append(runes, r)
						continue
					}
				}
			}
			runes = append(runes, r)
			i += 3
		default:
			i++
		}
	}
	return string(runes)
}
