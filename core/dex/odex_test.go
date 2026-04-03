package dex

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// createTestODEX creates a minimal valid ODEX file for testing.
func createTestODEX() []byte {
	// First create a minimal DEX file
	dexData := createMinimalDEX()

	// ODEX header is 40 bytes
	// Dependencies section: 16 bytes header + dependencies
	depsData := createMinimalDependencies()

	// Calculate offsets
	odexHeaderSize := 40
	dexOffset := uint32(odexHeaderSize)
	dexLength := uint32(len(dexData))
	depsOffset := dexOffset + dexLength
	depsLength := uint32(len(depsData))
	totalSize := odexHeaderSize + len(dexData) + len(depsData)

	buf := new(bytes.Buffer)

	// Write ODEX magic (dey\n036\0)
	buf.Write([]byte("dey\n036\x00"))

	// Write ODEX header fields
	binary.Write(buf, binary.LittleEndian, dexOffset)
	binary.Write(buf, binary.LittleEndian, dexLength)
	binary.Write(buf, binary.LittleEndian, depsOffset)
	binary.Write(buf, binary.LittleEndian, depsLength)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // aux_offset
	binary.Write(buf, binary.LittleEndian, uint32(0)) // aux_length
	binary.Write(buf, binary.LittleEndian, uint32(0)) // flags
	binary.Write(buf, binary.LittleEndian, uint32(0)) // padding

	// Write embedded DEX
	buf.Write(dexData)

	// Write dependencies
	buf.Write(depsData)

	if buf.Len() != totalSize {
		panic("ODEX size mismatch")
	}

	return buf.Bytes()
}

// createMinimalDEX creates a minimal valid DEX file for testing.
func createMinimalDEX() []byte {
	buf := new(bytes.Buffer)

	// DEX header (112 bytes minimum)
	// Magic: dex\n035\0
	buf.Write([]byte("dex\n035\x00"))

	// checksum (placeholder)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// signature (20 bytes placeholder)
	buf.Write(make([]byte, 20))

	// file_size (placeholder, will be set later)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// header_size = 0x70 (112)
	binary.Write(buf, binary.LittleEndian, uint32(0x70))

	// endian_tag = 0x12345678
	binary.Write(buf, binary.LittleEndian, uint32(0x12345678))

	// link_size = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// link_off = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// map_off (point to end of header)
	binary.Write(buf, binary.LittleEndian, uint32(0x70))

	// string_ids
	binary.Write(buf, binary.LittleEndian, uint32(0)) // size
	binary.Write(buf, binary.LittleEndian, uint32(0)) // offset

	// type_ids
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// proto_ids
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// field_ids
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// method_ids
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// class_defs
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// data_size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// data_off
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Add padding to reach minimum 116 bytes
	for buf.Len() < 116 {
		buf.WriteByte(0)
	}

	data := buf.Bytes()

	// Set file_size
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(data)))

	// Calculate adler32 checksum
	checksum := adler32(data[12:])
	binary.LittleEndian.PutUint32(data[8:12], checksum)

	return data
}

// createMinimalDependencies creates minimal ODEX dependencies section.
func createMinimalDependencies() []byte {
	buf := new(bytes.Buffer)

	// modification_time
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// crc
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// dalvik_build
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// dependency_count
	binary.Write(buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

func TestParseODEX(t *testing.T) {
	data := createTestODEX()

	dex, err := ParseODEX(data)
	if err != nil {
		t.Fatalf("ParseODEX failed: %v", err)
	}

	if !dex.IsODEXFile {
		t.Error("IsODEXFile should be true for ODEX file")
	}

	if !dex.IsODEX() {
		t.Error("IsODEX() should return true for ODEX file")
	}

	if dex.ODEXHeader == nil {
		t.Fatal("ODEXHeader should not be nil")
	}

	if dex.ODEXHeader.DexOffset != 40 {
		t.Errorf("DexOffset = %d, want 40", dex.ODEXHeader.DexOffset)
	}

	if dex.ODEXHeader.DexLength == 0 {
		t.Error("DexLength should not be 0")
	}

	if dex.Dependencies == nil {
		t.Error("Dependencies should not be nil")
	}

	if len(dex.Dependencies) != 0 {
		t.Errorf("Dependencies count = %d, want 0", len(dex.Dependencies))
	}
}

func TestParseODEXViaParse(t *testing.T) {
	data := createTestODEX()

	// Parse should automatically detect ODEX and handle it
	dex, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed for ODEX: %v", err)
	}

	if !dex.IsODEX() {
		t.Error("IsODEX() should return true")
	}

	if dex.GetFormatType() != "ODEX" {
		t.Errorf("GetFormatType() = %q, want 'ODEX'", dex.GetFormatType())
	}
}

func TestParseODEXHeader(t *testing.T) {
	data := createTestODEX()

	header, err := ParseODEXHeader(data)
	if err != nil {
		t.Fatalf("ParseODEXHeader failed: %v", err)
	}

	if header.DexOffset != 40 {
		t.Errorf("DexOffset = %d, want 40", header.DexOffset)
	}

	if header.DexLength == 0 {
		t.Error("DexLength should not be 0")
	}

	if header.Dependencies != header.DexOffset+header.DexLength {
		t.Errorf("Dependencies offset mismatch: got %d, want %d",
			header.Dependencies, header.DexOffset+header.DexLength)
	}
}

func TestParseODEXDependencies(t *testing.T) {
	data := createTestODEX()

	header, err := ParseODEXHeader(data)
	if err != nil {
		t.Fatalf("ParseODEXHeader failed: %v", err)
	}

	deps, err := ParseODEXDependencies(data, header.Dependencies, header.DependenciesLength)
	if err != nil {
		t.Fatalf("ParseODEXDependencies failed: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("Dependencies count = %d, want 0", len(deps))
	}
}

func TestParseODEXInvalidMagic(t *testing.T) {
	data := []byte("dex\n035\x00" + string(make([]byte, 100)))

	_, err := ParseODEXHeader(data)
	if err == nil {
		t.Error("ParseODEXHeader should fail for non-ODEX magic")
	}
}

func TestParseODEXTooShort(t *testing.T) {
	data := []byte("dey\n036\x00")

	_, err := ParseODEX(data)
	if err == nil {
		t.Error("ParseODEX should fail for too short data")
	}
}
