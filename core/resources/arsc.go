// Package arsc parses Android Resource Table (.arsc) files.
// ARSC files contain compiled resources (strings, layouts, drawables, etc.)
// and are found inside APK files as resources.arsc.
package resources

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/grassto/androguard-go/internal/leb128"
)

// Resource chunk types
const (
	ResNullType         = 0x0000
	ResStringPoolType   = 0x0001
	ResTableType        = 0x0002
	ResTablePackageType = 0x0200
	ResTableTypeType    = 0x0201
	ResTableTypeSpecType = 0x0202
	ResTableLibraryType = 0x0203
)

// Flags
const (
	SortedFlag = 1 << 0
	UTF8Flag   = 1 << 8
)

// ARSCHeader represents the common resource chunk header
type ARSCHeader struct {
	ChunkType  uint16
	HeaderSize uint16
	ChunkSize  uint32
}

// ResourceTable represents the full parsed resource table
type ResourceTable struct {
	Packages  []ResourcePackage
	StringPool []string
}

// ResourcePackage represents a resource package (usually one per APK)
type ResourcePackage struct {
	ID         uint32
	Name       string
	TypeStrings []string
	KeyStrings  []string
	TypeSpecs   []TypeSpec
	Types       []ResourceType
}

// TypeSpec holds type specification for a resource type
type TypeSpec struct {
	ID    uint32
	Name  string
	Flags []uint32 // Entry configuration flags
}

// ResourceType holds a resource type with entries for a specific configuration
type ResourceType struct {
	ID         uint32
	Name       string
	Config     ResTableConfig
	Entries    []ResourceEntry
}

// ResTableConfig represents a resource configuration (locale, screen size, etc.)
type ResTableConfig struct {
	MCC         uint16
	MNC         uint16
	Language    [2]byte
	Country     [2]byte
	Orientation uint8
	Touchscreen uint8
	Density     uint16
	ScreenSize  uint8
	Version     uint16
	ScreenConfig uint32
	LocaleScript [4]byte
}

// ResourceEntry represents a single resource entry
type ResourceEntry struct {
	Index   uint32
	Name    string
	Value   *ResourceValue
	Complex *ResourceComplexValue
}

// ResourceValue represents a simple resource value
type ResourceValue struct {
	Size     uint16
	Res0     uint8
	DataType uint8
	Data     uint32
}

// ResourceComplexValue represents a complex (map/attr) resource value
type ResourceComplexValue struct {
	Parent uint32
	Count  uint32
	Entries []MapEntry
}

// MapEntry represents a single entry in a complex resource
type MapEntry struct {
	Name  uint32
	Value ResourceValue
}

// ARSCParser is the main parser for Android Resource Table files
type ARSCParser struct {
	data []byte
	pos  int
}

// NewARSCParser creates a new ARSC parser
func NewARSCParser(data []byte) *ARSCParser {
	return &ARSCParser{data: data}
}

// Parse parses the entire resource table
func (p *ARSCParser) Parse() (*ResourceTable, error) {
	table := &ResourceTable{}
	p.pos = 0

	// Read table header
	header, err := p.readHeader()
	if err != nil {
		return nil, fmt.Errorf("arsc: reading header: %w", err)
	}

	if header.ChunkType != ResTableType {
		return nil, fmt.Errorf("arsc: expected ResTable type (0x%x), got 0x%x", ResTableType, header.ChunkType)
	}

	// Read package count (immediately after the 8-byte chunk header)
	if p.pos+12 > len(p.data) {
		return nil, fmt.Errorf("arsc: cannot read package count")
	}
	packageCount := binary.LittleEndian.Uint32(p.data[p.pos+8 : p.pos+12])
	_ = packageCount

	// Advance past the full header
	p.pos += int(header.HeaderSize)

	// Parse chunks until end of table
	tableEnd := int(header.ChunkSize)
	for p.pos < tableEnd && p.pos < len(p.data) {
		if p.pos+8 > len(p.data) {
			break
		}

		chunkType := binary.LittleEndian.Uint16(p.data[p.pos : p.pos+2])
		chunkSize := int(binary.LittleEndian.Uint32(p.data[p.pos+4 : p.pos+8]))

		if chunkSize <= 0 {
			break
		}

		switch chunkType {
		case ResStringPoolType:
			pool, err := p.parseStringPool(p.pos)
			if err != nil {
				return nil, fmt.Errorf("arsc: string pool: %w", err)
			}
			table.StringPool = pool
			p.pos += chunkSize

		case ResTablePackageType:
			pkg, err := p.parsePackage(p.pos)
			if err != nil {
				return nil, fmt.Errorf("arsc: package: %w", err)
			}
			table.Packages = append(table.Packages, *pkg)
			p.pos += chunkSize

		default:
			// Skip unknown chunks
			p.pos += chunkSize
		}
	}

	return table, nil
}

func (p *ARSCParser) readHeader() (ARSCHeader, error) {
	if p.pos+8 > len(p.data) {
		return ARSCHeader{}, io.ErrUnexpectedEOF
	}
	header := ARSCHeader{
		ChunkType:  binary.LittleEndian.Uint16(p.data[p.pos : p.pos+2]),
		HeaderSize: binary.LittleEndian.Uint16(p.data[p.pos+2 : p.pos+4]),
		ChunkSize:  binary.LittleEndian.Uint32(p.data[p.pos+4 : p.pos+8]),
	}
	return header, nil
}

func (p *ARSCParser) parseStringPool(offset int) ([]string, error) {
	if offset+28 > len(p.data) {
		return nil, fmt.Errorf("string pool header too short")
	}

	data := p.data[offset:]
	stringCount := binary.LittleEndian.Uint32(data[8:12])
	styleCount := binary.LittleEndian.Uint32(data[12:16])
	flags := binary.LittleEndian.Uint32(data[16:20])
	stringsOffset := binary.LittleEndian.Uint32(data[20:24])
	_ = styleCount

	isUTF8 := (flags & UTF8Flag) != 0

	// Read string offsets
	stringOffsets := make([]uint32, stringCount)
	for i := uint32(0); i < stringCount; i++ {
		off := 28 + i*4
		if int(off)+4 > len(data) {
			break
		}
		stringOffsets[i] = binary.LittleEndian.Uint32(data[off : off+4])
	}

	// Read strings
	stringDataStart := int(stringsOffset)
	result := make([]string, stringCount)

	for i := uint32(0); i < stringCount; i++ {
		strOff := stringDataStart + int(stringOffsets[i])
		if strOff >= len(data) {
			continue
		}

		if isUTF8 {
			result[i] = decodeUTF8(data, strOff)
		} else {
			result[i] = decodeUTF16(data, strOff)
		}
	}

	return result, nil
}

func decodeUTF8(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}

	// Skip length fields
	strLen, n := leb128.ReadULEB128(data[offset:])
	offset += n
	_, n2 := leb128.ReadULEB128(data[offset:])
	offset += n2
	_ = strLen

	// Find null terminator
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

func decodeUTF16(data []byte, offset int) string {
	if offset+2 > len(data) {
		return ""
	}

	// UTF-16 string length is a plain uint16, not ULEB128
	strLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+strLen*2 > len(data) {
		return ""
	}

	runes := make([]rune, 0, strLen)
	for i := 0; i < strLen; i++ {
		ch := binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		runes = append(runes, rune(ch))
	}

	return string(runes)
}

func (p *ARSCParser) parsePackage(offset int) (*ResourcePackage, error) {
	if offset+288 > len(p.data) {
		return nil, fmt.Errorf("package header too short")
	}

	data := p.data[offset:]
	pkg := &ResourcePackage{}

	pkg.ID = binary.LittleEndian.Uint32(data[8:12])

	// Package name is 256 bytes of UTF-16 LE
	nameBytes := data[12:268]
	pkg.Name = decodeUTF16Name(nameBytes)

	// Type strings offset
	typeStringsOffset := binary.LittleEndian.Uint32(data[268:272])
	lastPublicType := binary.LittleEndian.Uint32(data[272:276])

	// Key strings offset
	keyStringsOffset := binary.LittleEndian.Uint32(data[276:280])
	lastPublicKey := binary.LittleEndian.Uint32(data[280:284])
	_ = lastPublicType
	_ = lastPublicKey

	// Parse type string pool
	var typeStringPoolSize int
	if typeStringsOffset > 0 {
		pool, err := p.parseStringPool(offset + int(typeStringsOffset))
		if err == nil {
			pkg.TypeStrings = pool
		}
		// Get the string pool chunk size to skip past it
		spOff := offset + int(typeStringsOffset)
		if spOff+8 <= len(p.data) {
			typeStringPoolSize = int(binary.LittleEndian.Uint32(p.data[spOff+4 : spOff+8]))
		}
	}

	// Parse key string pool
	var keyStringPoolSize int
	if keyStringsOffset > 0 {
		pool, err := p.parseStringPool(offset + int(keyStringsOffset))
		if err == nil {
			pkg.KeyStrings = pool
		}
		// Get the string pool chunk size to skip past it
		spOff := offset + int(keyStringsOffset)
		if spOff+8 <= len(p.data) {
			keyStringPoolSize = int(binary.LittleEndian.Uint32(p.data[spOff+4 : spOff+8]))
		}
	}

	// Parse type specs and types
	// Start after the last string pool (whichever comes last)
	pkgEnd := offset + int(binary.LittleEndian.Uint32(data[4:8]))
	pos := offset + 288
	if int(typeStringsOffset) >= int(keyStringsOffset) {
		pos = offset + int(typeStringsOffset) + typeStringPoolSize
	} else {
		pos = offset + int(keyStringsOffset) + keyStringPoolSize
	}

	for pos < pkgEnd && pos < len(p.data) {
		if pos+8 > len(p.data) {
			break
		}

		chunkType := binary.LittleEndian.Uint16(p.data[pos : pos+2])
		chunkSize := int(binary.LittleEndian.Uint32(p.data[pos+4 : pos+8]))

		if chunkSize <= 0 {
			break
		}

		switch chunkType {
		case ResTableTypeSpecType:
			spec, err := p.parseTypeSpec(pos, pkg.TypeStrings)
			if err == nil {
				pkg.TypeSpecs = append(pkg.TypeSpecs, *spec)
			}
			pos += chunkSize

		case ResTableTypeType:
			typ, err := p.parseType(pos, pkg.TypeStrings, pkg.KeyStrings)
			if err == nil {
				pkg.Types = append(pkg.Types, *typ)
			}
			pos += chunkSize

		default:
			pos += chunkSize
		}
	}

	return pkg, nil
}

func decodeUTF16Name(data []byte) string {
	runes := make([]rune, 0, 128)
	for i := 0; i+1 < len(data); i += 2 {
		ch := binary.LittleEndian.Uint16(data[i : i+2])
		if ch == 0 {
			break
		}
		runes = append(runes, rune(ch))
	}
	return string(runes)
}

func (p *ARSCParser) parseTypeSpec(offset int, typeStrings []string) (*TypeSpec, error) {
	if offset+16 > len(p.data) {
		return nil, fmt.Errorf("type spec header too short")
	}

	data := p.data[offset:]
	spec := &TypeSpec{}
	spec.ID = uint32(data[8])

	entryCount := binary.LittleEndian.Uint32(data[12:16])

	// Get type name from type strings
	if int(spec.ID-1) < len(typeStrings) {
		spec.Name = typeStrings[spec.ID-1]
	}

	// Read flags
	spec.Flags = make([]uint32, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		off := 16 + i*4
		if int(off)+4 > len(data) {
			break
		}
		spec.Flags[i] = binary.LittleEndian.Uint32(data[off : off+4])
	}

	return spec, nil
}

func (p *ARSCParser) parseType(offset int, typeStrings, keyStrings []string) (*ResourceType, error) {
	if offset+20 > len(p.data) {
		return nil, fmt.Errorf("type header too short")
	}

	data := p.data[offset:]
	typ := &ResourceType{}
	typ.ID = uint32(data[8])
	headerSize := binary.LittleEndian.Uint16(data[2:4])

	if int(typ.ID-1) < len(typeStrings) {
		typ.Name = typeStrings[typ.ID-1]
	}

	entryCount := binary.LittleEndian.Uint32(data[12:16])
	entriesStart := binary.LittleEndian.Uint32(data[16:20])

	// Read config (starts at offset 20 from chunk start)
	configData := data[20:]
	if len(configData) >= 64 {
		typ.Config.MCC = binary.LittleEndian.Uint16(configData[4:6])
		typ.Config.MNC = binary.LittleEndian.Uint16(configData[6:8])
		copy(typ.Config.Language[:], configData[8:10])
		copy(typ.Config.Country[:], configData[10:12])
		typ.Config.Orientation = uint8(configData[12])
		typ.Config.Touchscreen = uint8(configData[13])
		typ.Config.Density = binary.LittleEndian.Uint16(configData[14:16])
		typ.Config.Version = binary.LittleEndian.Uint16(configData[24:26])
	}

	// Read entry offsets
	// The offset table is between the header (headerSize) and the entry data (entriesStart).
	// Each offset is relative to entriesStart.
	entryOffsets := make([]uint32, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		off := offset + int(headerSize) + int(i)*4
		if off+4 > len(p.data) {
			break
		}
		entryOffsets[i] = binary.LittleEndian.Uint32(p.data[off : off+4])
	}

	// Parse entries
	typ.Entries = make([]ResourceEntry, 0, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		if entryOffsets[i] == 0xFFFFFFFF {
			continue // No entry
		}

		entry := ResourceEntry{Index: i}

		entryOffset := offset + int(entriesStart) + int(entryOffsets[i])
		if entryOffset+8 > len(p.data) {
			typ.Entries = append(typ.Entries, entry)
			continue
		}

		entrySize := binary.LittleEndian.Uint16(p.data[entryOffset : entryOffset+2])
		flags := binary.LittleEndian.Uint16(p.data[entryOffset+2 : entryOffset+4])
		key := binary.LittleEndian.Uint32(p.data[entryOffset+4 : entryOffset+8])

		// Get key name from the entry's key field, not the loop index
		if int(key) < len(keyStrings) {
			entry.Name = keyStrings[key]
		}


		if flags&1 != 0 {
			// Complex entry
			if entryOffset+int(entrySize) <= len(p.data) {
				complexVal := &ResourceComplexValue{
					Parent: binary.LittleEndian.Uint32(p.data[entryOffset+8 : entryOffset+12]),
					Count:  binary.LittleEndian.Uint32(p.data[entryOffset+12 : entryOffset+16]),
				}

				mapOffset := entryOffset + 16
				for j := uint32(0); j < complexVal.Count; j++ {
					if mapOffset+8 > len(p.data) {
						break
					}
					me := MapEntry{
						Name: binary.LittleEndian.Uint32(p.data[mapOffset : mapOffset+4]),
					}
					me.Value.Size = binary.LittleEndian.Uint16(p.data[mapOffset+4 : mapOffset+6])
					me.Value.Res0 = p.data[mapOffset+6]
					me.Value.DataType = p.data[mapOffset+7]
					me.Value.Data = binary.LittleEndian.Uint32(p.data[mapOffset+8 : mapOffset+12])
					complexVal.Entries = append(complexVal.Entries, me)
					mapOffset += 12
				}

				entry.Complex = complexVal
			}
		} else {
			// Simple entry
			valOffset := entryOffset + int(entrySize)
			if valOffset+8 <= len(p.data) {
				val := &ResourceValue{
					Size:     binary.LittleEndian.Uint16(p.data[valOffset : valOffset+2]),
					Res0:     p.data[valOffset+2],
					DataType: p.data[valOffset+3],
					Data:     binary.LittleEndian.Uint32(p.data[valOffset+4 : valOffset+8]),
				}
				entry.Value = val
			}
		}

		typ.Entries = append(typ.Entries, entry)
	}

	return typ, nil
}

// GetResourceValueString returns a human-readable string for a resource value.
func GetResourceValueString(val *ResourceValue, stringPool []string) string {
	if val == nil {
		return ""
	}

	switch val.DataType {
	case 0x03: // String
		if int(val.Data) < len(stringPool) {
			return stringPool[val.Data]
		}
		return fmt.Sprintf("@string/%d", val.Data)
	case 0x01: // Reference
		return fmt.Sprintf("@0x%08x", val.Data)
	case 0x10: // Int dec
		return fmt.Sprintf("%d", int32(val.Data))
	case 0x11: // Int hex
		return fmt.Sprintf("0x%x", val.Data)
	case 0x12: // Boolean
		if val.Data != 0 {
			return "true"
		}
		return "false"
	case 0x1C: // Color ARGB8
		return fmt.Sprintf("#%08x", val.Data)
	case 0x1D: // Color RGB8
		return fmt.Sprintf("#%06x", val.Data&0xFFFFFF)
	case 0x1E: // Color ARGB4
		return fmt.Sprintf("#%04x", val.Data&0xFFFF)
	case 0x1F: // Color RGB4
		return fmt.Sprintf("#%03x", val.Data&0xFFF)
	default:
		return fmt.Sprintf("0x%x", val.Data)
	}
}

// ParseARSC is a convenience function to parse ARSC data.
func ParseARSC(data []byte) (*ResourceTable, error) {
	parser := NewARSCParser(data)
	return parser.Parse()
}
