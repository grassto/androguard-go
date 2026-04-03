package dex

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
)

// adler32 function is defined in dex.go
// We use the standard library for checksum computation here.

// ODEX header (Optimized DEX)
type ODEXHeader struct {
	Magic         [8]byte  // "dey\n036\0" or similar
	DexOffset     uint32   // Offset to embedded DEX
	DexLength     uint32   // Length of embedded DEX
	Dependencies  uint32   // Offset to dependency table
	DependenciesLength uint32 // Length of dependency table
	Flags         uint32   // ODEX flags
	Padding       [20]byte // Padding to 48 bytes
}

// ODEXDependency represents a dependency in an ODEX file.
type ODEXDependency struct {
	Name    string
	ModTime uint32
	CRC     uint32
}

// HiddenApiClassDataItem represents hidden API restriction info.
type HiddenApiClassDataItem struct {
	Size       uint32
	Flags      []HiddenApiFlags
	DeltaIndex []uint32
	Secret     []uint32
}

// HiddenApiFlags represents hidden API flag values.
type HiddenApiFlags uint8

const (
	HiddenApiWhitelist      HiddenApiFlags = 0x0  // Public API
	HiddenApiGreylist       HiddenApiFlags = 0x1  // Greylist (allowed with warning)
	HiddenApiBlacklist      HiddenApiFlags = 0x2  // Blacklisted
	HiddenApiCorePlatformApi HiddenApiFlags = 0x3 // Core platform API
	HiddenApiTestApi        HiddenApiFlags = 0x4  // Test API
)

// DexFile extension methods

// Save serializes the DEX file back to bytes.
func (d *DexFile) Save() ([]byte, error) {
	// For now, return the raw data
	// Full serialization would require rebuilding all sections
	if d.raw == nil {
		return nil, fmt.Errorf("dex: no raw data to save")
	}
	return d.raw, nil
}

// FixChecksums recalculates and fixes the checksum and SHA-1 signature.
func (d *DexFile) FixChecksums(buff []byte) ([]byte, error) {
	if len(buff) < 12+20 {
		return nil, fmt.Errorf("dex: buffer too short")
	}

	result := make([]byte, len(buff))
	copy(result, buff)

	// Zero out signature (bytes 12-32)
	for i := 12; i < 32; i++ {
		result[i] = 0
	}

	// Calculate SHA-1 of data after signature (bytes 32+)
	h := sha1.New()
	h.Write(result[32:])
	sig := h.Sum(nil)
	copy(result[12:32], sig)

	// Calculate Adler32 of data after checksum (bytes 12+)
	checksum := computeAdler32(result[12:])
	binary.LittleEndian.PutUint32(result[8:12], checksum)

	return result, nil
}

// computeAdler32 computes the Adler-32 checksum.
func computeAdler32(data []byte) uint32 {
	var a, b uint32 = 1, 0
	for _, c := range data {
		a = (a + uint32(c)) % 65521
		b = (b + a) % 65521
	}
	return (b << 16) | a
}

// GetClassesNames returns all class names in the DEX.
func (d *DexFile) GetClassesNames() []string {
	names := make([]string, len(d.ClassDefs))
	for i := range d.ClassDefs {
		names[i] = d.GetClassName(uint32(i))
	}
	return names
}

// GetClass returns the class def index for a given class name, or -1.
func (d *DexFile) GetClass(name string) int {
	for i := range d.ClassDefs {
		if d.GetClassName(uint32(i)) == name {
			return i
		}
	}
	return -1
}

// GetMethodsOfClass returns all method indices for a class.
func (d *DexFile) GetMethodsOfClass(classIdx uint32) []uint32 {
	var methods []uint32
	cd, ok := d.ClassData[classIdx]
	if !ok {
		return methods
	}

	for _, m := range cd.DirectMethods {
		methods = append(methods, m.MethodIdxDiff)
	}
	for _, m := range cd.VirtualMethods {
		methods = append(methods, m.MethodIdxDiff)
	}
	return methods
}

// GetFieldsOfClass returns all field indices for a class.
func (d *DexFile) GetFieldsOfClass(classIdx uint32) []uint32 {
	var fields []uint32
	cd, ok := d.ClassData[classIdx]
	if !ok {
		return fields
	}

	for _, f := range cd.StaticFields {
		fields = append(fields, f.FieldIdxDiff)
	}
	for _, f := range cd.InstanceFields {
		fields = append(fields, f.FieldIdxDiff)
	}
	return fields
}

// GetStrings returns all strings in the DEX.
func (d *DexFile) GetStrings() []string {
	strings := make([]string, len(d.StringData))
	for i, sd := range d.StringData {
		strings[i] = sd.Data
	}
	return strings
}

// GetRegexStrings returns strings matching a regex pattern.
func (d *DexFile) GetRegexStrings(pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var result []string
	for _, sd := range d.StringData {
		if re.MatchString(sd.Data) {
			result = append(result, sd.Data)
		}
	}
	return result
}

// GetMethodDescriptor returns the full method descriptor for a method index.
func (d *DexFile) GetMethodDescriptor(methodIdx uint32) string {
	if int(methodIdx) >= len(d.MethodIDs) {
		return ""
	}
	m := d.MethodIDs[methodIdx]
	return d.GetProtoSignature(uint32(m.ProtoIdx))
}

// GetEncodedMethod returns the encoded method for a class and method index.
func (d *DexFile) GetEncodedMethod(classIdx, methodIdx uint32) *EncodedMethod {
	cd, ok := d.ClassData[classIdx]
	if !ok {
		return nil
	}

	for i, m := range cd.DirectMethods {
		if m.MethodIdxDiff == methodIdx {
			return &cd.DirectMethods[i]
		}
	}
	for i, m := range cd.VirtualMethods {
		if m.MethodIdxDiff == methodIdx {
			return &cd.VirtualMethods[i]
		}
	}
	return nil
}

// GetEncodedField returns the encoded field for a class and field index.
func (d *DexFile) GetEncodedField(classIdx, fieldIdx uint32) *EncodedField {
	cd, ok := d.ClassData[classIdx]
	if !ok {
		return nil
	}

	for i, f := range cd.StaticFields {
		if f.FieldIdxDiff == fieldIdx {
			return &cd.StaticFields[i]
		}
	}
	for i, f := range cd.InstanceFields {
		if f.FieldIdxDiff == fieldIdx {
			return &cd.InstanceFields[i]
		}
	}
	return nil
}

// Disassemble disassembles instructions at a given offset.
func (d *DexFile) Disassemble(offset, size uint32) ([]Instruction, error) {
	disasm := NewDisassembler(d)

	// Create a mock code item
	code := &CodeItem{
		Insns: make([]uint16, size/2),
	}

	off := offset
	for i := uint32(0); i < size/2; i++ {
		if off+2 > uint32(len(d.raw)) {
			break
		}
		code.Insns[i] = binary.LittleEndian.Uint16(d.raw[off : off+2])
		off += 2
	}

	return disasm.DisassembleCode(code)
}

// GetClassHierarchy returns a simple class hierarchy.
func (d *DexFile) GetClassHierarchy() map[string]string {
	hierarchy := make(map[string]string)
	for _, classDef := range d.ClassDefs {
		className := d.GetTypeName(classDef.ClassIdx)
		if classDef.SuperclassIdx != NO_INDEX {
			superClass := d.GetTypeName(classDef.SuperclassIdx)
			hierarchy[className] = superClass
		} else {
			hierarchy[className] = ""
		}
	}
	return hierarchy
}

// GetInterfaces returns the interfaces implemented by a class.
func (d *DexFile) GetInterfaces(classIdx uint32) []string {
	if int(classIdx) >= len(d.ClassDefs) {
		return nil
	}

	classDef := d.ClassDefs[classIdx]
	if classDef.InterfacesOff == 0 {
		return nil
	}

	off := classDef.InterfacesOff
	if off+4 > uint32(len(d.raw)) {
		return nil
	}

	size := binary.LittleEndian.Uint32(d.raw[off : off+4])
	off += 4

	interfaces := make([]string, size)
	for i := uint32(0); i < size; i++ {
		if off+2 > uint32(len(d.raw)) {
			break
		}
		typeIdx := binary.LittleEndian.Uint16(d.raw[off : off+2])
		interfaces[i] = d.GetTypeName(uint32(typeIdx))
		off += 2
	}

	return interfaces
}

// ParseODEXHeader parses an ODEX file header.
func ParseODEXHeader(data []byte) (*ODEXHeader, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("odex: file too short")
	}

	if !bytes.HasPrefix(data, []byte("dey\n")) {
		return nil, fmt.Errorf("odex: invalid magic")
	}

	header := &ODEXHeader{}
	copy(header.Magic[:], data[0:8])
	header.DexOffset = binary.LittleEndian.Uint32(data[8:12])
	header.DexLength = binary.LittleEndian.Uint32(data[12:16])
	header.Dependencies = binary.LittleEndian.Uint32(data[16:20])
	header.DependenciesLength = binary.LittleEndian.Uint32(data[20:24])
	header.Flags = binary.LittleEndian.Uint32(data[24:28])

	return header, nil
}

// ParseODEXDependencies parses the dependency table from an ODEX file.
func ParseODEXDependencies(data []byte, offset, length uint32) ([]ODEXDependency, error) {
	if offset+4 > uint32(len(data)) {
		return nil, fmt.Errorf("odex: dependencies out of bounds")
	}

	count := binary.LittleEndian.Uint32(data[offset : offset+4])
	off := offset + 4

	deps := make([]ODEXDependency, count)
	for i := uint32(0); i < count; i++ {
		if off+12 > uint32(len(data)) {
			break
		}

		// Name is 256 bytes of UTF-16 LE
		nameBytes := data[off : off+256]
		deps[i].Name = decodeUTF16Name(nameBytes)
		off += 256

		deps[i].ModTime = binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		deps[i].CRC = binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
	}

	return deps, nil
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

// GetRaw returns the raw DEX file bytes.
func (d *DexFile) GetRaw() []byte {
	return d.raw
}

// GetOffset returns the current offset for a reader-like interface.
func GetOffset(r io.ReadSeeker) int64 {
	pos, _ := r.Seek(0, io.SeekCurrent)
	return pos
}
