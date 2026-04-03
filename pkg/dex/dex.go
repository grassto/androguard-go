// Package dex implements a DEX file parser compatible with Android's DEX format.
// Reference: https://source.android.com/devices/tech/dalvik/dex-format
package dex

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/goandroguard/goandroguard/internal/leb128"
)

// DEX file magic constants
var (
	DEXMagic35 = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00} // "dex\n035\0"
	DEXMagic36 = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x36, 0x00}
	DEXMagic37 = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00}
	DEXMagic38 = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00}
	DEXMagic39 = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00}
	ODEXMagic  = []byte{0x64, 0x65, 0x79, 0x0a} // "dey\n" prefix
)

// Map item types
const (
	TypeHeaderItem               = 0x0000
	TypeStringIDItem             = 0x0001
	TypeTypeIDItem               = 0x0002
	TypeProtoIDItem              = 0x0003
	TypeFieldIDItem              = 0x0004
	TypeMethodIDItem             = 0x0005
	TypeClassDefItem             = 0x0006
	TypeCallSiteIDItem           = 0x0007
	TypeMethodHandleItem         = 0x0008
	TypeMapList                  = 0x1000
	TypeTypeList                 = 0x1001
	TypeAnnotationSetRefList     = 0x1002
	TypeAnnotationSetItem        = 0x1003
	TypeClassDataItem            = 0x2000
	TypeCodeItem                 = 0x2001
	TypeStringDataItem           = 0x2002
	TypeDebugInfoItem            = 0x2003
	TypeAnnotationItem           = 0x2004
	TypeEncodedArrayItem         = 0x2005
	TypeAnnotationsDirectoryItem = 0x2006
)

// Access flags
const (
	AccPublic       = 0x1
	AccPrivate      = 0x2
	AccProtected    = 0x4
	AccStatic       = 0x8
	AccFinal        = 0x10
	AccSynchronized = 0x20
	AccVolatile     = 0x40
	AccBridge       = 0x40
	AccTransient    = 0x80
	AccVarargs      = 0x80
	AccNative       = 0x100
	AccInterface    = 0x200
	AccAbstract     = 0x400
	AccStrict       = 0x800
	AccSynthetic    = 0x1000
	AccAnnotation   = 0x2000
	AccEnum         = 0x4000
	AccUnused       = 0x8000
	AccConstructor  = 0x10000
	AccDeclaredSynchronized = 0x20000
)

// Header represents the DEX file header (80 bytes fixed + variable sections)
type Header struct {
	Magic         [8]byte
	Checksum      uint32
	Signature     [20]byte
	FileSize      uint32
	HeaderSize    uint32
	EndianTag     uint32
	LinkSize      uint32
	LinkOff       uint32
	MapOff        uint32
	StringIDsSize uint32
	StringIDsOff  uint32
	TypeIDsSize   uint32
	TypeIDsOff    uint32
	ProtoIDsSize  uint32
	ProtoIDsOff   uint32
	FieldIDsSize  uint32
	FieldIDsOff   uint32
	MethodIDsSize uint32
	MethodIDsOff  uint32
	ClassDefsSize uint32
	ClassDefsOff  uint32
	DataSize      uint32
	DataOff       uint32
}

// StringID holds the offset to a string data item
type StringID struct {
	StringDataOff uint32
}

// StringDataItem holds the actual string data
type StringDataItem struct {
	UTF16Size uint32 // MUTF-8 length (in UTF-16 code units)
	Data      string
}

// TypeID holds an index into string_ids for a type descriptor
type TypeID struct {
	DescriptorIdx uint32
}

// ProtoID holds prototype (method signature) information
type ProtoID struct {
	ShortyIdx      uint32 // Index into string_ids
	ReturnTypeIdx  uint32 // Index into type_ids
	ParametersOff  uint32 // File offset to a type_list for parameters
}

// FieldID holds field identifier information
type FieldID struct {
	ClassIdx uint16 // Index into type_ids (defining class)
	TypeIdx  uint16 // Index into type_ids (field type)
	NameIdx  uint32 // Index into string_ids (field name)
}

// MethodID holds method identifier information
type MethodID struct {
	ClassIdx uint16 // Index into type_ids (defining class)
	ProtoIdx uint16 // Index into proto_ids (method prototype)
	NameIdx  uint32 // Index into string_ids (method name)
}

// ClassDef holds class definition information
type ClassDef struct {
	ClassIdx          uint32 // Index into type_ids
	AccessFlags       uint32
	SuperclassIdx     uint32 // Index into type_ids (NO_INDEX if Object)
	InterfacesOff     uint32 // File offset to a type_list
	SourceFileIdx     uint32 // Index into string_ids (NO_INDEX if unknown)
	AnnotationsOff    uint32
	ClassDataOff      uint32
	StaticValuesOff   uint32
}

// ClassData holds the encoded data for a class
type ClassData struct {
	StaticFieldsSize   uint32
	InstanceFieldsSize uint32
	DirectMethodsSize  uint32
	VirtualMethodsSize uint32
	StaticFields       []EncodedField
	InstanceFields     []EncodedField
	DirectMethods      []EncodedMethod
	VirtualMethods     []EncodedMethod
}

// EncodedField represents an encoded field in class data
type EncodedField struct {
	FieldIdxDiff uint32
	AccessFlags  uint32
}

// EncodedMethod represents an encoded method in class data
type EncodedMethod struct {
	MethodIdxDiff uint32
	AccessFlags   uint32
	CodeOff       uint32
}

// CodeItem holds the bytecode of a method
type CodeItem struct {
	RegistersSize uint16
	InsSize       uint16
	OutsSize      uint16
	TriesSize     uint16
	DebugInfoOff  uint32
	InsnsSize     uint32
	Insns         []uint16
	Tries         []TryItem
	CatchHandler  *CatchHandler
}

// TryItem represents a try block
type TryItem struct {
	StartAddr  uint32
	InsnCount  uint16
	HandlerOff uint16
}

// CatchHandler holds catch handler information
type CatchHandler struct {
	Size     int32
	Handlers []EncodedCatchHandler
}

// EncodedCatchHandler represents a single catch handler
type EncodedCatchHandler struct {
	TypeIdx  uint32
	Addr     uint32
	CatchAll bool
}

// MapItem represents an item in the map list
type MapItem struct {
	Type   uint16
	Unused uint16
	Size   uint32
	Offset uint32
}

// TypeList holds a list of type indices
type TypeList struct {
	Size  uint32
	List  []uint16
}

// NO_INDEX is used when a string index is not present
const NO_INDEX = 0xFFFFFFFF

// DexFile represents a parsed DEX file
type DexFile struct {
	Header      Header
	StringIDs   []StringID
	StringData  []StringDataItem
	TypeIDs     []TypeID
	ProtoIDs    []ProtoID
	FieldIDs    []FieldID
	MethodIDs   []MethodID
	ClassDefs   []ClassDef
	ClassData   map[uint32]*ClassData // keyed by class def index
	CodeItems   map[uint32]*CodeItem  // keyed by offset
	MapItems    []MapItem
	raw         []byte
}

// Parse reads and parses a DEX file from the given byte slice.
func Parse(data []byte) (*DexFile, error) {
	d := &DexFile{
		raw:       data,
		ClassData: make(map[uint32]*ClassData),
		CodeItems: make(map[uint32]*CodeItem),
	}

	if len(data) < 116 {
		return nil, fmt.Errorf("dex: file too short (%d bytes)", len(data))
	}

	// Verify magic
	if !bytes.HasPrefix(data, DEXMagic35[:4]) {
		return nil, fmt.Errorf("dex: invalid magic")
	}

	if err := d.parseHeader(); err != nil {
		return nil, fmt.Errorf("dex: header: %w", err)
	}

	if err := d.parseStringIDs(); err != nil {
		return nil, fmt.Errorf("dex: string_ids: %w", err)
	}

	if err := d.parseTypeIDs(); err != nil {
		return nil, fmt.Errorf("dex: type_ids: %w", err)
	}

	if err := d.parseProtoIDs(); err != nil {
		return nil, fmt.Errorf("dex: proto_ids: %w", err)
	}

	if err := d.parseFieldIDs(); err != nil {
		return nil, fmt.Errorf("dex: field_ids: %w", err)
	}

	if err := d.parseMethodIDs(); err != nil {
		return nil, fmt.Errorf("dex: method_ids: %w", err)
	}

	if err := d.parseClassDefs(); err != nil {
		return nil, fmt.Errorf("dex: class_defs: %w", err)
	}

	if d.Header.MapOff > 0 && d.Header.MapOff < uint32(len(data)) {
		d.parseMapList(d.Header.MapOff)
	}

	return d, nil
}

func (d *DexFile) parseHeader() error {
	r := bytes.NewReader(d.raw)

	binary.Read(r, binary.LittleEndian, &d.Header.Magic)
	binary.Read(r, binary.LittleEndian, &d.Header.Checksum)
	binary.Read(r, binary.LittleEndian, &d.Header.Signature)
	binary.Read(r, binary.LittleEndian, &d.Header.FileSize)
	binary.Read(r, binary.LittleEndian, &d.Header.HeaderSize)
	binary.Read(r, binary.LittleEndian, &d.Header.EndianTag)
	binary.Read(r, binary.LittleEndian, &d.Header.LinkSize)
	binary.Read(r, binary.LittleEndian, &d.Header.LinkOff)
	binary.Read(r, binary.LittleEndian, &d.Header.MapOff)
	binary.Read(r, binary.LittleEndian, &d.Header.StringIDsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.StringIDsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.TypeIDsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.TypeIDsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.ProtoIDsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.ProtoIDsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.FieldIDsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.FieldIDsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.MethodIDsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.MethodIDsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.ClassDefsSize)
	binary.Read(r, binary.LittleEndian, &d.Header.ClassDefsOff)
	binary.Read(r, binary.LittleEndian, &d.Header.DataSize)
	binary.Read(r, binary.LittleEndian, &d.Header.DataOff)

	return nil
}

func (d *DexFile) parseStringIDs() error {
	off := d.Header.StringIDsOff
	size := d.Header.StringIDsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.StringIDs = make([]StringID, size)
	d.StringData = make([]StringDataItem, size)

	for i := uint32(0); i < size; i++ {
		if off+4 > uint32(len(d.raw)) {
			return fmt.Errorf("string_id %d out of bounds", i)
		}
		d.StringIDs[i].StringDataOff = leb128.ReadUint32(d.raw[off : off+4])
		off += 4

		// Parse the string data item
		if err := d.parseStringData(i); err != nil {
			return err
		}
	}
	return nil
}

func (d *DexFile) parseStringData(idx uint32) error {
	off := d.StringIDs[idx].StringDataOff
	if off >= uint32(len(d.raw)) {
		return fmt.Errorf("string_data %d: offset %d out of bounds", idx, off)
	}

	// Read MUTF-8 size (ULEB128)
	utf16Size, n := leb128.ReadULEB128(d.raw[off:])
	off += uint32(n)
	d.StringData[idx].UTF16Size = uint32(utf16Size)

	// Find null terminator
	end := off
	for end < uint32(len(d.raw)) && d.raw[end] != 0 {
		end++
	}

	d.StringData[idx].Data = leb128.MUTF8Decode(d.raw[off:end])
	return nil
}

func (d *DexFile) parseTypeIDs() error {
	off := d.Header.TypeIDsOff
	size := d.Header.TypeIDsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.TypeIDs = make([]TypeID, size)
	for i := uint32(0); i < size; i++ {
		if off+4 > uint32(len(d.raw)) {
			return fmt.Errorf("type_id %d out of bounds", i)
		}
		d.TypeIDs[i].DescriptorIdx = leb128.ReadUint32(d.raw[off : off+4])
		off += 4
	}
	return nil
}

func (d *DexFile) parseProtoIDs() error {
	off := d.Header.ProtoIDsOff
	size := d.Header.ProtoIDsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.ProtoIDs = make([]ProtoID, size)
	for i := uint32(0); i < size; i++ {
		if off+12 > uint32(len(d.raw)) {
			return fmt.Errorf("proto_id %d out of bounds", i)
		}
		d.ProtoIDs[i].ShortyIdx = leb128.ReadUint32(d.raw[off : off+4])
		d.ProtoIDs[i].ReturnTypeIdx = leb128.ReadUint32(d.raw[off+4 : off+8])
		d.ProtoIDs[i].ParametersOff = leb128.ReadUint32(d.raw[off+8 : off+12])
		off += 12
	}
	return nil
}

func (d *DexFile) parseFieldIDs() error {
	off := d.Header.FieldIDsOff
	size := d.Header.FieldIDsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.FieldIDs = make([]FieldID, size)
	for i := uint32(0); i < size; i++ {
		if off+8 > uint32(len(d.raw)) {
			return fmt.Errorf("field_id %d out of bounds", i)
		}
		d.FieldIDs[i].ClassIdx = binary.LittleEndian.Uint16(d.raw[off : off+2])
		d.FieldIDs[i].TypeIdx = binary.LittleEndian.Uint16(d.raw[off+2 : off+4])
		d.FieldIDs[i].NameIdx = leb128.ReadUint32(d.raw[off+4 : off+8])
		off += 8
	}
	return nil
}

func (d *DexFile) parseMethodIDs() error {
	off := d.Header.MethodIDsOff
	size := d.Header.MethodIDsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.MethodIDs = make([]MethodID, size)
	for i := uint32(0); i < size; i++ {
		if off+8 > uint32(len(d.raw)) {
			return fmt.Errorf("method_id %d out of bounds", i)
		}
		d.MethodIDs[i].ClassIdx = binary.LittleEndian.Uint16(d.raw[off : off+2])
		d.MethodIDs[i].ProtoIdx = binary.LittleEndian.Uint16(d.raw[off+2 : off+4])
		d.MethodIDs[i].NameIdx = leb128.ReadUint32(d.raw[off+4 : off+8])
		off += 8
	}
	return nil
}

func (d *DexFile) parseClassDefs() error {
	off := d.Header.ClassDefsOff
	size := d.Header.ClassDefsSize
	if off == 0 || size == 0 {
		return nil
	}

	d.ClassDefs = make([]ClassDef, size)
	for i := uint32(0); i < size; i++ {
		if off+32 > uint32(len(d.raw)) {
			return fmt.Errorf("class_def %d out of bounds", i)
		}
		d.ClassDefs[i].ClassIdx = leb128.ReadUint32(d.raw[off : off+4])
		d.ClassDefs[i].AccessFlags = leb128.ReadUint32(d.raw[off+4 : off+8])
		d.ClassDefs[i].SuperclassIdx = leb128.ReadUint32(d.raw[off+8 : off+12])
		d.ClassDefs[i].InterfacesOff = leb128.ReadUint32(d.raw[off+12 : off+16])
		d.ClassDefs[i].SourceFileIdx = leb128.ReadUint32(d.raw[off+16 : off+20])
		d.ClassDefs[i].AnnotationsOff = leb128.ReadUint32(d.raw[off+20 : off+24])
		d.ClassDefs[i].ClassDataOff = leb128.ReadUint32(d.raw[off+24 : off+28])
		d.ClassDefs[i].StaticValuesOff = leb128.ReadUint32(d.raw[off+28 : off+32])
		off += 32

		// Parse class data if present
		if d.ClassDefs[i].ClassDataOff > 0 && d.ClassDefs[i].ClassDataOff < uint32(len(d.raw)) {
			cd, err := d.parseClassData(d.ClassDefs[i].ClassDataOff)
			if err == nil {
				d.ClassData[i] = cd
			}
		}
	}
	return nil
}

func (d *DexFile) parseClassData(offset uint32) (*ClassData, error) {
	cd := &ClassData{}
	off := offset
	data := d.raw

	if off >= uint32(len(data)) {
		return nil, fmt.Errorf("class_data out of bounds")
	}

	var n int
	staticSize, n := leb128.ReadULEB128(data[off:])
	cd.StaticFieldsSize = uint32(staticSize)
	off += uint32(n)
	instanceSize, n := leb128.ReadULEB128(data[off:])
	cd.InstanceFieldsSize = uint32(instanceSize)
	off += uint32(n)
	directSize, n := leb128.ReadULEB128(data[off:])
	cd.DirectMethodsSize = uint32(directSize)
	off += uint32(n)
	virtualSize, n := leb128.ReadULEB128(data[off:])
	cd.VirtualMethodsSize = uint32(virtualSize)
	off += uint32(n)

	// Parse static fields
	cd.StaticFields = make([]EncodedField, cd.StaticFieldsSize)
	fieldIdx := uint32(0)
	for i := uint32(0); i < cd.StaticFieldsSize; i++ {
		idxDiff, n1 := leb128.ReadULEB128(data[off:])
		off += uint32(n1)
		flags, n2 := leb128.ReadULEB128(data[off:])
		off += uint32(n2)
		fieldIdx += uint32(idxDiff)
		cd.StaticFields[i] = EncodedField{FieldIdxDiff: fieldIdx, AccessFlags: uint32(flags)}
	}

	// Parse instance fields
	cd.InstanceFields = make([]EncodedField, cd.InstanceFieldsSize)
	fieldIdx = 0
	for i := uint32(0); i < cd.InstanceFieldsSize; i++ {
		idxDiff, n1 := leb128.ReadULEB128(data[off:])
		off += uint32(n1)
		flags, n2 := leb128.ReadULEB128(data[off:])
		off += uint32(n2)
		fieldIdx += uint32(idxDiff)
		cd.InstanceFields[i] = EncodedField{FieldIdxDiff: fieldIdx, AccessFlags: uint32(flags)}
	}

	// Parse direct methods
	cd.DirectMethods = make([]EncodedMethod, cd.DirectMethodsSize)
	methodIdx := uint32(0)
	for i := uint32(0); i < cd.DirectMethodsSize; i++ {
		idxDiff, n1 := leb128.ReadULEB128(data[off:])
		off += uint32(n1)
		flags, n2 := leb128.ReadULEB128(data[off:])
		off += uint32(n2)
		codeOff, n3 := leb128.ReadULEB128(data[off:])
		off += uint32(n3)
		methodIdx += uint32(idxDiff)
		cd.DirectMethods[i] = EncodedMethod{MethodIdxDiff: methodIdx, AccessFlags: uint32(flags), CodeOff: uint32(codeOff)}
	}

	// Parse virtual methods
	cd.VirtualMethods = make([]EncodedMethod, cd.VirtualMethodsSize)
	methodIdx = 0
	for i := uint32(0); i < cd.VirtualMethodsSize; i++ {
		idxDiff, n1 := leb128.ReadULEB128(data[off:])
		off += uint32(n1)
		flags, n2 := leb128.ReadULEB128(data[off:])
		off += uint32(n2)
		codeOff, n3 := leb128.ReadULEB128(data[off:])
		off += uint32(n3)
		methodIdx += uint32(idxDiff)
		cd.VirtualMethods[i] = EncodedMethod{MethodIdxDiff: methodIdx, AccessFlags: uint32(flags), CodeOff: uint32(codeOff)}
	}

	return cd, nil
}

func (d *DexFile) parseMapList(offset uint32) {
	off := offset
	if off+4 > uint32(len(d.raw)) {
		return
	}
	size := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	d.MapItems = make([]MapItem, size)
	for i := uint32(0); i < size; i++ {
		if off+12 > uint32(len(d.raw)) {
			return
		}
		d.MapItems[i].Type = binary.LittleEndian.Uint16(d.raw[off : off+2])
		d.MapItems[i].Unused = binary.LittleEndian.Uint16(d.raw[off+2 : off+4])
		d.MapItems[i].Size = leb128.ReadUint32(d.raw[off+4 : off+8])
		d.MapItems[i].Offset = leb128.ReadUint32(d.raw[off+8 : off+12])
		off += 12
	}
}

// GetString returns the string at the given index in the string_ids table.
func (d *DexFile) GetString(idx uint32) string {
	if idx >= uint32(len(d.StringData)) {
		return ""
	}
	return d.StringData[idx].Data
}

// GetTypeName returns the type descriptor string for the given type index.
func (d *DexFile) GetTypeName(idx uint32) string {
	if idx >= uint32(len(d.TypeIDs)) {
		return ""
	}
	return d.GetString(d.TypeIDs[idx].DescriptorIdx)
}

// GetClassName returns the class name for the given class def index.
func (d *DexFile) GetClassName(idx uint32) string {
	if idx >= uint32(len(d.ClassDefs)) {
		return ""
	}
	return d.GetTypeName(d.ClassDefs[idx].ClassIdx)
}

// GetMethodName returns the full method name (class->name) for the given method index.
func (d *DexFile) GetMethodName(idx uint32) string {
	if idx >= uint32(len(d.MethodIDs)) {
		return ""
	}
	m := d.MethodIDs[idx]
	className := d.GetTypeName(uint32(m.ClassIdx))
	methodName := d.GetString(m.NameIdx)
	return fmt.Sprintf("%s->%s", className, methodName)
}

// GetFieldName returns the full field name (class->name) for the given field index.
func (d *DexFile) GetFieldName(idx uint32) string {
	if idx >= uint32(len(d.FieldIDs)) {
		return ""
	}
	f := d.FieldIDs[idx]
	className := d.GetTypeName(uint32(f.ClassIdx))
	fieldName := d.GetString(f.NameIdx)
	return fmt.Sprintf("%s->%s", className, fieldName)
}

// GetProtoSignature returns the method prototype string for the given proto index.
func (d *DexFile) GetProtoSignature(idx uint32) string {
	if idx >= uint32(len(d.ProtoIDs)) {
		return ""
	}
	p := d.ProtoIDs[idx]
	returnType := d.GetTypeName(p.ReturnTypeIdx)

	// Read parameter types from type_list
	params := ""
	if p.ParametersOff > 0 && p.ParametersOff < uint32(len(d.raw)) {
		off := p.ParametersOff
		size := leb128.ReadUint32(d.raw[off : off+4])
		off += 4
		paramTypes := make([]string, size)
		for i := uint32(0); i < size; i++ {
			typeIdx := binary.LittleEndian.Uint16(d.raw[off : off+2])
			paramTypes[i] = d.GetTypeName(uint32(typeIdx))
			off += 2
		}
		params = fmt.Sprintf("%v", paramTypes)
	}

	return fmt.Sprintf("(%s)%s", params, returnType)
}

// ComputeSHA1 returns the SHA-1 signature of the DEX file (excluding the signature field itself).
func (d *DexFile) ComputeSHA1() [20]byte {
	h := sha1.New()
	h.Write(d.raw[32:]) // skip magic + checksum + signature
	var sig [20]byte
	copy(sig[:], h.Sum(nil))
	return sig
}

// ComputeAdler32 computes the Adler-32 checksum of the DEX file (excluding magic and checksum).
func (d *DexFile) ComputeAdler32() uint32 {
	return adler32(d.raw[12:])
}

func adler32(data []byte) uint32 {
	var a, b uint32 = 1, 0
	for _, c := range data {
		a = (a + uint32(c)) % 65521
		b = (b + a) % 65521
	}
	return (b << 16) | a
}

// GetAccessFlagsString returns a human-readable string for access flags.
func GetAccessFlagsString(flags uint32) string {
	var result []byte
	accMap := []struct {
		flag uint32
		name string
	}{
		{AccPublic, "public"}, {AccPrivate, "private"}, {AccProtected, "protected"},
		{AccStatic, "static"}, {AccFinal, "final"}, {AccSynchronized, "synchronized"},
		{AccVolatile, "volatile"}, {AccBridge, "bridge"}, {AccTransient, "transient"},
		{AccVarargs, "varargs"}, {AccNative, "native"}, {AccInterface, "interface"},
		{AccAbstract, "abstract"}, {AccStrict, "strict"}, {AccSynthetic, "synthetic"},
		{AccAnnotation, "annotation"}, {AccEnum, "enum"},
		{AccConstructor, "constructor"}, {AccDeclaredSynchronized, "declared-synchronized"},
	}

	for _, a := range accMap {
		if flags&a.flag == a.flag {
			if len(result) > 0 {
				result = append(result, ' ')
			}
			result = append(result, a.name...)
		}
	}
	return string(result)
}

// GetVersion returns the DEX version string from the magic bytes.
func (d *DexFile) GetVersion() string {
	return string(d.Header.Magic[4:7])
}

// IsODEX returns true if this is an optimized DEX (ODEX) file.
func (d *DexFile) IsODEX() bool {
	return d.Header.Magic[0] == 'd' && d.Header.Magic[1] == 'e' && d.Header.Magic[2] == 'y'
}

// ParseFromReader parses a DEX file from an io.Reader.
func ParseFromReader(r io.Reader) (*DexFile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}
