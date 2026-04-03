package dex

import (
	"fmt"
	"sync"
)

// ClassManager provides centralized access to all DEX elements by index or offset.
// It wraps DexFile and adds caching, string hooking, and offset-based lookups.
type ClassManager struct {
	dex    *DexFile
	mu     sync.RWMutex

	// Caches
	stringCache   map[uint32]string
	typeCache     map[uint32]string
	protoCache    map[uint32]ProtoInfo
	methodCache   map[uint32]MethodRef
	fieldCache    map[uint32]FieldRef

	// String hooking
	hookStrings   map[uint32]string

	// Offset lookups
	offsetCache   map[uint32]interface{}

	// ODEX format flag
	isODEX        bool
}

// ProtoInfo holds resolved proto information.
type ProtoInfo struct {
	Shorty          string
	ReturnType      string
	Parameters      []string
	ParametersOff   uint32
	ReturnTypeIdx   uint32
}

// MethodRef holds resolved method reference information.
type MethodRef struct {
	ClassName   string
	Name        string
	Descriptor  string
	ClassIdx    uint16
	ProtoIdx    uint16
	NameIdx     uint32
}

// FieldRef holds resolved field reference information.
type FieldRef struct {
	ClassName  string
	Type       string
	Name       string
	ClassIdx   uint16
	TypeIdx    uint16
	NameIdx    uint32
}

// NewClassManager creates a new ClassManager for the given DEX file.
func NewClassManager(dex *DexFile) *ClassManager {
	cm := &ClassManager{
		dex:          dex,
		stringCache:  make(map[uint32]string),
		typeCache:    make(map[uint32]string),
		protoCache:   make(map[uint32]ProtoInfo),
		methodCache:  make(map[uint32]MethodRef),
		fieldCache:   make(map[uint32]FieldRef),
		hookStrings:  make(map[uint32]string),
		offsetCache:  make(map[uint32]interface{}),
		isODEX:       dex.IsODEX(),
	}
	return cm
}

// GetDexFile returns the underlying DexFile.
func (cm *ClassManager) GetDexFile() *DexFile {
	return cm.dex
}

// IsODEX returns true if the DEX is in ODEX format.
func (cm *ClassManager) IsODEX() bool {
	return cm.isODEX
}

// GetString returns a string from the string table at index idx.
// If the string is hooked, the hooked value is returned.
func (cm *ClassManager) GetString(idx uint32) string {
	cm.mu.RLock()
	if hooked, ok := cm.hookStrings[idx]; ok {
		cm.mu.RUnlock()
		return hooked
	}
	if cached, ok := cm.stringCache[idx]; ok {
		cm.mu.RUnlock()
		return cached
	}
	cm.mu.RUnlock()

	s := cm.dex.GetString(idx)

	cm.mu.Lock()
	cm.stringCache[idx] = s
	cm.mu.Unlock()

	return s
}

// GetRawString returns the raw (unhooked) string at index idx.
func (cm *ClassManager) GetRawString(idx uint32) string {
	return cm.dex.GetString(idx)
}

// SetHookString sets a hook to replace a string at the given index.
func (cm *ClassManager) SetHookString(idx uint32, value string) {
	cm.mu.Lock()
	cm.hookStrings[idx] = value
	cm.mu.Unlock()
}

// RemoveHookString removes a string hook.
func (cm *ClassManager) RemoveHookString(idx uint32) {
	cm.mu.Lock()
	delete(cm.hookStrings, idx)
	cm.mu.Unlock()
}

// GetHookStrings returns all hooked strings.
func (cm *ClassManager) GetHookStrings() map[uint32]string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make(map[uint32]string)
	for k, v := range cm.hookStrings {
		result[k] = v
	}
	return result
}

// GetType returns the type name at the given type index.
func (cm *ClassManager) GetType(idx uint32) string {
	cm.mu.RLock()
	if cached, ok := cm.typeCache[idx]; ok {
		cm.mu.RUnlock()
		return cached
	}
	cm.mu.RUnlock()

	s := cm.dex.GetTypeName(idx)

	cm.mu.Lock()
	cm.typeCache[idx] = s
	cm.mu.Unlock()

	return s
}

// GetTypeRef returns the string index for a given type index.
func (cm *ClassManager) GetTypeRef(idx uint32) uint32 {
	if int(idx) >= len(cm.dex.TypeIDs) {
		return 0xFFFFFFFF
	}
	return cm.dex.TypeIDs[idx].DescriptorIdx
}

// GetProto returns prototype information at the given index.
func (cm *ClassManager) GetProto(idx uint32) ProtoInfo {
	cm.mu.RLock()
	if cached, ok := cm.protoCache[idx]; ok {
		cm.mu.RUnlock()
		return cached
	}
	cm.mu.RUnlock()

	if int(idx) >= len(cm.dex.ProtoIDs) {
		return ProtoInfo{}
	}

	p := cm.dex.ProtoIDs[idx]
	info := ProtoInfo{
		Shorty:        cm.GetString(p.ShortyIdx),
		ReturnType:    cm.GetType(p.ReturnTypeIdx),
		ReturnTypeIdx: p.ReturnTypeIdx,
		ParametersOff: p.ParametersOff,
	}

	// Parse parameters
	if p.ParametersOff > 0 && p.ParametersOff < uint32(len(cm.dex.raw)) {
		off := p.ParametersOff
		size := readUint32(cm.dex.raw, off)
		off += 4
		for i := uint32(0); i < size; i++ {
			if off+2 > uint32(len(cm.dex.raw)) {
				break
			}
			typeIdx := uint32(readUint16(cm.dex.raw, off))
			info.Parameters = append(info.Parameters, cm.GetType(typeIdx))
			off += 2
		}
	}

	cm.mu.Lock()
	cm.protoCache[idx] = info
	cm.mu.Unlock()

	return info
}

// GetMethod returns method reference information at the given index.
func (cm *ClassManager) GetMethod(idx uint32) MethodRef {
	cm.mu.RLock()
	if cached, ok := cm.methodCache[idx]; ok {
		cm.mu.RUnlock()
		return cached
	}
	cm.mu.RUnlock()

	if int(idx) >= len(cm.dex.MethodIDs) {
		return MethodRef{}
	}

	m := cm.dex.MethodIDs[idx]
	ref := MethodRef{
		ClassName: cm.GetType(uint32(m.ClassIdx)),
		Name:      cm.GetString(m.NameIdx),
		ClassIdx:  m.ClassIdx,
		ProtoIdx:  m.ProtoIdx,
		NameIdx:   m.NameIdx,
	}

	// Build descriptor from proto
	proto := cm.GetProto(uint32(m.ProtoIdx))
	ref.Descriptor = buildMethodDescriptor(proto)

	cm.mu.Lock()
	cm.methodCache[idx] = ref
	cm.mu.Unlock()

	return ref
}

// GetField returns field reference information at the given index.
func (cm *ClassManager) GetField(idx uint32) FieldRef {
	cm.mu.RLock()
	if cached, ok := cm.fieldCache[idx]; ok {
		cm.mu.RUnlock()
		return cached
	}
	cm.mu.RUnlock()

	if int(idx) >= len(cm.dex.FieldIDs) {
		return FieldRef{}
	}

	f := cm.dex.FieldIDs[idx]
	ref := FieldRef{
		ClassName: cm.GetType(uint32(f.ClassIdx)),
		Type:      cm.GetType(uint32(f.TypeIdx)),
		Name:      cm.GetString(f.NameIdx),
		ClassIdx:  f.ClassIdx,
		TypeIdx:   f.TypeIdx,
		NameIdx:   f.NameIdx,
	}

	cm.mu.Lock()
	cm.fieldCache[idx] = ref
	cm.mu.Unlock()

	return ref
}

// GetClassDef returns the class def at the given index.
func (cm *ClassManager) GetClassDef(idx uint32) *ClassDef {
	if int(idx) >= len(cm.dex.ClassDefs) {
		return nil
	}
	return &cm.dex.ClassDefs[idx]
}

// GetClassName returns the class name at the given class def index.
func (cm *ClassManager) GetClassName(idx uint32) string {
	return cm.dex.GetClassName(idx)
}

// GetAllClassNames returns all class names in the DEX.
func (cm *ClassManager) GetAllClassNames() []string {
	return cm.dex.GetClassesNames()
}

// GetClassByName returns the class def index for a given class name, or -1.
func (cm *ClassManager) GetClassByName(name string) int32 {
	return int32(cm.dex.GetClass(name))
}

// GetCode returns the DalvikCode at the given offset.
func (cm *ClassManager) GetCode(offset uint32) *DalvikCode {
	code, _ := cm.dex.ParseDalvikCode(offset)
	return code
}

// GetClassData returns the class data at the given offset.
func (cm *ClassManager) GetClassData(offset uint32) *ClassData {
	return cm.dex.ClassData[offset>>8] // Simplified - real impl would use offset map
}

// GetEncodedMethod returns the encoded method for a class and method index.
func (cm *ClassManager) GetEncodedMethod(classIdx, methodIdx uint32) *EncodedMethod {
	return cm.dex.GetEncodedMethod(classIdx, methodIdx)
}

// GetEncodedField returns the encoded field for a class and field index.
func (cm *ClassManager) GetEncodedField(classIdx, fieldIdx uint32) *EncodedField {
	return cm.dex.GetEncodedField(classIdx, fieldIdx)
}

// GetMethodsOfClass returns all method indices for a class.
func (cm *ClassManager) GetMethodsOfClass(classIdx uint32) []uint32 {
	return cm.dex.GetMethodsOfClass(classIdx)
}

// GetFieldsOfClass returns all field indices for a class.
func (cm *ClassManager) GetFieldsOfClass(classIdx uint32) []uint32 {
	return cm.dex.GetFieldsOfClass(classIdx)
}

// GetInterfaces returns the interfaces implemented by a class.
func (cm *ClassManager) GetInterfaces(classIdx uint32) []string {
	return cm.dex.GetInterfaces(classIdx)
}

// GetClassHierarchy returns the class hierarchy map.
func (cm *ClassManager) GetClassHierarchy() map[string]string {
	return cm.dex.GetClassHierarchy()
}

// GetDebugInfo returns debug info at the given offset.
func (cm *ClassManager) GetDebugInfo(offset uint32) *DebugInfo {
	if offset == 0 || offset >= uint32(len(cm.dex.raw)) {
		return nil
	}
	info, _ := cm.dex.ParseDebugInfo(offset)
	return info
}

// GetAnnotationSet returns an annotation set at the given offset.
func (cm *ClassManager) GetAnnotationSet(offset uint32) *AnnotationSet {
	if offset == 0 || offset >= uint32(len(cm.dex.raw)) {
		return nil
	}
	set, _ := cm.dex.ParseAnnotationSet(offset)
	return set
}

// GetAnnotationsDirectory returns annotations directory at the given offset.
func (cm *ClassManager) GetAnnotationsDirectory(offset uint32) *AnnotationsDirectory {
	if offset == 0 || offset >= uint32(len(cm.dex.raw)) {
		return nil
	}
	dir, _ := cm.dex.ParseAnnotationsDirectory(offset)
	return dir
}

// GetKind resolves a kind reference to a human-readable string.
func (cm *ClassManager) GetKind(kind Kind, value uint32) string {
	switch kind {
	case KindMETH:
		m := cm.GetMethod(value)
		return fmt.Sprintf("%s->%s%s", m.ClassName, m.Name, m.Descriptor)
	case KindSTRING, KindRAW_STRING:
		return cm.GetString(value)
	case KindFIELD:
		f := cm.GetField(value)
		return fmt.Sprintf("%s->%s %s", f.ClassName, f.Name, f.Type)
	case KindTYPE:
		return cm.GetType(value)
	case KindPROTO:
		p := cm.GetProto(value)
		return fmt.Sprintf("(%s)%s", formatParamTypes(p.Parameters), p.ReturnType)
	case KindVTABLE_OFFSET:
		return fmt.Sprintf("vtable[0x%x]", value)
	case KindFIELD_OFFSET:
		return fmt.Sprintf("field[0x%x]", value)
	case KindINLINE_METHOD:
		return fmt.Sprintf("inline[0x%x]", value)
	case KindCALL_SITE:
		return fmt.Sprintf("call_site[%d]", value)
	default:
		return fmt.Sprintf("unknown_kind[%d]", value)
	}
}

// GetStrings returns all strings in the DEX.
func (cm *ClassManager) GetStrings() []string {
	return cm.dex.GetStrings()
}

// GetRegexStrings returns strings matching a regex pattern.
func (cm *ClassManager) GetRegexStrings(pattern string) []string {
	return cm.dex.GetRegexStrings(pattern)
}

// GetTypes returns all type names.
func (cm *ClassManager) GetTypes() []string {
	types := make([]string, len(cm.dex.TypeIDs))
	for i := range cm.dex.TypeIDs {
		types[i] = cm.GetType(uint32(i))
	}
	return types
}

// GetMethods returns all method references.
func (cm *ClassManager) GetMethods() []MethodRef {
	refs := make([]MethodRef, len(cm.dex.MethodIDs))
	for i := range cm.dex.MethodIDs {
		refs[i] = cm.GetMethod(uint32(i))
	}
	return refs
}

// GetFields returns all field references.
func (cm *ClassManager) GetFields() []FieldRef {
	refs := make([]FieldRef, len(cm.dex.FieldIDs))
	for i := range cm.dex.FieldIDs {
		refs[i] = cm.GetField(uint32(i))
	}
	return refs
}

// InvalidateCache clears all caches.
func (cm *ClassManager) InvalidateCache() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.stringCache = make(map[uint32]string)
	cm.typeCache = make(map[uint32]string)
	cm.protoCache = make(map[uint32]ProtoInfo)
	cm.methodCache = make(map[uint32]MethodRef)
	cm.fieldCache = make(map[uint32]FieldRef)
}

// Helper functions

func buildMethodDescriptor(proto ProtoInfo) string {
	s := "("
	for i, p := range proto.Parameters {
		if i > 0 {
			s += ", "
		}
		s += p
	}
	s += ")"
	s += proto.ReturnType
	return s
}

func formatParamTypes(params []string) string {
	s := ""
	for i, p := range params {
		if i > 0 {
			s += ", "
		}
		s += p
	}
	return s
}

func readUint32(data []byte, offset uint32) uint32 {
	if int(offset)+4 > len(data) {
		return 0
	}
	return uint32(data[offset]) | uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
}

func readUint16(data []byte, offset uint32) uint16 {
	if int(offset)+2 > len(data) {
		return 0
	}
	return uint16(data[offset]) | uint16(data[offset+1])<<8
}
