package dex

import (
	"fmt"
	"regexp"
)

// --- Missing methods from Python androguard DEX class ---

// GetFormatType returns the format type of the DEX file ("DEX" or "ODEX").
func (d *DexFile) GetFormatType() string {
	if d.IsODEX() {
		return "ODEX"
	}
	return "DEX"
}

// GetAPIMaxVersion returns the max API version supported by this DEX.
func (d *DexFile) GetAPIMaxVersion() int {
	version := d.GetVersion()
	switch version {
	case "035":
		return 25 // Android 7.1
	case "036":
		return 26 // Android 8.0
	case "037":
		return 27 // Android 8.1
	case "038":
		return 28 // Android 9.0
	case "039":
		return 29 // Android 10
	case "040":
		return 30 // Android 11
	case "041":
		return 31 // Android 12
	case "042":
		return 32 // Android 12L
	case "043":
		return 33 // Android 13
	default:
		return 35
	}
}

// GetAPIMinVersion returns the min API version for this DEX format.
func (d *DexFile) GetAPIMinVersion() int {
	version := d.GetVersion()
	switch version {
	case "035":
		return 1
	case "036":
		return 24
	case "037":
		return 26
	case "038":
		return 26
	case "039":
		return 28
	case "040":
		return 29
	case "041":
		return 30
	case "042":
		return 31
	case "043":
		return 33
	default:
		return 1
	}
}

// GetLenClasses returns the number of classes defined.
func (d *DexFile) GetLenClasses() int {
	return len(d.ClassDefs)
}

// GetLenMethods returns the number of method IDs.
func (d *DexFile) GetLenMethods() int {
	return len(d.MethodIDs)
}

// GetLenFields returns the number of field IDs.
func (d *DexFile) GetLenFields() int {
	return len(d.FieldIDs)
}

// GetLenStrings returns the number of strings.
func (d *DexFile) GetLenStrings() int {
	return len(d.StringData)
}

// GetLenTypes returns the number of type IDs.
func (d *DexFile) GetLenTypes() int {
	return len(d.TypeIDs)
}

// GetLenProtos returns the number of proto IDs.
func (d *DexFile) GetLenProtos() int {
	return len(d.ProtoIDs)
}

// GetMethodByName returns methods matching the given name pattern.
func (d *DexFile) GetMethodByName(name string) []uint32 {
	var result []uint32
	re, err := regexp.Compile(name)
	if err != nil {
		return result
	}

	for i, m := range d.MethodIDs {
		methodName := d.GetString(m.NameIdx)
		if re.MatchString(methodName) {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetFieldByName returns fields matching the given name pattern.
func (d *DexFile) GetFieldByName(name string) []uint32 {
	var result []uint32
	re, err := regexp.Compile(name)
	if err != nil {
		return result
	}

	for i, f := range d.FieldIDs {
		fieldName := d.GetString(f.NameIdx)
		if re.MatchString(fieldName) {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetClassByNameIndex returns the class def index by class name, or -1.
func (d *DexFile) GetClassByNameIndex(name string) int32 {
	for i, cd := range d.ClassDefs {
		className := d.GetTypeName(cd.ClassIdx)
		if className == name {
			return int32(i)
		}
	}
	return -1
}

// GetMethodByDescriptor returns methods matching class->name(descriptor).
func (d *DexFile) GetMethodByDescriptor(classMethod string) []uint32 {
	var result []uint32

	for i, m := range d.MethodIDs {
		fullName := fmt.Sprintf("%s->%s",
			d.GetTypeName(uint32(m.ClassIdx)),
			d.GetString(m.NameIdx))
		if fullName == classMethod {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetFieldByDescriptor returns fields matching class->name type.
func (d *DexFile) GetFieldByDescriptor(classField string) []uint32 {
	var result []uint32

	for i, f := range d.FieldIDs {
		fullName := fmt.Sprintf("%s->%s %s",
			d.GetTypeName(uint32(f.ClassIdx)),
			d.GetString(f.NameIdx),
			d.GetTypeName(uint32(f.TypeIdx)))
		if fullName == classField {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetClassMethods returns all method IDs for a given class name.
func (d *DexFile) GetClassMethods(className string) []uint32 {
	var result []uint32

	for i, m := range d.MethodIDs {
		if d.GetTypeName(uint32(m.ClassIdx)) == className {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetClassFields returns all field IDs for a given class name.
func (d *DexFile) GetClassFields(className string) []uint32 {
	var result []uint32

	for i, f := range d.FieldIDs {
		if d.GetTypeName(uint32(f.ClassIdx)) == className {
			result = append(result, uint32(i))
		}
	}
	return result
}

// GetMethodImplementation returns the code for a method index.
func (d *DexFile) GetMethodImplementation(methodIdx uint32) *DalvikCode {
	if int(methodIdx) >= len(d.MethodIDs) {
		return nil
	}

	// Find which class owns this method
	m := d.MethodIDs[methodIdx]
	className := d.GetTypeName(uint32(m.ClassIdx))

	for i, cd := range d.ClassDefs {
		if d.GetTypeName(cd.ClassIdx) != className {
			continue
		}

		classData, ok := d.ClassData[uint32(i)]
		if !ok {
			continue
		}

		for _, method := range classData.DirectMethods {
			if method.MethodIdxDiff == methodIdx && method.CodeOff > 0 {
				code, _ := d.ParseDalvikCode(method.CodeOff)
				return code
			}
		}
		for _, method := range classData.VirtualMethods {
			if method.MethodIdxDiff == methodIdx && method.CodeOff > 0 {
				code, _ := d.ParseDalvikCode(method.CodeOff)
				return code
			}
		}
	}
	return nil
}

// IsExternal returns true if the class at the given index is not defined in this DEX.
func (d *DexFile) IsExternal(classIdx uint32) bool {
	if int(classIdx) >= len(d.ClassDefs) {
		return true
	}
	return d.ClassDefs[classIdx].ClassDataOff == 0
}

// IsExternalByName returns true if the class name is not defined in this DEX.
func (d *DexFile) IsExternalByName(className string) bool {
	idx := d.GetClassByNameIndex(className)
	if idx < 0 {
		return true
	}
	return d.IsExternal(uint32(idx))
}

// GetExternalClasses returns class names that are referenced but not defined.
func (d *DexFile) GetExternalClasses() []string {
	// Build set of defined classes
	defined := make(map[string]bool)
	for _, cd := range d.ClassDefs {
		defined[d.GetTypeName(cd.ClassIdx)] = true
	}

	// Find all referenced classes
	referenced := make(map[string]bool)
	for _, t := range d.TypeIDs {
		name := d.GetString(t.DescriptorIdx)
		if !defined[name] {
			referenced[name] = true
		}
	}

	result := make([]string, 0, len(referenced))
	for name := range referenced {
		result = append(result, name)
	}
	return result
}

// GetInternalClasses returns class names that are defined in this DEX.
func (d *DexFile) GetInternalClasses() []string {
	names := make([]string, 0, len(d.ClassDefs))
	for _, cd := range d.ClassDefs {
		names = append(names, d.GetTypeName(cd.ClassIdx))
	}
	return names
}

// GetReferencedStrings returns strings referenced by code.
func (d *DexFile) GetReferencedStrings() []string {
	referenced := make(map[uint32]bool)

	for _, cd := range d.ClassData {
		for _, m := range cd.DirectMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markStringRefs(code, referenced)
				}
			}
		}
		for _, m := range cd.VirtualMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markStringRefs(code, referenced)
				}
			}
		}
	}

	result := make([]string, 0, len(referenced))
	for idx := range referenced {
		result = append(result, d.GetString(idx))
	}
	return result
}

func (d *DexFile) markStringRefs(code *CodeItem, referenced map[uint32]bool) {
	disasm := NewDisassembler(d)
	insns, _ := disasm.DisassembleCode(code)
	for _, insn := range insns {
		for _, op := range insn.Operands {
			if op.Type == OpString {
				referenced[op.Ref] = true
			}
		}
	}
}

// GetReferencedTypes returns types referenced by code.
func (d *DexFile) GetReferencedTypes() []string {
	referenced := make(map[uint32]bool)

	for _, cd := range d.ClassData {
		for _, m := range cd.DirectMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markTypeRefs(code, referenced)
				}
			}
		}
		for _, m := range cd.VirtualMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markTypeRefs(code, referenced)
				}
			}
		}
	}

	result := make([]string, 0, len(referenced))
	for idx := range referenced {
		result = append(result, d.GetTypeName(idx))
	}
	return result
}

func (d *DexFile) markTypeRefs(code *CodeItem, referenced map[uint32]bool) {
	disasm := NewDisassembler(d)
	insns, _ := disasm.DisassembleCode(code)
	for _, insn := range insns {
		for _, op := range insn.Operands {
			if op.Type == OpType {
				referenced[op.Ref] = true
			}
		}
	}
}

// GetReferencedMethods returns methods referenced by code.
func (d *DexFile) GetReferencedMethods() []string {
	referenced := make(map[uint32]bool)

	for _, cd := range d.ClassData {
		for _, m := range cd.DirectMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markMethodRefs(code, referenced)
				}
			}
		}
		for _, m := range cd.VirtualMethods {
			if m.CodeOff > 0 {
				code, ok := d.CodeItems[m.CodeOff]
				if ok {
					d.markMethodRefs(code, referenced)
				}
			}
		}
	}

	result := make([]string, 0, len(referenced))
	for idx := range referenced {
		result = append(result, d.GetMethodName(idx))
	}
	return result
}

func (d *DexFile) markMethodRefs(code *CodeItem, referenced map[uint32]bool) {
	disasm := NewDisassembler(d)
	insns, _ := disasm.DisassembleCode(code)
	for _, insn := range insns {
		for _, op := range insn.Operands {
			if op.Type == OpMethod {
				referenced[op.Ref] = true
			}
		}
	}
}

// ListClassesHierarchy returns the full class hierarchy as a map.
func (d *DexFile) ListClassesHierarchy() map[string][]string {
	children := make(map[string][]string)

	for _, cd := range d.ClassDefs {
		className := d.GetTypeName(cd.ClassIdx)
		superClass := ""
		if cd.SuperclassIdx != NO_INDEX {
			superClass = d.GetTypeName(cd.SuperclassIdx)
		}
		if superClass != "" {
			children[superClass] = append(children[superClass], className)
		}
	}

	return children
}

// GetClassInterfaces returns interfaces for all classes.
func (d *DexFile) GetAllInterfaces() map[string][]string {
	result := make(map[string][]string)

	for i, cd := range d.ClassDefs {
		ifaces := d.GetInterfaces(uint32(i))
		if len(ifaces) > 0 {
			className := d.GetTypeName(cd.ClassIdx)
			result[className] = ifaces
		}
	}

	return result
}
