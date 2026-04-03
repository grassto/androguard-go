package dex

import (
	"fmt"
	"strings"
)

// Show prints DEX file information.
func (d *DexFile) Show() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("DEX version: %s\n", d.GetVersion()))
	sb.WriteString(fmt.Sprintf("Format: %s\n", d.GetFormatType()))
	sb.WriteString(fmt.Sprintf("File size: %d bytes\n", d.Header.FileSize))
	sb.WriteString(fmt.Sprintf("String IDs: %d\n", d.Header.StringIDsSize))
	sb.WriteString(fmt.Sprintf("Type IDs: %d\n", d.Header.TypeIDsSize))
	sb.WriteString(fmt.Sprintf("Proto IDs: %d\n", d.Header.ProtoIDsSize))
	sb.WriteString(fmt.Sprintf("Field IDs: %d\n", d.Header.FieldIDsSize))
	sb.WriteString(fmt.Sprintf("Method IDs: %d\n", d.Header.MethodIDsSize))
	sb.WriteString(fmt.Sprintf("Class defs: %d\n", d.Header.ClassDefsSize))

	return sb.String()
}

// ShowClass shows detailed information about a class.
func (d *DexFile) ShowClass(classIdx uint32) string {
	if int(classIdx) >= len(d.ClassDefs) {
		return "Class index out of range"
	}

	var sb strings.Builder
	cd := d.ClassDefs[classIdx]
	className := d.GetClassName(classIdx)

	sb.WriteString(fmt.Sprintf("Class: %s\n", className))
	sb.WriteString(fmt.Sprintf("Access: %s\n", GetAccessFlagsString(cd.AccessFlags)))

	if cd.SuperclassIdx != NO_INDEX {
		sb.WriteString(fmt.Sprintf("Extends: %s\n", d.GetTypeName(cd.SuperclassIdx)))
	}

	ifaces := d.GetInterfaces(classIdx)
	if len(ifaces) > 0 {
		sb.WriteString(fmt.Sprintf("Implements: %s\n", strings.Join(ifaces, ", ")))
	}

	if cd.SourceFileIdx != NO_INDEX {
		sb.WriteString(fmt.Sprintf("Source: %s\n", d.GetString(cd.SourceFileIdx)))
	}

	classData, ok := d.ClassData[classIdx]
	if ok {
		sb.WriteString(fmt.Sprintf("\nStatic fields (%d):\n", classData.StaticFieldsSize))
		for _, f := range classData.StaticFields {
			sb.WriteString(fmt.Sprintf("  %s %s %s\n",
				GetAccessFlagsString(f.AccessFlags),
				d.GetFieldName(f.FieldIdxDiff),
				d.GetTypeName(uint32(d.FieldIDs[f.FieldIdxDiff].TypeIdx))))
		}

		sb.WriteString(fmt.Sprintf("\nInstance fields (%d):\n", classData.InstanceFieldsSize))
		for _, f := range classData.InstanceFields {
			sb.WriteString(fmt.Sprintf("  %s %s %s\n",
				GetAccessFlagsString(f.AccessFlags),
				d.GetFieldName(f.FieldIdxDiff),
				d.GetTypeName(uint32(d.FieldIDs[f.FieldIdxDiff].TypeIdx))))
		}

		sb.WriteString(fmt.Sprintf("\nDirect methods (%d):\n", classData.DirectMethodsSize))
		for _, m := range classData.DirectMethods {
			sb.WriteString(fmt.Sprintf("  %s %s%s\n",
				GetAccessFlagsString(m.AccessFlags),
				d.GetMethodName(m.MethodIdxDiff),
				d.GetMethodDescriptor(m.MethodIdxDiff)))
		}

		sb.WriteString(fmt.Sprintf("\nVirtual methods (%d):\n", classData.VirtualMethodsSize))
		for _, m := range classData.VirtualMethods {
			sb.WriteString(fmt.Sprintf("  %s %s%s\n",
				GetAccessFlagsString(m.AccessFlags),
				d.GetMethodName(m.MethodIdxDiff),
				d.GetMethodDescriptor(m.MethodIdxDiff)))
		}
	}

	return sb.String()
}

// ShowMethod shows detailed information about a method including disassembly.
func (d *DexFile) ShowMethod(methodIdx uint32) string {
	if int(methodIdx) >= len(d.MethodIDs) {
		return "Method index out of range"
	}

	var sb strings.Builder
	m := d.MethodIDs[methodIdx]
	className := d.GetTypeName(uint32(m.ClassIdx))
	methodName := d.GetString(m.NameIdx)
	descriptor := d.GetProtoSignature(uint32(m.ProtoIdx))

	sb.WriteString(fmt.Sprintf("Method: %s->%s%s\n", className, methodName, descriptor))

	// Find and disassemble code
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
				code, err := d.ParseDalvikCode(method.CodeOff)
				if err == nil {
					sb.WriteString(showCode(d, code))
				}
				return sb.String()
			}
		}

		for _, method := range classData.VirtualMethods {
			if method.MethodIdxDiff == methodIdx && method.CodeOff > 0 {
				code, err := d.ParseDalvikCode(method.CodeOff)
				if err == nil {
					sb.WriteString(showCode(d, code))
				}
				return sb.String()
			}
		}
	}

	sb.WriteString("  (no code - abstract/native)\n")
	return sb.String()
}

func showCode(d *DexFile, code *DalvikCode) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Registers: %d, Ins: %d, Outs: %d\n",
		code.RegistersSize, code.InsSize, code.OutsSize))

	insns := code.Disassemble(d)
	for _, insn := range insns {
		sb.WriteString(fmt.Sprintf("  %s\n", insn.FormatString(d)))
	}

	if code.HasTryCatch() {
		sb.WriteString("\n  Exception handlers:\n")
		for _, tryItem := range code.Tries {
			sb.WriteString(fmt.Sprintf("    %s\n", tryItem.String()))
		}
	}

	if code.HasDebugInfo() {
		if len(code.DebugInfo.ParamNames) > 0 {
			sb.WriteString(fmt.Sprintf("  Parameters: %s\n",
				strings.Join(code.DebugInfo.ParamNames, ", ")))
		}
	}

	return sb.String()
}

// ShowStrings prints all strings in the DEX.
func (d *DexFile) ShowStrings() string {
	var sb strings.Builder
	for i, sd := range d.StringData {
		sb.WriteString(fmt.Sprintf("[%d] %q\n", i, sd.Data))
	}
	return sb.String()
}

// ShowTypes prints all type IDs.
func (d *DexFile) ShowTypes() string {
	var sb strings.Builder
	for i, t := range d.TypeIDs {
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i, d.GetString(t.DescriptorIdx)))
	}
	return sb.String()
}

// ShowMethods prints all method IDs.
func (d *DexFile) ShowMethods() string {
	var sb strings.Builder
	for i, m := range d.MethodIDs {
		sb.WriteString(fmt.Sprintf("[%d] %s->%s%s\n", i,
			d.GetTypeName(uint32(m.ClassIdx)),
			d.GetString(m.NameIdx),
			d.GetProtoSignature(uint32(m.ProtoIdx))))
	}
	return sb.String()
}

// ShowFields prints all field IDs.
func (d *DexFile) ShowFields() string {
	var sb strings.Builder
	for i, f := range d.FieldIDs {
		sb.WriteString(fmt.Sprintf("[%d] %s->%s %s\n", i,
			d.GetTypeName(uint32(f.ClassIdx)),
			d.GetString(f.NameIdx),
			d.GetTypeName(uint32(f.TypeIdx))))
	}
	return sb.String()
}

// ShowClasses prints all class definitions.
func (d *DexFile) ShowClasses() string {
	var sb strings.Builder
	for i := range d.ClassDefs {
		sb.WriteString(d.ShowClass(uint32(i)))
		sb.WriteString("\n")
	}
	return sb.String()
}

// GetInformation returns a summary of the DEX file.
func (d *DexFile) GetInformation() string {
	var sb strings.Builder
	sb.WriteString(d.Show())
	sb.WriteString(fmt.Sprintf("Classes: %d\n", d.GetLenClasses()))
	sb.WriteString(fmt.Sprintf("Methods: %d\n", d.GetLenMethods()))
	sb.WriteString(fmt.Sprintf("Fields: %d\n", d.GetLenFields()))
	sb.WriteString(fmt.Sprintf("Strings: %d\n", d.GetLenStrings()))
	sb.WriteString(fmt.Sprintf("Types: %d\n", d.GetLenTypes()))
	sb.WriteString(fmt.Sprintf("Protos: %d\n", d.GetLenProtos()))
	return sb.String()
}
