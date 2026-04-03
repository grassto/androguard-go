// Package analysis provides code analysis features for DEX files.
// It includes control flow analysis, method cross-references, and string analysis.
package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goandroguard/goandroguard/core/dex"
)

// Analysis holds analysis results for a DEX file.
type Analysis struct {
	dexFile       *dex.DexFile
	classes       []*ClassAnalysis
	methods       []*MethodAnalysis
	fields        []*FieldAnalysis
	strings       []*StringAnalysis
	xrefs          map[string][]XRef
}

// ClassAnalysis holds analysis data for a class.
type ClassAnalysis struct {
	Name          string
	Idx           uint32
	AccessFlags   uint32
	SuperClass    string
	Interfaces    []string
	IsAbstract    bool
	IsInterface   bool
	IsFinal       bool
	Methods       []*MethodAnalysis
	Fields        []*FieldAnalysis
	Annotations   []string
}

// MethodAnalysis holds analysis data for a method.
type MethodAnalysis struct {
	Name          string
	Descriptor    string
	ClassName     string
	Idx           uint32
	AccessFlags   uint32
	CodeOff       uint32
	IsStatic      bool
	IsAbstract    bool
	IsNative      bool
	IsConstructor bool
	IsVirtual     bool
	Instructions  []dex.Instruction
	StringRefs    []string
	MethodRefs    []string
	FieldRefs     []string
	TypeRefs      []string
	XRefsTo       []XRef
	XRefsFrom     []XRef
	Exceptions    []string
}

// FieldAnalysis holds analysis data for a field.
type FieldAnalysis struct {
	Name          string
	Descriptor    string
	ClassName     string
	Idx           uint32
	AccessFlags   uint32
	IsStatic      bool
	IsFinal       bool
	XRefsTo       []XRef
	XRefsFrom     []XRef
}

// StringAnalysis holds analysis data for a string reference.
type StringAnalysis struct {
	Value     string
	Idx       uint32
	XRefsTo   []XRef
	Methods   []string // Methods that reference this string
}

// XRef represents a cross-reference between code elements.
type XRef struct {
	Type       XRefType
	FromClass  string
	FromMethod string
	FromClassIdx  uint32
	FromMethodIdx uint32
	Offset     uint32
	Insn       dex.Instruction
}

// XRefType identifies the type of cross-reference.
type XRefType int

const (
	XRefCall XRefType = iota // Method call
	XRefRead                 // Field read
	XRefWrite                // Field write
	XRefString               // String reference
	XRefTypeOf               // Type reference
)

func (t XRefType) String() string {
	switch t {
	case XRefCall:
		return "call"
	case XRefRead:
		return "read"
	case XRefWrite:
		return "write"
	case XRefString:
		return "string"
	case XRefTypeOf:
		return "typeof"
	default:
		return "unknown"
	}
}

// New creates a new Analysis for the given DEX file.
func New(df *dex.DexFile) *Analysis {
	a := &Analysis{
		dexFile: df,
		xrefs:   make(map[string][]XRef),
	}
	a.analyze()
	return a
}

// analyze performs full analysis of the DEX file.
func (a *Analysis) analyze() {
	a.analyzeClasses()
	a.analyzeMethods()
	a.analyzeFields()
	a.analyzeStrings()
	a.buildXRefs()
}

func (a *Analysis) analyzeClasses() {
	if a.dexFile == nil {
		return
	}

	for i, classDef := range a.dexFile.ClassDefs {
		ca := &ClassAnalysis{
			Name:        a.dexFile.GetClassName(uint32(i)),
			Idx:         uint32(i),
			AccessFlags: classDef.AccessFlags,
			IsAbstract:  classDef.AccessFlags&dex.AccAbstract != 0,
			IsInterface: classDef.AccessFlags&dex.AccInterface != 0,
			IsFinal:     classDef.AccessFlags&dex.AccFinal != 0,
		}

		if classDef.SuperclassIdx != dex.NO_INDEX {
			ca.SuperClass = a.dexFile.GetTypeName(classDef.SuperclassIdx)
		}

		// Parse interfaces
		if classDef.InterfacesOff > 0 {
			off := classDef.InterfacesOff
			if off+4 <= uint32(len(a.dexFile.Header.Magic)*0+100) { // Bounds check simplified
				// Would parse type_list here
			}
		}

		a.classes = append(a.classes, ca)
	}
}

func (a *Analysis) analyzeMethods() {
	if a.dexFile == nil {
		return
	}

	disasm := dex.NewDisassembler(a.dexFile)

	for _, classDef := range a.dexFile.ClassDefs {
		className := a.dexFile.GetTypeName(classDef.ClassIdx)
		classIdx := classDef.ClassIdx

		cd, ok := a.dexFile.ClassData[classIdx]
		if !ok {
			continue
		}

		// Analyze direct methods
		for _, m := range cd.DirectMethods {
			ma := a.analyzeMethod(disasm, className, classIdx, m, false)
			a.methods = append(a.methods, ma)
		}

		// Analyze virtual methods
		for _, m := range cd.VirtualMethods {
			ma := a.analyzeMethod(disasm, className, classIdx, m, true)
			a.methods = append(a.methods, ma)
		}
	}
}

func (a *Analysis) analyzeMethod(disasm *dex.Disassembler, className string, classIdx uint32, m dex.EncodedMethod, isVirtual bool) *MethodAnalysis {
	ma := &MethodAnalysis{
		ClassName:     className,
		Idx:           m.MethodIdxDiff,
		AccessFlags:   m.AccessFlags,
		CodeOff:       m.CodeOff,
		IsStatic:      m.AccessFlags&dex.AccStatic != 0,
		IsAbstract:    m.AccessFlags&dex.AccAbstract != 0,
		IsNative:      m.AccessFlags&dex.AccNative != 0,
		IsConstructor: m.AccessFlags&dex.AccConstructor != 0,
		IsVirtual:     isVirtual,
	}

	if int(m.MethodIdxDiff) < len(a.dexFile.MethodIDs) {
		methodID := a.dexFile.MethodIDs[m.MethodIdxDiff]
		ma.Name = a.dexFile.GetString(methodID.NameIdx)
		ma.Descriptor = a.dexFile.GetProtoSignature(uint32(methodID.ProtoIdx))
	}

	// Disassemble code
	if m.CodeOff > 0 {
		codeItem, ok := a.dexFile.CodeItems[m.CodeOff]
		if ok {
			insns, err := disasm.DisassembleCode(codeItem)
			if err == nil {
				ma.Instructions = insns

				// Extract references from instructions
				for _, insn := range insns {
					for _, op := range insn.Operands {
						switch op.Type {
						case dex.OpString:
							if int(op.Ref) < len(a.dexFile.StringData) {
								str := a.dexFile.GetString(op.Ref)
								ma.StringRefs = append(ma.StringRefs, str)
							}
						case dex.OpMethod:
							if int(op.Ref) < len(a.dexFile.MethodIDs) {
								methodName := a.dexFile.GetMethodName(op.Ref)
								ma.MethodRefs = append(ma.MethodRefs, methodName)
							}
						case dex.OpField:
							if int(op.Ref) < len(a.dexFile.FieldIDs) {
								fieldName := a.dexFile.GetFieldName(op.Ref)
								ma.FieldRefs = append(ma.FieldRefs, fieldName)
							}
						case dex.OpType:
							if int(op.Ref) < len(a.dexFile.TypeIDs) {
								typeName := a.dexFile.GetTypeName(op.Ref)
								ma.TypeRefs = append(ma.TypeRefs, typeName)
							}
						}
					}
				}
			}
		}
	}

	return ma
}

func (a *Analysis) analyzeFields() {
	if a.dexFile == nil {
		return
	}

	for _, classDef := range a.dexFile.ClassDefs {
		className := a.dexFile.GetTypeName(classDef.ClassIdx)
		classIdx := classDef.ClassIdx

		cd, ok := a.dexFile.ClassData[classIdx]
		if !ok {
			continue
		}

		// Analyze static fields
		for _, f := range cd.StaticFields {
			fa := &FieldAnalysis{
				Idx:         f.FieldIdxDiff,
				ClassName:   className,
				AccessFlags: f.AccessFlags,
				IsStatic:    true,
				IsFinal:     f.AccessFlags&dex.AccFinal != 0,
			}

			if int(f.FieldIdxDiff) < len(a.dexFile.FieldIDs) {
				fieldID := a.dexFile.FieldIDs[f.FieldIdxDiff]
				fa.Name = a.dexFile.GetString(fieldID.NameIdx)
				fa.Descriptor = a.dexFile.GetTypeName(uint32(fieldID.TypeIdx))
			}

			a.fields = append(a.fields, fa)
		}

		// Analyze instance fields
		for _, f := range cd.InstanceFields {
			fa := &FieldAnalysis{
				Idx:         f.FieldIdxDiff,
				ClassName:   className,
				AccessFlags: f.AccessFlags,
				IsStatic:    false,
				IsFinal:     f.AccessFlags&dex.AccFinal != 0,
			}

			if int(f.FieldIdxDiff) < len(a.dexFile.FieldIDs) {
				fieldID := a.dexFile.FieldIDs[f.FieldIdxDiff]
				fa.Name = a.dexFile.GetString(fieldID.NameIdx)
				fa.Descriptor = a.dexFile.GetTypeName(uint32(fieldID.TypeIdx))
			}

			a.fields = append(a.fields, fa)
		}
	}
}

func (a *Analysis) analyzeStrings() {
	if a.dexFile == nil {
		return
	}

	for i, sd := range a.dexFile.StringData {
		sa := &StringAnalysis{
			Value: sd.Data,
			Idx:   uint32(i),
		}
		a.strings = append(a.strings, sa)
	}
}

func (a *Analysis) buildXRefs() {
	// Build cross-references by scanning all method instructions
	for _, ma := range a.methods {
		methodKey := fmt.Sprintf("%s->%s", ma.ClassName, ma.Name)

		for _, insn := range ma.Instructions {
			for _, op := range insn.Operands {
				switch op.Type {
				case dex.OpMethod:
					if int(op.Ref) < len(a.dexFile.MethodIDs) {
						targetMethod := a.dexFile.GetMethodName(op.Ref)
						xref := XRef{
							Type:       XRefCall,
							FromClass:  ma.ClassName,
							FromMethod: ma.Name,
							Offset:     insn.Offset,
							Insn:       insn,
						}
						a.xrefs[targetMethod] = append(a.xrefs[targetMethod], xref)
						ma.XRefsFrom = append(ma.XRefsFrom, xref)
					}
				case dex.OpField:
					if int(op.Ref) < len(a.dexFile.FieldIDs) {
						targetField := a.dexFile.GetFieldName(op.Ref)
						xrefType := XRefRead
						if insn.Opcode.Flags&dex.FlagFieldOp != 0 {
							if strings.HasPrefix(insn.Opcode.Name, "sput") || strings.HasPrefix(insn.Opcode.Name, "iput") {
								xrefType = XRefWrite
							}
						}
						xref := XRef{
							Type:       xrefType,
							FromClass:  ma.ClassName,
							FromMethod: ma.Name,
							Offset:     insn.Offset,
							Insn:       insn,
						}
						a.xrefs[targetField] = append(a.xrefs[targetField], xref)
					}
				case dex.OpString:
					if int(op.Ref) < len(a.dexFile.StringData) {
						xref := XRef{
							Type:       XRefString,
							FromClass:  ma.ClassName,
							FromMethod: ma.Name,
							Offset:     insn.Offset,
							Insn:       insn,
						}
						key := fmt.Sprintf("string:%d", op.Ref)
						a.xrefs[key] = append(a.xrefs[key], xref)

						// Update string analysis
						for _, sa := range a.strings {
							if sa.Idx == op.Ref {
								sa.XRefsTo = append(sa.XRefsTo, xref)
								sa.Methods = append(sa.Methods, methodKey)
							}
						}
					}
				}
			}
		}
	}
}

// GetClasses returns all analyzed classes.
func (a *Analysis) GetClasses() []*ClassAnalysis {
	return a.classes
}

// GetMethods returns all analyzed methods.
func (a *Analysis) GetMethods() []*MethodAnalysis {
	return a.methods
}

// GetFields returns all analyzed fields.
func (a *Analysis) GetFields() []*FieldAnalysis {
	return a.fields
}

// GetStrings returns all analyzed strings.
func (a *Analysis) GetStrings() []*StringAnalysis {
	return a.strings
}

// GetClassByName returns the class analysis for the given name.
func (a *Analysis) GetClassByName(name string) *ClassAnalysis {
	for _, c := range a.classes {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// GetMethodByName returns methods matching the given name.
func (a *Analysis) GetMethodByName(name string) []*MethodAnalysis {
	var result []*MethodAnalysis
	for _, m := range a.methods {
		if m.Name == name {
			result = append(result, m)
		}
	}
	return result
}

// GetXRefs returns cross-references to the given target.
func (a *Analysis) GetXRefs(target string) []XRef {
	return a.xrefs[target]
}

// GetMethodsCalling returns all methods that call the given method.
func (a *Analysis) GetMethodsCalling(classMethod string) []XRef {
	return a.xrefs[classMethod]
}

// IsClassPresent checks if a class name is present in the analysis.
func (a *Analysis) IsClassPresent(name string) bool {
	for _, c := range a.classes {
		if c.Name == name {
			return true
		}
	}
	return false
}

// GetClassAnalysis returns the ClassAnalysis for the given class name.
func (a *Analysis) GetClassAnalysis(name string) *ClassAnalysis {
	return a.GetClassByName(name)
}

// GetMethodAnalysisByName returns all MethodAnalysis matching the method name.
func (a *Analysis) GetMethodAnalysisByName(name string) []*MethodAnalysis {
	var result []*MethodAnalysis
	for _, m := range a.methods {
		if m.Name == name {
			result = append(result, m)
		}
	}
	return result
}

// GetStringsAnalysis returns all strings as a map of value -> StringAnalysis.
func (a *Analysis) GetStringsAnalysis() map[string]*StringAnalysis {
	result := make(map[string]*StringAnalysis)
	for _, s := range a.strings {
		result[s.Value] = s
	}
	return result
}

// CreateXref is an alias for internal xref building.
// In Python androguard this is called after adding DEX files.
func (a *Analysis) CreateXref() {
	// xrefs are already built during analyze()
}

// GetPermissions returns permission strings found in the analysis.
func (a *Analysis) GetPermissions() []string {
	perms := make(map[string]bool)
	for _, s := range a.strings {
		if strings.HasPrefix(s.Value, "android.permission.") ||
			strings.HasPrefix(s.Value, "android.app.permission.") {
			perms[s.Value] = true
		}
	}
	result := make([]string, 0, len(perms))
	for p := range perms {
		result = append(result, p)
	}
	return result
}

// GetStringsUsedInMethod returns all strings used in a method.
func (a *Analysis) GetStringsUsedInMethod(className, methodName string) []string {
	for _, m := range a.methods {
		if m.ClassName == className && m.Name == methodName {
			return m.StringRefs
		}
	}
	return nil
}

// GetMethodCallGraph returns a simple call graph starting from the given method.
func (a *Analysis) GetMethodCallGraph(className, methodName string, maxDepth int) map[string][]string {
	graph := make(map[string][]string)
	visited := make(map[string]bool)
	a.buildCallGraph(className, methodName, graph, visited, 0, maxDepth)
	return graph
}

func (a *Analysis) buildCallGraph(className, methodName string, graph map[string][]string, visited map[string]bool, depth, maxDepth int) {
	if maxDepth > 0 && depth >= maxDepth {
		return
	}

	key := fmt.Sprintf("%s->%s", className, methodName)
	if visited[key] {
		return
	}
	visited[key] = true

	for _, m := range a.methods {
		if m.ClassName == className && m.Name == methodName {
			for _, callee := range m.MethodRefs {
				graph[key] = append(graph[key], callee)
				// Parse callee to get class and method
				parts := strings.SplitN(callee, "->", 2)
				if len(parts) == 2 {
					a.buildCallGraph(parts[0], parts[1], graph, visited, depth+1, maxDepth)
				}
			}
			break
		}
	}
}

// GetEncryptedStrings attempts to find strings that are likely encrypted.
func (a *Analysis) GetEncryptedStrings() []*StringAnalysis {
	var result []*StringAnalysis
	for _, s := range a.strings {
		if isLikelyEncrypted(s.Value) {
			result = append(result, s)
		}
	}
	return result
}

// GetInterestingStrings returns strings that look interesting (URLs, IPs, etc.)
func (a *Analysis) GetInterestingStrings() map[string][]string {
	result := make(map[string][]string)

	for _, s := range a.strings {
		v := s.Value
		switch {
		case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
			result["urls"] = append(result["urls"], v)
		case strings.Contains(v, ".com") || strings.Contains(v, ".net") || strings.Contains(v, ".org"):
			result["domains"] = append(result["domains"], v)
		case isIPAddress(v):
			result["ips"] = append(result["ips"], v)
		case strings.Contains(v, "android.permission"):
			result["permissions"] = append(result["permissions"], v)
		case strings.HasPrefix(v, "L") && strings.HasSuffix(v, ";"):
			result["classnames"] = append(result["classnames"], v)
		case strings.Contains(v, "key") || strings.Contains(v, "secret") || strings.Contains(v, "token") || strings.Contains(v, "password"):
			result["sensitive_keywords"] = append(result["sensitive_keywords"], v)
		}
	}

	// Sort results
	for k := range result {
		sort.Strings(result[k])
	}

	return result
}

func isLikelyEncrypted(s string) bool {
	if len(s) < 8 {
		return false
	}
	// Check for high entropy (base64-like characters mixed)
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '+' || c == '/' || c == '=':
			hasSpecial = true
		}
	}

	// Likely base64 or encoded if it has multiple character classes
	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}

	return count >= 3 && len(s) > 20
}

func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// String returns a summary of the analysis.
func (a *Analysis) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Classes: %d\n", len(a.classes)))
	sb.WriteString(fmt.Sprintf("Methods: %d\n", len(a.methods)))
	sb.WriteString(fmt.Sprintf("Fields: %d\n", len(a.fields)))
	sb.WriteString(fmt.Sprintf("Strings: %d\n", len(a.strings)))

	// Count by access flags
	publicClasses := 0
	abstractClasses := 0
	interfaces := 0
	for _, c := range a.classes {
		if c.AccessFlags&dex.AccPublic != 0 {
			publicClasses++
		}
		if c.IsAbstract {
			abstractClasses++
		}
		if c.IsInterface {
			interfaces++
		}
	}

	sb.WriteString(fmt.Sprintf("\nClass Breakdown:\n"))
	sb.WriteString(fmt.Sprintf("  Public: %d\n", publicClasses))
	sb.WriteString(fmt.Sprintf("  Abstract: %d\n", abstractClasses))
	sb.WriteString(fmt.Sprintf("  Interfaces: %d\n", interfaces))

	// Method counts
	staticMethods := 0
	nativeMethods := 0
	abstractMethods := 0
	for _, m := range a.methods {
		if m.IsStatic {
			staticMethods++
		}
		if m.IsNative {
			nativeMethods++
		}
		if m.IsAbstract {
			abstractMethods++
		}
	}

	sb.WriteString(fmt.Sprintf("\nMethod Breakdown:\n"))
	sb.WriteString(fmt.Sprintf("  Static: %d\n", staticMethods))
	sb.WriteString(fmt.Sprintf("  Native: %d\n", nativeMethods))
	sb.WriteString(fmt.Sprintf("  Abstract: %d\n", abstractMethods))

	return sb.String()
}
