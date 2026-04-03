package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goandroguard/goandroguard/pkg/dex"
)

// BasicBlock represents a basic block in a method's control flow graph.
type BasicBlock struct {
	Name       string
	Start      uint32
	End        uint32
	Instructions []dex.Instruction
	Next       []*BasicBlock
	Prev       []*BasicBlock
	IsEntry    bool
	IsExit     bool
}

// ExternalClass represents a class not defined in the DEX (external/SDK class).
type ExternalClass struct {
	Name    string
	Methods []ExternalMethod
}

// ExternalMethod represents a method on an external class.
type ExternalMethod struct {
	ClassName    string
	Name         string
	Descriptor   string
	AccessFlags  uint32
}

// ExternalField represents a field on an external class.
type ExternalField struct {
	ClassName   string
	Name        string
	Descriptor  string
	AccessFlags uint32
}

// PermissionMapping maps Android API methods to permissions they require.
var PermissionMapping = map[string]string{
	// Location
	"getLastKnownLocation": "android.permission.ACCESS_FINE_LOCATION",
	"requestLocationUpdates": "android.permission.ACCESS_FINE_LOCATION",
	"getLatitude": "",
	"getLongitude": "",

	// Camera
	"open": "android.permission.CAMERA",
	"takePicture": "android.permission.CAMERA",

	// Internet
	"openConnection": "android.permission.INTERNET",
	"connect": "android.permission.INTERNET",

	// Storage
	"openFileOutput": "android.permission.WRITE_EXTERNAL_STORAGE",
	"openFileInput": "android.permission.READ_EXTERNAL_STORAGE",

	// Phone
	"getDeviceId": "android.permission.READ_PHONE_STATE",
	"getLine1Number": "android.permission.READ_PHONE_STATE",
	"getSubscriberId": "android.permission.READ_PHONE_STATE",

	// Contacts
	"query": "",  // Depends on URI

	// SMS
	"sendTextMessage": "android.permission.SEND_SMS",

	// Microphone
	"startRecording": "android.permission.RECORD_AUDIO",

	// Bluetooth
	"startLeScan": "android.permission.BLUETOOTH_ADMIN",
}

// FindClasses searches for classes matching a regex pattern.
func (a *Analysis) FindClasses(pattern string) []*ClassAnalysis {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var result []*ClassAnalysis
	for _, c := range a.classes {
		if re.MatchString(c.Name) {
			result = append(result, c)
		}
	}
	return result
}

// FindMethods searches for methods matching a regex pattern.
func (a *Analysis) FindMethods(pattern string) []*MethodAnalysis {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var result []*MethodAnalysis
	for _, m := range a.methods {
		fullName := fmt.Sprintf("%s->%s", m.ClassName, m.Name)
		if re.MatchString(fullName) || re.MatchString(m.Name) {
			result = append(result, m)
		}
	}
	return result
}

// FindStrings searches for strings matching a regex pattern.
func (a *Analysis) FindStrings(pattern string) []*StringAnalysis {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var result []*StringAnalysis
	for _, s := range a.strings {
		if re.MatchString(s.Value) {
			result = append(result, s)
		}
	}
	return result
}

// FindFields searches for fields matching a regex pattern.
func (a *Analysis) FindFields(pattern string) []*FieldAnalysis {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var result []*FieldAnalysis
	for _, f := range a.fields {
		fullName := fmt.Sprintf("%s->%s", f.ClassName, f.Name)
		if re.MatchString(fullName) || re.MatchString(f.Name) {
			result = append(result, f)
		}
	}
	return result
}

// GetExternalClasses returns all external classes (not defined in the DEX).
func (a *Analysis) GetExternalClasses() []*ExternalClass {
	// Build set of internal classes
	internalClasses := make(map[string]bool)
	for _, c := range a.classes {
		internalClasses[c.Name] = true
	}

	// Find all classes referenced but not defined
	externalMap := make(map[string]*ExternalClass)

	for _, m := range a.methods {
		for _, ref := range m.MethodRefs {
			parts := strings.SplitN(ref, "->", 2)
			if len(parts) == 2 && !internalClasses[parts[0]] {
				if _, ok := externalMap[parts[0]]; !ok {
					externalMap[parts[0]] = &ExternalClass{Name: parts[0]}
				}
			}
		}
		for _, ref := range m.TypeRefs {
			if !internalClasses[ref] {
				if _, ok := externalMap[ref]; !ok {
					externalMap[ref] = &ExternalClass{Name: ref}
				}
			}
		}
	}

	result := make([]*ExternalClass, 0, len(externalMap))
	for _, ec := range externalMap {
		result = append(result, ec)
	}
	return result
}

// GetInternalClasses returns all classes defined in the DEX.
func (a *Analysis) GetInternalClasses() []*ClassAnalysis {
	return a.classes
}

// GetInternalMethods returns all methods defined in the DEX.
func (a *Analysis) GetInternalMethods() []*MethodAnalysis {
	var result []*MethodAnalysis
	for _, m := range a.methods {
		if m.CodeOff > 0 || len(m.Instructions) > 0 {
			result = append(result, m)
		}
	}
	return result
}

// GetExternalMethods returns all methods called but not defined in the DEX.
func (a *Analysis) GetExternalMethods() []string {
	internalClasses := make(map[string]bool)
	for _, c := range a.classes {
		internalClasses[c.Name] = true
	}

	externalMethods := make(map[string]bool)
	for _, m := range a.methods {
		for _, ref := range m.MethodRefs {
			parts := strings.SplitN(ref, "->", 2)
			if len(parts) == 2 && !internalClasses[parts[0]] {
				externalMethods[ref] = true
			}
		}
	}

	result := make([]string, 0, len(externalMethods))
	for m := range externalMethods {
		result = append(result, m)
	}
	return result
}

// GetCallGraph builds a complete call graph for the DEX.
func (a *Analysis) GetCallGraph() map[string][]string {
	graph := make(map[string][]string)

	for _, m := range a.methods {
		key := fmt.Sprintf("%s->%s", m.ClassName, m.Name)
		graph[key] = m.MethodRefs
	}

	return graph
}

// GetMethodsCalled returns all methods called by the given method.
func (a *Analysis) GetMethodsCalled(className, methodName string) []string {
	for _, m := range a.methods {
		if m.ClassName == className && m.Name == methodName {
			return m.MethodRefs
		}
	}
	return nil
}

// GetFieldsAccessedInMethod returns all fields accessed by a method.
func (a *Analysis) GetFieldsAccessedInMethod(className, methodName string) []string {
	for _, m := range a.methods {
		if m.ClassName == className && m.Name == methodName {
			return m.FieldRefs
		}
	}
	return nil
}

// GetPermissionUsage returns methods that use APIs requiring permissions.
func (a *Analysis) GetPermissionUsage() map[string][]*MethodAnalysis {
	result := make(map[string][]*MethodAnalysis)

	for _, m := range a.methods {
		for _, ref := range m.MethodRefs {
			parts := strings.SplitN(ref, "->", 2)
			if len(parts) == 2 {
				methodName := parts[1]
				if perm, ok := PermissionMapping[methodName]; ok && perm != "" {
					result[perm] = append(result[perm], m)
				}
			}
		}
	}

	return result
}

// GetAndroidAPIUsage returns all external Android API methods used.
func (a *Analysis) GetAndroidAPIUsage() []string {
	androidAPIs := make(map[string]bool)

	for _, m := range a.methods {
		for _, ref := range m.MethodRefs {
			if strings.HasPrefix(ref, "Landroid/") || strings.HasPrefix(ref, "Lcom/android/") {
				androidAPIs[ref] = true
			}
		}
	}

	result := make([]string, 0, len(androidAPIs))
	for api := range androidAPIs {
		result = append(result, api)
	}
	return result
}

// GetMethodsByAccessFlags returns methods matching specific access flags.
func (a *Analysis) GetMethodsByAccessFlags(flags uint32) []*MethodAnalysis {
	var result []*MethodAnalysis
	for _, m := range a.methods {
		if m.AccessFlags&flags == flags {
			result = append(result, m)
		}
	}
	return result
}

// GetClassesByAccessFlags returns classes matching specific access flags.
func (a *Analysis) GetClassesByAccessFlags(flags uint32) []*ClassAnalysis {
	var result []*ClassAnalysis
	for _, c := range a.classes {
		if c.AccessFlags&flags == flags {
			result = append(result, c)
		}
	}
	return result
}

// BuildBasicBlocks builds basic blocks for a method's code.
func BuildBasicBlocks(insns []dex.Instruction) []*BasicBlock {
	if len(insns) == 0 {
		return nil
	}

	// Find leaders (instructions that start a basic block)
	leaders := make(map[uint32]bool)
	leaders[insns[0].Offset] = true // First instruction is always a leader

	for i, insn := range insns {
		// Branch targets are leaders
		for _, target := range insn.GetBranchTargets() {
			leaders[target] = true
		}

		// Instructions after branches are leaders
		if insn.IsBranch() || insn.IsReturn() || insn.CanThrow() {
			if i+1 < len(insns) {
				leaders[insns[i+1].Offset] = true
			}
		}
	}

	// Build blocks
	var blocks []*BasicBlock
	var current *BasicBlock

	for _, insn := range insns {
		if leaders[insn.Offset] {
			if current != nil {
				current.End = insn.Offset
				blocks = append(blocks, current)
			}
			current = &BasicBlock{
				Start: insn.Offset,
				Name:  fmt.Sprintf("block_%04x", insn.Offset),
			}
		}
		if current != nil {
			current.Instructions = append(current.Instructions, insn)
		}
	}

	if current != nil {
		if len(insns) > 0 {
			lastInsn := insns[len(insns)-1]
			current.End = lastInsn.Offset + uint32(dex.FormatInstructionSize(lastInsn.Opcode.Format))
		}
		blocks = append(blocks, current)
	}

	// Mark entry and exit blocks
	if len(blocks) > 0 {
		blocks[0].IsEntry = true
		for _, b := range blocks {
			if len(b.Instructions) > 0 {
				lastInsn := b.Instructions[len(b.Instructions)-1]
				if lastInsn.IsReturn() {
					b.IsExit = true
				}
			}
		}
	}

	// Build edges
	offsetToBlock := make(map[uint32]*BasicBlock)
	for _, b := range blocks {
		offsetToBlock[b.Start] = b
	}

	for _, b := range blocks {
		if len(b.Instructions) == 0 {
			continue
		}
		lastInsn := b.Instructions[len(b.Instructions)-1]

		// Branch targets
		for _, target := range lastInsn.GetBranchTargets() {
			if targetBlock, ok := offsetToBlock[target]; ok {
				b.Next = append(b.Next, targetBlock)
				targetBlock.Prev = append(targetBlock.Prev, b)
			}
		}

		// Fall-through (if not an unconditional branch or return)
		if !lastInsn.IsReturn() && lastInsn.Opcode.Name != "goto" &&
			lastInsn.Opcode.Name != "goto/16" && lastInsn.Opcode.Name != "goto/32" {
			// Find the next block
			for _, other := range blocks {
				if other.Start == b.End {
					b.Next = append(b.Next, other)
					other.Prev = append(other.Prev, b)
					break
				}
			}
		}
	}

	return blocks
}

// MethodAnalysis extension: add CodeOff field
// Note: This adds to the existing MethodAnalysis via a new field
