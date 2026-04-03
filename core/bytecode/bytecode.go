// Package bytecode provides pretty printing, graph export, and formatting
// utilities for DEX bytecode analysis.
package bytecode

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/grassto/androguard-go/core/analysis"
	"github.com/grassto/androguard-go/core/config"
	"github.com/grassto/androguard-go/core/dex"
)

// FormatClassToJava transforms a class name to the typed variant found in DEX files.
// Example: "java.lang.Object" -> "Ljava/lang/Object;"
func FormatClassToJava(class string) string {
	return "L" + strings.ReplaceAll(class, ".", "/") + ";"
}

// FormatClassToPython transforms a typed class name to a Python-safe attribute form.
// Example: "Lfoo/bar/foo/Barfoo$InnerClass;" -> "Lfoo_bar_foo_Barfoo_InnerClass"
func FormatClassToPython(class string) string {
	if len(class) > 0 && class[len(class)-1] == ';' {
		class = class[:len(class)-1]
	}
	class = strings.ReplaceAll(class, "/", "_")
	class = strings.ReplaceAll(class, "$", "_")
	return class
}

// FormatNameToPython transforms a method name to a Python-safe attribute form.
// Example: "<clinit>" -> "clinit"
func FormatNameToPython(name string) string {
	name = strings.ReplaceAll(name, "<", "")
	name = strings.ReplaceAll(name, ">", "")
	name = strings.ReplaceAll(name, "$", "_")
	return name
}

// FormatDescriptorToPython formats a descriptor to a Python-safe form.
// Example: "(Ljava/lang/Long; Ljava/lang/Long; Z Z)V" -> "Ljava_lang_LongLjava_lang_LongZZV"
func FormatDescriptorToPython(desc string) string {
	desc = strings.ReplaceAll(desc, "/", "_")
	desc = strings.ReplaceAll(desc, ";", "")
	desc = strings.ReplaceAll(desc, "[", "")
	desc = strings.ReplaceAll(desc, "(", "")
	desc = strings.ReplaceAll(desc, ")", "")
	desc = strings.ReplaceAll(desc, " ", "")
	desc = strings.ReplaceAll(desc, "$", "")
	return desc
}

// GetPackageClassName returns package and class name from a typed DEX name.
// If no package could be found, the package is an empty string.
// Example: "Ljava/lang/Object;" -> ("java.lang", "Object")
func GetPackageClassName(name string) (string, string, error) {
	if len(name) == 0 || name[len(name)-1] != ';' {
		return "", "", fmt.Errorf("name %q does not look like a typed name", name)
	}

	// Discard array types
	name = strings.TrimLeft(name, "[")
	if len(name) == 0 || name[0] != 'L' {
		return "", "", fmt.Errorf("name does not start with L")
	}

	name = name[1 : len(name)-1] // Remove L and ;
	if !strings.Contains(name, "/") {
		return "", name, nil
	}

	lastSlash := strings.LastIndex(name, "/")
	packageName := strings.ReplaceAll(name[:lastSlash], "/", ".")
	className := name[lastSlash+1:]
	return packageName, className, nil
}

// BasicBlock represents a basic block for pretty printing.
type BasicBlock struct {
	Name             string
	Start            uint32
	End              uint32
	Instructions     []dex.Instruction
	Childs           []*BasicBlock
	ExceptionAnalysis *ExceptionAnalysis
}

// ExceptionAnalysis represents exception analysis for a basic block.
type ExceptionAnalysis struct {
	Start     uint32
	End       uint32
	Exception []ExceptionEntry
}

// ExceptionEntry represents a single exception handler entry.
type ExceptionEntry struct {
	ExceptionType string
	HandlerAddr   uint32
	BasicBlock    *BasicBlock
}

// ShowBuff returns a string representation of the exception analysis.
func (ea *ExceptionAnalysis) ShowBuff() string {
	if ea == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%x:%x\n", ea.Start, ea.End))
	for _, e := range ea.Exception {
		bbName := "none"
		if e.BasicBlock != nil {
			bbName = e.BasicBlock.Name
		}
		sb.WriteString(fmt.Sprintf("\t(%s -> %x %s)\n", e.ExceptionType, e.HandlerAddr, bbName))
	}
	return sb.String()
}

// PrettyShow pretty-prints basic blocks with color coding.
func PrettyShow(basicBlocks []*BasicBlock, notes map[int][]string) string {
	var sb strings.Builder
	c := config.Global.Colors

	idx := uint32(0)
	for nb, bb := range basicBlocks {
		sb.WriteString(fmt.Sprintf("%s%s%s : \n", c.BB, bb.Name, c.Normal))

		for _, ins := range bb.Instructions {
			if n, ok := notes[nb]; ok {
				for _, note := range n {
					sb.WriteString(fmt.Sprintf("\t%s# %s%s\n", c.Note, note, c.Normal))
				}
			}

			sb.WriteString(fmt.Sprintf("\t%s%-3d%s(%s%08x%s) ",
				c.Offset, nb, c.Normal, c.OffsetAddr, idx, c.Normal))
			sb.WriteString(fmt.Sprintf("%s%-20s%s",
				c.InstructionName, ins.Opcode.Name, c.Normal))

			operands := formatOperands(ins, c.Output)
			sb.WriteString(strings.Join(operands, ", "))

			// Branch info for last instruction
			if &ins == &bb.Instructions[len(bb.Instructions)-1] && len(bb.Childs) > 0 {
				sb.WriteString(" ")
				sb.WriteString(fmt.Sprintf("%s[ ", c.Branch))
				for i, child := range bb.Childs {
					if i > 0 {
						sb.WriteString(" ")
					}
					sb.WriteString(child.Name)
				}
				sb.WriteString(fmt.Sprintf(" ]%s", c.Normal))
			}

			idx += uint32(len(ins.RawBytes))
			sb.WriteString("\n")
		}

		if bb.ExceptionAnalysis != nil {
			sb.WriteString(fmt.Sprintf("\t%s%s%s\n",
				c.Exception, bb.ExceptionAnalysis.ShowBuff(), c.Normal))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatOperands(ins dex.Instruction, colors config.OutputColors) []string {
	var ops []string
	for _, op := range ins.Operands {
		switch op.Type {
		case dex.OpRegister:
			ops = append(ops, fmt.Sprintf("%sv%d%s", colors.Registers, op.Value, colors.Normal))
		case dex.OpLiteral:
			ops = append(ops, fmt.Sprintf("%s%d%s", colors.Literal, op.Value, colors.Normal))
		case dex.OpBranch:
			ops = append(ops, fmt.Sprintf("%s@0x%x%s", colors.Offset, op.Value, colors.Normal))
		case dex.OpString:
			ops = append(ops, fmt.Sprintf("%s\"%d\"%s", colors.String, op.Ref, colors.Normal))
		case dex.OpType:
			ops = append(ops, fmt.Sprintf("%s%d%s", colors.Type, op.Ref, colors.Normal))
		case dex.OpField:
			ops = append(ops, fmt.Sprintf("%s%d%s", colors.Field, op.Ref, colors.Normal))
		case dex.OpMethod:
			ops = append(ops, fmt.Sprintf("%s%d%s", colors.Method, op.Ref, colors.Normal))
		default:
			ops = append(ops, fmt.Sprintf("%d", op.Value))
		}
	}
	return ops
}

// DotGraph represents a DOT format graph for a method.
type DotGraph struct {
	Name  string
	Nodes string
	Edges string
}

// Method2Dot exports a method analysis to DOT format.
func Method2Dot(mx *analysis.MethodAnalysis, dexFile *dex.DexFile) *DotGraph {
	fontFace := "monospace"

	colors := map[string]string{
		"true_branch":      "green",
		"false_branch":     "red",
		"default_branch":   "purple",
		"jump_branch":      "blue",
		"bg_idx":           "lightgray",
		"idx":              "blue",
		"bg_start_idx":     "yellow",
		"bg_instruction":   "lightgray",
		"instruction_name": "black",
		"string":           "red",
		"literal":          "green",
		"offset":           "#4000FF",
		"method":           "#DF3A01",
		"field":            "#088A08",
		"type":             "#0000FF",
	}

	nodeTpl := `    struct_%s [label=<
        <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="3">
            %s
        </TABLE>
    >];` + "\n"

	labelTpl := fmt.Sprintf(`        <TR>
            <TD ALIGN="LEFT" BGCOLOR="%%s"><FONT FACE="%s" color="%%s">%%04x</FONT></TD>
            <TD ALIGN="LEFT" BGCOLOR="%%s"><FONT FACE="%s" color="%%s">%%s</FONT> %%s</TD>
        </TR>`, fontFace, fontFace)

	linkTpl := `        <TR><TD PORT="%s"></TD></TR>` + "\n"

	var nodesHTML, edgesHTML strings.Builder

	methodLabel := fmt.Sprintf("%s.%s->%s", mx.ClassName, mx.Name, mx.Descriptor)

	// Generate a hash for unique node IDs
	h := md5.Sum([]byte(methodLabel))
	sha256 := fmt.Sprintf("%02x", h[:])

	// Process instructions as basic blocks
	for _, ins := range mx.Instructions {
		blockID := fmt.Sprintf("%s_%04x", sha256, ins.Offset)

		content := fmt.Sprintf(linkTpl, "header")
		content += fmt.Sprintf(labelTpl,
			colors["bg_idx"], colors["idx"], ins.Offset,
			colors["bg_instruction"], colors["instruction_name"],
			ins.Opcode.Name, formatOperandsSimple(ins, dexFile))
		content += fmt.Sprintf(linkTpl, "tail")

		nodesHTML.WriteString(fmt.Sprintf(nodeTpl, blockID, content))
	}

	return &DotGraph{
		Name:  methodLabel,
		Nodes: nodesHTML.String(),
		Edges: edgesHTML.String(),
	}
}

func formatOperandsSimple(ins dex.Instruction, dexFile *dex.DexFile) string {
	var ops []string
	for _, op := range ins.Operands {
		switch op.Type {
		case dex.OpRegister:
			ops = append(ops, fmt.Sprintf("v%d", op.Value))
		case dex.OpLiteral:
			ops = append(ops, fmt.Sprintf("0x%x", op.Value))
		case dex.OpBranch:
			ops = append(ops, fmt.Sprintf("@0x%x", op.Value))
		case dex.OpString:
			if dexFile != nil {
				s := dexFile.GetString(op.Ref)
				ops = append(ops, fmt.Sprintf("\"%s\"", s))
			} else {
				ops = append(ops, fmt.Sprintf("str@%d", op.Ref))
			}
		case dex.OpType:
			if dexFile != nil {
				ops = append(ops, dexFile.GetTypeName(op.Ref))
			} else {
				ops = append(ops, fmt.Sprintf("type@%d", op.Ref))
			}
		case dex.OpMethod:
			if dexFile != nil {
				ops = append(ops, dexFile.GetMethodName(op.Ref))
			} else {
				ops = append(ops, fmt.Sprintf("method@%d", op.Ref))
			}
		case dex.OpField:
			if dexFile != nil {
				ops = append(ops, dexFile.GetFieldName(op.Ref))
			} else {
				ops = append(ops, fmt.Sprintf("field@%d", op.Ref))
			}
		default:
			ops = append(ops, fmt.Sprintf("%d", op.Value))
		}
	}
	return strings.Join(ops, ", ")
}

// Method2Format exports a method graph to a DOT format string.
func Method2Format(g *DotGraph) string {
	h := md5.Sum([]byte(g.Name))
	return fmt.Sprintf(`digraph {
    graph [rankdir=TB]
    node [shape=plaintext]

    subgraph cluster_%02x {
        label="%s"
        %s
    }

    %s
}`, h[:], g.Name, g.Nodes, g.Edges)
}

// MethodJSON represents a method in JSON format for export.
type MethodJSON struct {
	BasicBlockID string              `json:"BasicBlockId"`
	Start        uint32              `json:"start"`
	Registers    int                 `json:"registers"`
	Instructions []InstructionJSON   `json:"instructions"`
	Edge         []string            `json:"Edge"`
}

// InstructionJSON represents an instruction in JSON format.
type InstructionJSON struct {
	Idx     uint32 `json:"idx"`
	Name    string `json:"name"`
	Operands string `json:"operands"`
}

// Method2JSON creates a JSON representation of a method's CFG.
func Method2JSON(mx *analysis.MethodAnalysis, dexFile *dex.DexFile) (string, error) {
	var reports []MethodJSON

	block := MethodJSON{
		BasicBlockID: fmt.Sprintf("%s.%s", mx.ClassName, mx.Name),
		Registers:    0,
	}

	for _, ins := range mx.Instructions {
		block.Instructions = append(block.Instructions, InstructionJSON{
			Idx:      ins.Offset,
			Name:     ins.Opcode.Name,
			Operands: formatOperandsSimple(ins, dexFile),
		})
	}

	reports = append(reports, block)

	result := map[string]interface{}{
		"reports": reports,
	}
	data, err := json.MarshalIndent(result, "", "  ")
	return string(data), err
}

// VM2JSON creates a JSON representation of a DEX file.
func VM2JSON(vm *dex.DexFile) (string, error) {
	type methodInfo struct {
		Name string `json:"name"`
	}
	type classInfo struct {
		Name    string       `json:"name"`
		Methods []methodInfo `json:"children"`
	}
	type rootInfo struct {
		Name     string      `json:"name"`
		Children []classInfo `json:"children"`
	}

	root := rootInfo{Name: "root"}

	classes := vm.GetClassesNames()
	for _, className := range classes {
		ci := classInfo{Name: className}
		classIdx := vm.GetClass(className)
		if classIdx >= 0 {
			methods := vm.GetMethodsOfClass(uint32(classIdx))
			for _, methodIdx := range methods {
				methodName := vm.GetMethodName(methodIdx)
				ci.Methods = append(ci.Methods, methodInfo{Name: methodName})
			}
		}
		root.Children = append(root.Children, ci)
	}

	data, err := json.MarshalIndent(root, "", "  ")
	return string(data), err
}
