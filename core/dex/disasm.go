// Package dex provides bytecode disassembly for Dalvik instructions.
package dex

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Instruction represents a parsed Dalvik bytecode instruction.
type Instruction struct {
	Opcode    Opcode
	Offset    uint32 // Code offset in method
	Operands  []OperandValue
	RawBytes  []byte
}

// OperandValue represents an operand in an instruction.
type OperandValue struct {
	Type   OperandType
	Value  int64
	Ref    uint32 // Reference index for kind operands
	Kind   Kind
}

// OperandType identifies the type of an operand.
type OperandType int

const (
	OpRegister OperandType = iota // Register (v0, v1, etc.)
	OpLiteral                     // Numeric literal
	OpBranch                      // Branch offset
	OpString                      // String reference
	OpType                        // Type reference
	OpField                       // Field reference
	OpMethod                      // Method reference
	OpProto                       // Proto reference
	OpCallSite                    // Call site reference
)

// Disassembler provides Dalvik bytecode disassembly.
type Disassembler struct {
	dex   *DexFile
	code  []byte
	pos   int
}

// NewDisassembler creates a new disassembler for the given DEX file.
func NewDisassembler(dex *DexFile) *Disassembler {
	return &Disassembler{dex: dex}
}

// DisassembleCode disassembles all instructions in a code item.
func (d *Disassembler) DisassembleCode(codeItem *CodeItem) ([]Instruction, error) {
	if codeItem == nil || len(codeItem.Insns) == 0 {
		return nil, nil
	}

	// Convert uint16 instruction array to byte array
	d.code = make([]byte, len(codeItem.Insns)*2)
	for i, insn := range codeItem.Insns {
		binary.LittleEndian.PutUint16(d.code[i*2:], insn)
	}
	d.pos = 0

	var instructions []Instruction
	for d.pos < len(d.code) {
		insn, err := d.readInstruction()
		if err != nil {
			// Skip unknown bytes
			d.pos++
			continue
		}
		instructions = append(instructions, insn)
	}

	return instructions, nil
}

// DisassembleBytes disassembles raw bytecode bytes.
func (d *Disassembler) DisassembleBytes(code []byte) ([]Instruction, error) {
	d.code = code
	d.pos = 0

	var instructions []Instruction
	for d.pos < len(d.code) {
		insn, err := d.readInstruction()
		if err != nil {
			d.pos++
			continue
		}
		instructions = append(instructions, insn)
	}

	return instructions, nil
}

func (d *Disassembler) readInstruction() (Instruction, error) {
	if d.pos >= len(d.code) {
		return Instruction{}, fmt.Errorf("end of code")
	}

	offset := uint32(d.pos)
	opcodeByte := d.code[d.pos]

	opcode, ok := Opcodes[opcodeByte]
	if !ok {
		return Instruction{}, fmt.Errorf("unknown opcode: 0x%02x", opcodeByte)
	}

	insn := Instruction{
		Opcode: opcode,
		Offset: offset,
	}

	switch opcode.Format {
	case Format10x:
		// op (1 byte) + 0x00 padding (1 byte)
		insn.RawBytes = d.readBytes(2)
		d.pos += 2

	case Format12x:
		// op (1 byte) + B|A (1 byte)
		data := d.readBytes(2)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1] & 0x0F)},       // A
			{Type: OpRegister, Value: int64((data[1] >> 4) & 0x0F)}, // B
		}
		d.pos += 2

	case Format11n:
		// op (1 byte) + B|A (1 byte) - A is register, B is nibble literal
		data := d.readBytes(2)
		insn.RawBytes = data
		lit := int64(int8(data[1]>>4)) // sign-extended nibble
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1] & 0x0F)},
			{Type: OpLiteral, Value: lit},
		}
		d.pos += 2

	case Format11x:
		// op (1 byte) + AA (1 byte)
		data := d.readBytes(2)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
		}
		d.pos += 2

	case Format10t:
		// op (1 byte) + AA (signed offset)
		data := d.readBytes(2)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpBranch, Value: int64(int8(data[1]))},
		}
		d.pos += 2

	case Format20t:
		// op (1 byte) + 0x00 (1 byte) + AAAA (2 bytes signed offset)
		data := d.readBytes(4)
		insn.RawBytes = data
		offset := int64(int16(binary.LittleEndian.Uint16(data[2:])))
		insn.Operands = []OperandValue{
			{Type: OpBranch, Value: offset},
		}
		d.pos += 4

	case Format22x:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpRegister, Value: int64(binary.LittleEndian.Uint16(data[2:]))},
		}
		d.pos += 4

	case Format21t:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes signed offset)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpBranch, Value: int64(int16(binary.LittleEndian.Uint16(data[2:])))},
		}
		d.pos += 4

	case Format21s:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes signed literal)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpLiteral, Value: int64(int16(binary.LittleEndian.Uint16(data[2:])))},
		}
		d.pos += 4

	case Format21h:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes) - high literal
		data := d.readBytes(4)
		insn.RawBytes = data
		val := int64(binary.LittleEndian.Uint16(data[2:]))
		if opcodeByte == 0x15 || opcodeByte == 0x19 {
			val <<= 16 // high16 or wide high16
		} else {
			val <<= 48
		}
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpLiteral, Value: val},
		}
		d.pos += 4

	case Format21c:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes index)
		data := d.readBytes(4)
		insn.RawBytes = data
		idx := binary.LittleEndian.Uint16(data[2:])
		opType := d.getOperandType(opcode.Kind)
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: opType, Ref: uint32(idx), Kind: opcode.Kind},
		}
		d.pos += 4

	case Format23x:
		// op (1 byte) + AA (1 byte) + BB (1 byte) + CC (1 byte)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpRegister, Value: int64(data[2])},
			{Type: OpRegister, Value: int64(data[3])},
		}
		d.pos += 4

	case Format22b:
		// op (1 byte) + AA (1 byte) + BB (1 byte) + CC (1 byte signed literal)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpRegister, Value: int64(data[2])},
			{Type: OpLiteral, Value: int64(int8(data[3]))},
		}
		d.pos += 4

	case Format22t:
		// op (1 byte) + B|A (1 byte) + CCCC (2 bytes signed offset)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1] & 0x0F)},
			{Type: OpRegister, Value: int64((data[1] >> 4) & 0x0F)},
			{Type: OpBranch, Value: int64(int16(binary.LittleEndian.Uint16(data[2:])))},
		}
		d.pos += 4

	case Format22s:
		// op (1 byte) + B|A (1 byte) + CCCC (2 bytes signed literal)
		data := d.readBytes(4)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1] & 0x0F)},
			{Type: OpRegister, Value: int64((data[1] >> 4) & 0x0F)},
			{Type: OpLiteral, Value: int64(int16(binary.LittleEndian.Uint16(data[2:])))},
		}
		d.pos += 4

	case Format22c:
		// op (1 byte) + B|A (1 byte) + CCCC (2 bytes index)
		data := d.readBytes(4)
		insn.RawBytes = data
		idx := binary.LittleEndian.Uint16(data[2:])
		opType := d.getOperandType(opcode.Kind)
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1] & 0x0F)},
			{Type: OpRegister, Value: int64((data[1] >> 4) & 0x0F)},
			{Type: opType, Ref: uint32(idx), Kind: opcode.Kind},
		}
		d.pos += 4

	case Format32x:
		// op (1 byte) + 0x00 (1 byte) + AAAA (2 bytes) + BBBB (2 bytes)
		data := d.readBytes(6)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(binary.LittleEndian.Uint16(data[2:]))},
			{Type: OpRegister, Value: int64(binary.LittleEndian.Uint16(data[4:]))},
		}
		d.pos += 6

	case Format30t:
		// op (1 byte) + 0x00 (1 byte) + AAAAAAAA (4 bytes signed offset)
		data := d.readBytes(6)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpBranch, Value: int64(int32(binary.LittleEndian.Uint32(data[2:])))},
		}
		d.pos += 6

	case Format31t:
		// op (1 byte) + AA (1 byte) + BBBBBBBB (4 bytes)
		data := d.readBytes(6)
		insn.RawBytes = data
		ref := binary.LittleEndian.Uint32(data[2:])
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpLiteral, Value: int64(ref)},
		}
		d.pos += 6

	case Format31i:
		// op (1 byte) + AA (1 byte) + BBBBBBBB (4 bytes literal)
		data := d.readBytes(6)
		insn.RawBytes = data
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpLiteral, Value: int64(int32(binary.LittleEndian.Uint32(data[2:])))},
		}
		d.pos += 6

	case Format31c:
		// op (1 byte) + AA (1 byte) + BBBBBBBB (4 bytes index)
		data := d.readBytes(6)
		insn.RawBytes = data
		idx := binary.LittleEndian.Uint32(data[2:])
		opType := d.getOperandType(opcode.Kind)
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: opType, Ref: idx, Kind: opcode.Kind},
		}
		d.pos += 6

	case Format35c:
		// op (1 byte) + A|G (1 byte) + BBBB (2 bytes) + F|E|D|C (1 byte)
		data := d.readBytes(6)
		insn.RawBytes = data
		regCount := (data[1] >> 4) & 0x0F
		regG := data[1] & 0x0F
		idx := binary.LittleEndian.Uint16(data[2:])
		regs := data[4]

		operands := make([]OperandValue, 0, 6)
		// Add registers based on count
		registers := []int64{
			int64(regs & 0x0F),
			int64((regs >> 4) & 0x0F),
			int64(regG),
		}
		_ = registers
		for i := uint8(0); i < regCount && i < 5; i++ {
			var reg int64
			switch i {
			case 0:
				reg = int64(regs & 0x0F)
			case 1:
				reg = int64((regs >> 4) & 0x0F)
			case 2:
				reg = int64(regG)
			case 3:
				reg = int64((data[5] >> 4) & 0x0F)
			case 4:
				reg = int64(data[5] & 0x0F)
			}
			operands = append(operands, OperandValue{Type: OpRegister, Value: reg})
		}

		opType := d.getOperandType(opcode.Kind)
		operands = append(operands, OperandValue{Type: opType, Ref: uint32(idx), Kind: opcode.Kind})
		insn.Operands = operands
		d.pos += 6

	case Format3rc:
		// op (1 byte) + AA (1 byte) + BBBB (2 bytes) + CCCC (2 bytes)
		data := d.readBytes(6)
		insn.RawBytes = data
		regCount := int(data[1])
		idx := binary.LittleEndian.Uint16(data[2:])
		startReg := binary.LittleEndian.Uint16(data[4:])

		operands := make([]OperandValue, 0, regCount+1)
		for i := 0; i < regCount; i++ {
			operands = append(operands, OperandValue{Type: OpRegister, Value: int64(startReg + uint16(i))})
		}
		opType := d.getOperandType(opcode.Kind)
		operands = append(operands, OperandValue{Type: opType, Ref: uint32(idx), Kind: opcode.Kind})
		insn.Operands = operands
		d.pos += 6

	case Format51l:
		// op (1 byte) + AA (1 byte) + BBBBBBBBBBBBBBBB (8 bytes literal)
		data := d.readBytes(10)
		insn.RawBytes = data
		lit := int64(binary.LittleEndian.Uint64(data[2:]))
		insn.Operands = []OperandValue{
			{Type: OpRegister, Value: int64(data[1])},
			{Type: OpLiteral, Value: lit},
		}
		d.pos += 10

	default:
		// Unknown format, just read 2 bytes
		insn.RawBytes = d.readBytes(2)
		d.pos += 2
	}

	return insn, nil
}

func (d *Disassembler) readBytes(n int) []byte {
	if d.pos+n > len(d.code) {
		// Pad with zeros to ensure we always return n bytes
		result := make([]byte, n)
		copy(result, d.code[d.pos:])
		return result
	}
	return d.code[d.pos : d.pos+n]
}

func (d *Disassembler) getOperandType(k Kind) OperandType {
	switch k {
	case KindSTRING, KindRAW_STRING:
		return OpString
	case KindTYPE:
		return OpType
	case KindFIELD:
		return OpField
	case KindMETH:
		return OpMethod
	case KindPROTO, KindMETH_PROTO:
		return OpProto
	case KindCALL_SITE:
		return OpCallSite
	default:
		return OpRegister
	}
}

// String returns a human-readable string representation of the instruction.
func (insn Instruction) String() string {
	return insn.FormatString(nil)
}

// FormatString formats the instruction with optional DEX context for resolving references.
func (insn Instruction) FormatString(dex *DexFile) string {
	var sb strings.Builder

	// Offset
	sb.WriteString(fmt.Sprintf("0x%04x: %s", insn.Offset, insn.Opcode.Name))

	for i, op := range insn.Operands {
		if i == 0 {
			sb.WriteString(" ")
		} else {
			sb.WriteString(", ")
		}

		switch op.Type {
		case OpRegister:
			sb.WriteString(fmt.Sprintf("v%d", op.Value))
		case OpLiteral:
			sb.WriteString(fmt.Sprintf("#%d", op.Value))
		case OpBranch:
			target := insn.Offset + uint32(op.Value)*2
			sb.WriteString(fmt.Sprintf("+%d (0x%04x)", op.Value, target))
		case OpString:
			if dex != nil && int(op.Ref) < len(dex.StringData) {
				sb.WriteString(fmt.Sprintf("string@%d // %q", op.Ref, dex.GetString(op.Ref)))
			} else {
				sb.WriteString(fmt.Sprintf("string@%d", op.Ref))
			}
		case OpType:
			if dex != nil && int(op.Ref) < len(dex.TypeIDs) {
				sb.WriteString(fmt.Sprintf("type@%d // %s", op.Ref, dex.GetTypeName(op.Ref)))
			} else {
				sb.WriteString(fmt.Sprintf("type@%d", op.Ref))
			}
		case OpField:
			if dex != nil && int(op.Ref) < len(dex.FieldIDs) {
				sb.WriteString(fmt.Sprintf("field@%d // %s", op.Ref, dex.GetFieldName(op.Ref)))
			} else {
				sb.WriteString(fmt.Sprintf("field@%d", op.Ref))
			}
		case OpMethod:
			if dex != nil && int(op.Ref) < len(dex.MethodIDs) {
				sb.WriteString(fmt.Sprintf("method@%d // %s", op.Ref, dex.GetMethodName(op.Ref)))
			} else {
				sb.WriteString(fmt.Sprintf("method@%d", op.Ref))
			}
		case OpProto:
			sb.WriteString(fmt.Sprintf("proto@%d", op.Ref))
		case OpCallSite:
			sb.WriteString(fmt.Sprintf("call_site@%d", op.Ref))
		}
	}

	return sb.String()
}

// IsInvoke returns true if this instruction is an invoke.
func (insn Instruction) IsInvoke() bool {
	return insn.Opcode.Flags&FlagInvoke != 0
}

// IsBranch returns true if this instruction is a branch.
func (insn Instruction) IsBranch() bool {
	return insn.Opcode.Flags&FlagBranch != 0 || insn.Opcode.Flags&FlagSwitch != 0
}

// IsReturn returns true if this instruction returns from method.
func (insn Instruction) IsReturn() bool {
	return insn.Opcode.Flags&FlagCanReturn != 0
}

// CanThrow returns true if this instruction can throw an exception.
func (insn Instruction) CanThrow() bool {
	return insn.Opcode.Flags&FlagCanThrow != 0
}

// GetBranchTargets returns all branch target offsets from this instruction.
func (insn Instruction) GetBranchTargets() []uint32 {
	var targets []uint32
	for _, op := range insn.Operands {
		if op.Type == OpBranch {
			target := insn.Offset + uint32(op.Value)*2
			targets = append(targets, target)
		}
	}
	return targets
}

// DisassembleMethod disassembles a method by class and method index.
func (d *Disassembler) DisassembleMethod(classIdx, methodIdx uint32) ([]Instruction, error) {
	if d.dex == nil {
		return nil, fmt.Errorf("no DEX file loaded")
	}

	if int(classIdx) >= len(d.dex.ClassDefs) {
		return nil, fmt.Errorf("class index %d out of range", classIdx)
	}

	cd, ok := d.dex.ClassData[classIdx]
	if !ok {
		return nil, fmt.Errorf("no class data for class %d", classIdx)
	}

	// Search in direct methods
	for _, m := range cd.DirectMethods {
		if m.MethodIdxDiff == methodIdx || d.dex.MethodIDs[m.MethodIdxDiff].NameIdx == methodIdx {
			if m.CodeOff > 0 {
				code, ok := d.dex.CodeItems[m.CodeOff]
				if ok {
					return d.DisassembleCode(code)
				}
			}
		}
	}

	// Search in virtual methods
	for _, m := range cd.VirtualMethods {
		if m.MethodIdxDiff == methodIdx || d.dex.MethodIDs[m.MethodIdxDiff].NameIdx == methodIdx {
			if m.CodeOff > 0 {
				code, ok := d.dex.CodeItems[m.CodeOff]
				if ok {
					return d.DisassembleCode(code)
				}
			}
		}
	}

	return nil, fmt.Errorf("method not found or no code")
}

// FormatInstructionSize returns the byte size of an instruction for a given format.
func FormatInstructionSize(format InstructionFormat) int {
	switch format {
	case Format10x, Format12x, Format11n, Format11x, Format10t:
		return 2
	case Format20t, Format22x, Format21t, Format21s, Format21h, Format21c, Format23x, Format22b, Format22t, Format22s, Format22c:
		return 4
	case Format32x, Format30t, Format31t, Format31i, Format31c, Format35c, Format3rc:
		return 6
	case Format45cc, Format4rcc:
		return 8
	case Format51l:
		return 10
	default:
		return 2
	}
}

// DisassembleAll disassembles all code in a DEX file and returns instructions per method.
func DisassembleAll(dex *DexFile) (map[string][]Instruction, error) {
	d := NewDisassembler(dex)
	result := make(map[string][]Instruction)

	for classIdx := range dex.ClassDefs {
		cd, ok := dex.ClassData[uint32(classIdx)]
		if !ok {
			continue
		}

		className := dex.GetClassName(uint32(classIdx))

		for _, m := range cd.DirectMethods {
			if m.CodeOff > 0 {
				code, ok := dex.CodeItems[m.CodeOff]
				if ok {
					methodName := dex.GetMethodName(m.MethodIdxDiff)
					insns, _ := d.DisassembleCode(code)
					key := fmt.Sprintf("%s->%s (direct)", className, methodName)
					result[key] = insns
				}
			}
		}

		for _, m := range cd.VirtualMethods {
			if m.CodeOff > 0 {
				code, ok := dex.CodeItems[m.CodeOff]
				if ok {
					methodName := dex.GetMethodName(m.MethodIdxDiff)
					insns, _ := d.DisassembleCode(code)
					key := fmt.Sprintf("%s->%s (virtual)", className, methodName)
					result[key] = insns
				}
			}
		}
	}

	return result, nil
}
