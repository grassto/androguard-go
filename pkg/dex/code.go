package dex

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DalvikCode represents the full code of a method including instructions, try/catch, and debug info.
type DalvikCode struct {
	RegistersSize uint16
	InsSize       uint16
	OutsSize      uint16
	TriesSize     uint16
	DebugInfoOff  uint32
	InsnsSize     uint32
	Insns         []uint16
	Padding       uint16 // Present if insns_size is odd and tries_size > 0
	Tries         []TryItemFull
	Handlers      *EncodedCatchHandlerListFull
	DebugInfo     *DebugInfo
	offset        uint32
}

// TryItemFull represents a full try_item with parsed catch handler.
type TryItemFull struct {
	StartAddr  uint32
	InsnCount  uint16
	HandlerOff uint16
	Handler    *EncodedCatchHandlerFull // Parsed handler (if available)
}

// GetEndAddr returns the end address of the try block.
func (t *TryItemFull) GetEndAddr() uint32 {
	return t.StartAddr + uint32(t.InsnCount)*2
}

// CoversAddress returns true if this try block covers the given address.
func (t *TryItemFull) CoversAddress(addr uint32) bool {
	return addr >= t.StartAddr && addr < t.GetEndAddr()
}

// String returns a human-readable representation.
func (t *TryItemFull) String() string {
	return fmt.Sprintf("try [0x%04x-0x%04x] handler_off=%d", t.StartAddr, t.GetEndAddr(), t.HandlerOff)
}

// ParseDalvikCode parses a complete code item from the DEX file.
func (d *DexFile) ParseDalvikCode(offset uint32) (*DalvikCode, error) {
	if offset+16 > uint32(len(d.raw)) {
		return nil, fmt.Errorf("dalvik code: header out of bounds")
	}

	code := &DalvikCode{offset: offset}
	off := offset

	code.RegistersSize = binary.LittleEndian.Uint16(d.raw[off : off+2])
	off += 2
	code.InsSize = binary.LittleEndian.Uint16(d.raw[off : off+2])
	off += 2
	code.OutsSize = binary.LittleEndian.Uint16(d.raw[off : off+2])
	off += 2
	code.TriesSize = binary.LittleEndian.Uint16(d.raw[off : off+2])
	off += 2
	code.DebugInfoOff = binary.LittleEndian.Uint32(d.raw[off : off+4])
	off += 4
	code.InsnsSize = binary.LittleEndian.Uint32(d.raw[off : off+4])
	off += 4

	// Read instructions
	if code.InsnsSize > 0 {
		code.Insns = make([]uint16, code.InsnsSize)
		for i := uint32(0); i < code.InsnsSize; i++ {
			if off+2 > uint32(len(d.raw)) {
				return code, fmt.Errorf("dalvik code: instructions truncated")
			}
			code.Insns[i] = binary.LittleEndian.Uint16(d.raw[off : off+2])
			off += 2
		}
	}

	// Alignment padding
	if code.InsnsSize%2 == 1 && code.TriesSize > 0 {
		if off+2 <= uint32(len(d.raw)) {
			code.Padding = binary.LittleEndian.Uint16(d.raw[off : off+2])
			off += 2
		}
	}

	// Parse try items
	if code.TriesSize > 0 {
		code.Tries = make([]TryItemFull, code.TriesSize)
		for i := uint16(0); i < code.TriesSize; i++ {
			if off+8 > uint32(len(d.raw)) {
				break
			}
			code.Tries[i].StartAddr = binary.LittleEndian.Uint32(d.raw[off : off+4])
			off += 4
			code.Tries[i].InsnCount = binary.LittleEndian.Uint16(d.raw[off : off+2])
			off += 2
			code.Tries[i].HandlerOff = binary.LittleEndian.Uint16(d.raw[off : off+2])
			off += 2
		}

		// Parse catch handler list
		if off < uint32(len(d.raw)) {
			handlers, err := d.ParseEncodedCatchHandlerList(off)
			if err == nil {
				code.Handlers = handlers

				// Link handlers to try items
				for i := range code.Tries {
					handlerIdx := code.Tries[i].HandlerOff
					if int(handlerIdx) < len(handlers.Handlers) {
						code.Tries[i].Handler = &handlers.Handlers[handlerIdx]
					}
				}
			}
		}
	}

	// Parse debug info
	if code.DebugInfoOff > 0 && code.DebugInfoOff < uint32(len(d.raw)) {
		debug, err := d.ParseDebugInfo(code.DebugInfoOff)
		if err == nil {
			code.DebugInfo = debug
		}
	}

	return code, nil
}

// GetCodeAsBytes returns the raw instruction bytes.
func (c *DalvikCode) GetCodeAsBytes() []byte {
	raw := make([]byte, len(c.Insns)*2)
	for i, insn := range c.Insns {
		binary.LittleEndian.PutUint16(raw[i*2:], insn)
	}
	return raw
}

// GetTryBlockAt returns the try block covering the given address, or nil.
func (c *DalvikCode) GetTryBlockAt(addr uint32) *TryItemFull {
	for i := range c.Tries {
		if c.Tries[i].CoversAddress(addr) {
			return &c.Tries[i]
		}
	}
	return nil
}

// GetCatchHandlersForAddress returns all catch handlers for the given address.
func (c *DalvikCode) GetCatchHandlersForAddress(addr uint32) *EncodedCatchHandlerFull {
	tryBlock := c.GetTryBlockAt(addr)
	if tryBlock != nil && tryBlock.Handler != nil {
		return tryBlock.Handler
	}
	return nil
}

// GetAllCatchHandlers returns all unique catch handlers.
func (c *DalvikCode) GetAllCatchHandlers() []*EncodedCatchHandlerFull {
	var handlers []*EncodedCatchHandlerFull
	for i := range c.Tries {
		if c.Tries[i].Handler != nil {
			handlers = append(handlers, c.Tries[i].Handler)
		}
	}
	return handlers
}

// HasTryCatch returns true if the code has try/catch blocks.
func (c *DalvikCode) HasTryCatch() bool {
	return len(c.Tries) > 0
}

// HasDebugInfo returns true if debug info is available.
func (c *DalvikCode) HasDebugInfo() bool {
	return c.DebugInfo != nil
}

// GetLineNumber returns the source line number for the given bytecode address.
func (c *DalvikCode) GetLineNumber(addr uint32) uint32 {
	if c.DebugInfo != nil {
		return c.DebugInfo.GetLineAtAddr(addr)
	}
	return 0
}

// GetLocalVariable returns the local variable at the given register and address.
func (c *DalvikCode) GetLocalVariable(reg uint32, addr uint32) *LocalVariable {
	if c.DebugInfo != nil {
		for i := range c.DebugInfo.Locals {
			local := &c.DebugInfo.Locals[i]
			if local.Register == reg && local.StartAddr <= addr {
				if local.EndAddr == 0 || local.EndAddr > addr {
					return local
				}
			}
		}
	}
	return nil
}

// Disassemble disassembles all instructions in this code item.
func (c *DalvikCode) Disassemble(dex *DexFile) []Instruction {
	disasm := NewDisassembler(dex)
	codeItem := &CodeItem{
		RegistersSize: c.RegistersSize,
		InsSize:       c.InsSize,
		OutsSize:      c.OutsSize,
		TriesSize:     c.TriesSize,
		DebugInfoOff:  c.DebugInfoOff,
		InsnsSize:     c.InsnsSize,
		Insns:         c.Insns,
	}
	insns, _ := disasm.DisassembleCode(codeItem)
	return insns
}

// DCode manages a stream of instructions for a method.
type DCode struct {
	dex       *DexFile
	offset    uint32
	insns     []Instruction
	cached    bool
	notes     map[int][]string
}

// NewDCode creates a new DCode from raw instruction data.
func NewDCode(dex *DexFile, offset uint32, insns []Instruction) *DCode {
	return &DCode{
		dex:    dex,
		offset: offset,
		insns:  insns,
		cached: true,
		notes:  make(map[int][]string),
	}
}

// GetInstructions returns all instructions.
func (dc *DCode) GetInstructions() []Instruction {
	return dc.insns
}

// GetInstruction returns the instruction at the given index.
func (dc *DCode) GetInstruction(idx int) *Instruction {
	if idx >= 0 && idx < len(dc.insns) {
		return &dc.insns[idx]
	}
	return nil
}

// GetInstructionAtOffset returns the instruction at the given byte offset.
func (dc *DCode) GetInstructionAtOffset(offset uint32) *Instruction {
	for i := range dc.insns {
		if dc.insns[i].Offset == offset {
			return &dc.insns[i]
		}
	}
	return nil
}

// OffsetToIndex converts a byte offset to an instruction index.
func (dc *DCode) OffsetToIndex(offset uint32) int {
	for i, insn := range dc.insns {
		if insn.Offset == offset {
			return i
		}
	}
	return -1
}

// AddNote adds a note to a specific instruction.
func (dc *DCode) AddNote(idx int, note string) {
	dc.notes[idx] = append(dc.notes[idx], note)
}

// GetNotes returns notes for a specific instruction.
func (dc *DCode) GetNotes(idx int) []string {
	return dc.notes[idx]
}

// GetLength returns the total byte length of all instructions.
func (dc *DCode) GetLength() int {
	if len(dc.insns) == 0 {
		return 0
	}
	last := dc.insns[len(dc.insns)-1]
	return int(last.Offset) + FormatInstructionSize(last.Opcode.Format)
}

// Show prints all instructions.
func (dc *DCode) Show() string {
	var sb strings.Builder
	for _, insn := range dc.insns {
		sb.WriteString(insn.FormatString(dc.dex))
		sb.WriteString("\n")
	}
	return sb.String()
}

// LinearSweepAlgorithm provides static methods for linear sweep disassembly.
type LinearSweepAlgorithm struct{}

// Disassemble performs linear sweep disassembly on raw instruction bytes.
func (lsa *LinearSweepAlgorithm) Disassemble(dex *DexFile, data []byte, offset uint32) []Instruction {
	disasm := NewDisassembler(dex)
	codeItem := &CodeItem{
		InsnsSize: uint32(len(data) / 2),
		Insns:     make([]uint16, len(data)/2),
	}

	for i := 0; i < len(data)/2; i++ {
		if i*2+2 <= len(data) {
			codeItem.Insns[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
	}

	insns, _ := disasm.DisassembleCode(codeItem)

	// Adjust offsets
	for i := range insns {
		insns[i].Offset += offset
	}

	return insns
}
