// Package dex provides debug info parsing for DEX files.
// Debug info contains local variable names, line numbers, and source file information.
package dex

import (
	"fmt"

	"github.com/goandroguard/goandroguard/internal/leb128"
)

// Debug info opcodes
const (
	DBGEndSequence       = 0x00
	DBGAdvancePC         = 0x01
	DBGAdvanceLine       = 0x02
DBGStartLocal         = 0x03
DBGStartLocalExtended = 0x04
DBGEndLocal           = 0x05
DBGRestartLocal       = 0x06
DBGSetPrologueEnd     = 0x07
DBGSetEpilogueBegin   = 0x08
DBGSetFile            = 0x09
)

// DebugInfo represents parsed debug info for a code item.
type DebugInfo struct {
	LineStart   uint32
	ParamNames  []string // Parameter names
	Entries     []DebugEntry
	Locals      []LocalVariable
	Positions   []LinePosition
}

// DebugEntry represents a single debug info entry.
type DebugEntry struct {
	Opcode byte
	Args   []uint64
}

// LocalVariable represents a local variable with debug info.
type LocalVariable struct {
	Register uint32
	Name     string
	Type     string
	Signature string
	StartAddr uint32
	EndAddr   uint32
	IsLive    bool
}

// LinePosition represents a source line number mapping.
type LinePosition struct {
	Address uint32
	Line    uint32
}

// ParseDebugInfo parses a debug_info_item at the given offset.
func (d *DexFile) ParseDebugInfo(offset uint32) (*DebugInfo, error) {
	if offset >= uint32(len(d.raw)) {
		return nil, fmt.Errorf("debug info out of bounds")
	}

	info := &DebugInfo{}
	off := offset

	// line_start (uleb128)
	lineStart, n := leb128.ReadULEB128(d.raw[off:])
	info.LineStart = uint32(lineStart)
	off += uint32(n)

	// parameters_size (uleb128)
	paramsSize, n := leb128.ReadULEB128(d.raw[off:])
	off += uint32(n)

	// Read parameter names
	for i := uint64(0); i < paramsSize; i++ {
		// uleb128p1 - index into string_ids (NO_INDEX if unknown)
		nameIdx, n := leb128.ReadUleb128p1(d.raw[off:])
		off += uint32(n)

		if nameIdx >= 0 && int(nameIdx) < len(d.StringData) {
			info.ParamNames = append(info.ParamNames, d.GetString(uint32(nameIdx)))
		} else {
			info.ParamNames = append(info.ParamNames, fmt.Sprintf("p%d", i))
		}
	}

	// Parse debug entries
	currentLine := info.LineStart
	currentAddr := uint32(0)
	var currentLocals []LocalVariable

	for {
		if off >= uint32(len(d.raw)) {
			break
		}

		opcode := d.raw[off]
		off++

		entry := DebugEntry{Opcode: opcode}

		switch opcode {
		case DBGEndSequence:
			info.Entries = append(info.Entries, entry)
			goto done

		case DBGAdvancePC:
			addrDiff, n := leb128.ReadULEB128(d.raw[off:])
			off += uint32(n)
			currentAddr += uint32(addrDiff)
			entry.Args = []uint64{addrDiff}

		case DBGAdvanceLine:
			lineDiff, n := leb128.ReadSLEB128(d.raw[off:])
			off += uint32(n)
			currentLine = uint32(int32(currentLine) + int32(lineDiff))
			entry.Args = []uint64{uint64(lineDiff)}

		case DBGStartLocal:
			regNum, n1 := leb128.ReadULEB128(d.raw[off:])
			off += uint32(n1)
			nameIdx, n2 := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n2)
			typeIdx, n3 := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n3)

			local := LocalVariable{
				Register:  uint32(regNum),
				StartAddr: currentAddr,
				IsLive:    true,
			}

			if nameIdx >= 0 && int(nameIdx) < len(d.StringData) {
				local.Name = d.GetString(uint32(nameIdx))
			}
			if typeIdx >= 0 && int(typeIdx) < len(d.TypeIDs) {
				local.Type = d.GetTypeName(uint32(typeIdx))
			}

			currentLocals = append(currentLocals, local)
			entry.Args = []uint64{regNum, uint64(nameIdx), uint64(typeIdx)}

		case DBGStartLocalExtended:
			regNum, n1 := leb128.ReadULEB128(d.raw[off:])
			off += uint32(n1)
			nameIdx, n2 := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n2)
			typeIdx, n3 := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n3)
			sigIdx, n4 := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n4)

			local := LocalVariable{
				Register:  uint32(regNum),
				StartAddr: currentAddr,
				IsLive:    true,
			}

			if nameIdx >= 0 && int(nameIdx) < len(d.StringData) {
				local.Name = d.GetString(uint32(nameIdx))
			}
			if typeIdx >= 0 && int(typeIdx) < len(d.TypeIDs) {
				local.Type = d.GetTypeName(uint32(typeIdx))
			}
			if sigIdx >= 0 && int(sigIdx) < len(d.StringData) {
				local.Signature = d.GetString(uint32(sigIdx))
			}

			currentLocals = append(currentLocals, local)
			entry.Args = []uint64{regNum, uint64(nameIdx), uint64(typeIdx), uint64(sigIdx)}

		case DBGEndLocal:
			regNum, n := leb128.ReadULEB128(d.raw[off:])
			off += uint32(n)

			// Mark local as ended
			for i := range currentLocals {
				if currentLocals[i].Register == uint32(regNum) && currentLocals[i].IsLive {
					currentLocals[i].EndAddr = currentAddr
					currentLocals[i].IsLive = false
				}
			}

			entry.Args = []uint64{regNum}

		case DBGRestartLocal:
			regNum, n := leb128.ReadULEB128(d.raw[off:])
			off += uint32(n)

			// Restart a local - find the most recent one and create a new one with same info
			for i := len(currentLocals) - 1; i >= 0; i-- {
				if currentLocals[i].Register == uint32(regNum) {
					newLocal := currentLocals[i]
					newLocal.StartAddr = currentAddr
					newLocal.EndAddr = 0
					newLocal.IsLive = true
					currentLocals = append(currentLocals, newLocal)
					break
				}
			}

			entry.Args = []uint64{regNum}

		case DBGSetPrologueEnd:
			// No arguments

		case DBGSetEpilogueBegin:
			// No arguments

		case DBGSetFile:
			fileIdx, n := leb128.ReadUleb128p1(d.raw[off:])
			off += uint32(n)
			entry.Args = []uint64{uint64(fileIdx)}

		default:
			// Special opcodes (0x0A-0xFF)
			if opcode >= 0x0A {
				// addr_diff = (opcode - 0x0A) / 15
				// line_diff = DBG_LINE_BASE + (opcode - 0x0A) % 15
				adjustedOpcode := opcode - 0x0A
				addrDiff := uint32(adjustedOpcode) / 15
				lineDiff := int32(-4) + int32(adjustedOpcode%15)

				currentAddr += addrDiff
				currentLine = uint32(int32(currentLine) + lineDiff)

				// Emit a line position entry
				info.Positions = append(info.Positions, LinePosition{
					Address: currentAddr,
					Line:    currentLine,
				})

				entry.Args = []uint64{uint64(addrDiff), uint64(lineDiff)}
			}
		}

		info.Entries = append(info.Entries, entry)
	}

done:
	// Finalize locals
	for i := range currentLocals {
		if currentLocals[i].IsLive {
			currentLocals[i].EndAddr = currentAddr
		}
	}
	info.Locals = currentLocals

	return info, nil
}

// GetLocalVariableByName returns the local variable with the given name.
func (info *DebugInfo) GetLocalVariableByName(name string) *LocalVariable {
	for i := range info.Locals {
		if info.Locals[i].Name == name {
			return &info.Locals[i]
		}
	}
	return nil
}

// GetLocalVariablesAtAddr returns local variables live at the given address.
func (info *DebugInfo) GetLocalVariablesAtAddr(addr uint32) []LocalVariable {
	var result []LocalVariable
	for _, local := range info.Locals {
		if local.StartAddr <= addr && (local.EndAddr == 0 || local.EndAddr > addr) {
			result = append(result, local)
		}
	}
	return result
}

// GetLineAtAddr returns the source line number for the given address.
func (info *DebugInfo) GetLineAtAddr(addr uint32) uint32 {
	var lastLine uint32 = info.LineStart
	for _, pos := range info.Positions {
		if pos.Address <= addr {
			lastLine = pos.Line
		} else {
			break
		}
	}
	return lastLine
}

// GetParameterName returns the parameter name at the given index.
func (info *DebugInfo) GetParameterName(index int) string {
	if index >= 0 && index < len(info.ParamNames) {
		return info.ParamNames[index]
	}
	return fmt.Sprintf("p%d", index)
}

// String returns a string representation of debug info.
func (info *DebugInfo) String() string {
	result := fmt.Sprintf("Line Start: %d\n", info.LineStart)

	if len(info.ParamNames) > 0 {
		result += "Parameters:\n"
		for i, name := range info.ParamNames {
			result += fmt.Sprintf("  p%d: %s\n", i, name)
		}
	}

	if len(info.Locals) > 0 {
		result += "Local Variables:\n"
		for _, local := range info.Locals {
			result += fmt.Sprintf("  v%d: %s (type: %s, range: 0x%04x-0x%04x)\n",
				local.Register, local.Name, local.Type, local.StartAddr, local.EndAddr)
		}
	}

	if len(info.Positions) > 0 {
		result += fmt.Sprintf("Line Positions: %d entries\n", len(info.Positions))
	}

	return result
}
