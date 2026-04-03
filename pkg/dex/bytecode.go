package dex

import (
	"fmt"
)

// Branch type constants
const (
	BranchNone    = 0 // Not a branch
	BranchGoto    = 1 // Unconditional jump
	BranchIf      = 2 // Conditional branch (2 targets)
	BranchSwitch  = 3 // Switch (multiple targets)
	BranchReturn  = 4 // Method return
	BranchThrow   = 5 // Exception throw
)

// BranchInfo describes the branch behavior of an instruction.
type BranchInfo struct {
	Type    int
	Targets []uint32 // Absolute byte offsets (-1 means method exit for return/throw)
}

// DetermineNext determines the next offsets in bytecode after executing an instruction.
// Offsets are in bytes from the start of the method.
// Returns -1 in targets to indicate method exit (return/throw).
func DetermineNext(insn Instruction, curIdx uint32, code *DalvikCode) []int64 {
	opValue := uint32(insn.Opcode.OpValue)

	switch {
	// throw + return*
	case opValue == 0x27 || (opValue >= 0x0E && opValue <= 0x11):
		return []int64{-1}

	// goto, goto/16, goto/32
	case opValue >= 0x28 && opValue <= 0x2A:
		if len(insn.Operands) > 0 {
			off := insn.Operands[0].Value * 2
			return []int64{off + int64(curIdx)}
		}
		return nil

	// if-* (conditional branches)
	case opValue >= 0x32 && opValue <= 0x3D:
		if len(insn.Operands) >= 2 {
			off := insn.Operands[len(insn.Operands)-1].Value * 2
			return []int64{
				int64(curIdx) + int64(FormatInstructionSize(insn.Opcode.Format)), // fall-through
				off + int64(curIdx), // branch target
			}
		}
		return nil

	// packed-switch, sparse-switch
	case opValue == 0x2B || opValue == 0x2C:
		// Fall-through target
		targets := []int64{int64(curIdx) + int64(FormatInstructionSize(insn.Opcode.Format))}

		if code != nil && len(insn.Operands) > 0 {
			payloadOffset := int32(insn.Operands[1].Value) * 2 // ref_off * 2
			payloadAddr := int32(curIdx) + payloadOffset

			// Handle alignment
			remaining := payloadAddr % 4
			if remaining != 0 {
				payloadAddr += 4 - remaining
			}

			// Parse payload from the instruction bytes
			rawBytes := code.GetCodeAsBytes()
			if int(payloadAddr) < len(rawBytes) {
				if opValue == 0x2B {
					// packed-switch
					payload, err := ParsePackedSwitchPayload(rawBytes[payloadAddr:], uint32(payloadAddr))
					if err == nil {
						for _, t := range payload.GetAllTargets() {
							targets = append(targets, int64(t))
						}
					}
				} else {
					// sparse-switch
					payload, err := ParseSparseSwitchPayload(rawBytes[payloadAddr:], uint32(payloadAddr))
					if err == nil {
						for _, t := range payload.GetAllTargets() {
							targets = append(targets, int64(t))
						}
					}
				}
			}
		}

		return targets

	// fill-array-data
	case opValue == 0x26:
		if code != nil && len(insn.Operands) > 0 {
			payloadOffset := int32(insn.Operands[1].Value) * 2
			payloadAddr := int32(curIdx) + payloadOffset

			remaining := payloadAddr % 4
			if remaining != 0 {
				payloadAddr += 4 - remaining
			}

			_ = payloadAddr // Just validate offset, continue to next instruction
		}
		// Continue to next instruction
		return []int64{int64(curIdx) + int64(FormatInstructionSize(insn.Opcode.Format))}

	// packed-switch-payload (0xFE) and sparse-switch-payload (0xFF)
	case opValue == 0xFE || opValue == 0xFF:
		// These are payloads, not executable - continue to next
		return nil
	}

	return nil
}

// GetBranchInfo returns branch information for an instruction.
func GetBranchInfo(insn Instruction, curIdx uint32, code *DalvikCode) *BranchInfo {
	opValue := uint32(insn.Opcode.OpValue)
	info := &BranchInfo{}

	switch {
	case opValue == 0x27: // throw
		info.Type = BranchThrow
		info.Targets = []uint32{0xFFFFFFFF} // sentinel for exit

	case opValue >= 0x0E && opValue <= 0x11: // return*
		info.Type = BranchReturn
		info.Targets = []uint32{0xFFFFFFFF}

	case opValue >= 0x28 && opValue <= 0x2A: // goto
		info.Type = BranchGoto
		if len(insn.Operands) > 0 {
			off := uint32(insn.Operands[0].Value) * 2
			info.Targets = []uint32{off + curIdx}
		}

	case opValue >= 0x32 && opValue <= 0x3D: // if-*
		info.Type = BranchIf
		if len(insn.Operands) >= 2 {
			off := uint32(insn.Operands[len(insn.Operands)-1].Value) * 2
			info.Targets = []uint32{
				curIdx + uint32(FormatInstructionSize(insn.Opcode.Format)),
				off + curIdx,
			}
		}

	case opValue == 0x2B || opValue == 0x2C: // switch
		info.Type = BranchSwitch
		nexts := DetermineNext(insn, curIdx, code)
		for _, n := range nexts {
			if n >= 0 {
				info.Targets = append(info.Targets, uint32(n))
			}
		}

	default:
		info.Type = BranchNone
	}

	return info
}

// ExceptionRange represents a try-catch block.
type ExceptionRange struct {
	StartAddr uint32                // Start of try block (byte offset)
	EndAddr   uint32                // End of try block (byte offset, exclusive)
	Handlers  []ExceptionHandler    // Catch handlers
}

// ExceptionHandler represents a single catch handler.
type ExceptionHandler struct {
	ExceptionType string // Type descriptor (e.g., "Ljava/lang/Exception;")
	HandlerAddr   uint32 // Byte offset of handler code
	IsCatchAll    bool
}

// DetermineException returns try-catch handler ranges for a method.
func DetermineException(code *DalvikCode, dex *DexFile) []ExceptionRange {
	if code == nil || !code.HasTryCatch() {
		return nil
	}

	var exceptions []ExceptionRange

	for _, tryItem := range code.Tries {
		er := ExceptionRange{
			StartAddr: tryItem.StartAddr,
			EndAddr:   tryItem.StartAddr + uint32(tryItem.InsnCount)*2,
		}

		if tryItem.Handler != nil {
			for _, handler := range tryItem.Handler.Handlers {
				eh := ExceptionHandler{
					HandlerAddr: handler.Addr * 2, // Convert from 16-bit to byte offset
				}
				if dex != nil && int(handler.TypeIdx) < len(dex.TypeIDs) {
					eh.ExceptionType = dex.GetTypeName(handler.TypeIdx)
				}
				er.Handlers = append(er.Handlers, eh)
			}

			if tryItem.Handler.HasCatchAll {
				er.Handlers = append(er.Handlers, ExceptionHandler{
					ExceptionType: "Ljava/lang/Throwable;",
					HandlerAddr:   tryItem.Handler.CatchAllAddr * 2,
					IsCatchAll:    true,
				})
			}
		}

		exceptions = append(exceptions, er)
	}

	return exceptions
}

// GetMethodExceptions returns exception ranges for a method by class and method index.
func (d *DexFile) GetMethodExceptions(classIdx, methodIdx uint32) []ExceptionRange {
	cd, ok := d.ClassData[classIdx]
	if !ok {
		return nil
	}

	// Find the method
	var codeOff uint32
	for _, m := range cd.DirectMethods {
		if m.MethodIdxDiff == methodIdx {
			codeOff = m.CodeOff
			break
		}
	}
	if codeOff == 0 {
		for _, m := range cd.VirtualMethods {
			if m.MethodIdxDiff == methodIdx {
				codeOff = m.CodeOff
				break
			}
		}
	}
	if codeOff == 0 {
		return nil
	}

	code, err := d.ParseDalvikCode(codeOff)
	if err != nil {
		return nil
	}

	return DetermineException(code, d)
}

// IsBranchTarget returns true if the given address is a branch target of any instruction.
func IsBranchTarget(insns []Instruction, target uint32) bool {
	for _, insn := range insns {
		nexts := DetermineNext(insn, insn.Offset, nil)
		for _, n := range nexts {
			if n >= 0 && uint32(n) == target {
				return true
			}
		}
	}
	return false
}

// GetExceptionHandlerTarget returns exception handler target addresses for an instruction.
func GetExceptionHandlerTarget(addr uint32, code *DalvikCode) []uint32 {
	if code == nil {
		return nil
	}

	var targets []uint32
	handlers := code.GetCatchHandlersForAddress(addr)
	if handlers != nil {
		for _, h := range handlers.Handlers {
			targets = append(targets, h.Addr*2)
		}
		if handlers.HasCatchAll {
			targets = append(targets, handlers.CatchAllAddr*2)
		}
	}
	return targets
}

// String returns a human-readable representation of an ExceptionRange.
func (er ExceptionRange) String() string {
	s := fmt.Sprintf("try [0x%04x-0x%04x]", er.StartAddr, er.EndAddr)
	for _, h := range er.Handlers {
		if h.IsCatchAll {
			s += fmt.Sprintf(" catch_all->0x%04x", h.HandlerAddr)
		} else {
			s += fmt.Sprintf(" %s->0x%04x", h.ExceptionType, h.HandlerAddr)
		}
	}
	return s
}
