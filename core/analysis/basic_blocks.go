package analysis

import (
	"fmt"
	"sort"

	"github.com/goandroguard/goandroguard/core/dex"
)

// DEXBasicBlock represents a basic block in a method's control flow graph.
type DEXBasicBlock struct {
	Name        string
	Start       uint32
	End         uint32
	Instructions []dex.Instruction
	Childs      []*DEXBasicBlock
	Fathers     []*DEXBasicBlock
	Notes       []string
	Exception   *ExceptionAnalysis
	Method      *MethodAnalysis
}

// GetInstructions returns an iterator over instructions.
func (bb *DEXBasicBlock) GetInstructions() []dex.Instruction {
	return bb.Instructions
}

// GetNbInstructions returns the number of instructions.
func (bb *DEXBasicBlock) GetNbInstructions() int {
	return len(bb.Instructions)
}

// GetLast returns the last instruction in the block.
func (bb *DEXBasicBlock) GetLast() *dex.Instruction {
	if len(bb.Instructions) == 0 {
		return nil
	}
	return &bb.Instructions[len(bb.Instructions)-1]
}

// GetFirst returns the first instruction in the block.
func (bb *DEXBasicBlock) GetFirst() *dex.Instruction {
	if len(bb.Instructions) == 0 {
		return nil
	}
	return &bb.Instructions[0]
}

// GetNotes returns all notes attached to this block.
func (bb *DEXBasicBlock) GetNotes() []string {
	return bb.Notes
}

// AddNote adds a note to this block.
func (bb *DEXBasicBlock) AddNote(note string) {
	bb.Notes = append(bb.Notes, note)
}

// SetNotes replaces all notes.
func (bb *DEXBasicBlock) SetNotes(notes []string) {
	bb.Notes = notes
}

// ClearNotes removes all notes.
func (bb *DEXBasicBlock) ClearNotes() {
	bb.Notes = nil
}

// GetExceptionAnalysis returns the exception analysis for this block.
func (bb *DEXBasicBlock) GetExceptionAnalysis() *ExceptionAnalysis {
	return bb.Exception
}

// SetExceptionAnalysis sets the exception analysis for this block.
func (bb *DEXBasicBlock) SetExceptionAnalysis(ea *ExceptionAnalysis) {
	bb.Exception = ea
}

// GetNext returns the next blocks (successors).
func (bb *DEXBasicBlock) GetNext() []*DEXBasicBlock {
	return bb.Childs
}

// GetPrev returns the previous blocks (predecessors).
func (bb *DEXBasicBlock) GetPrev() []*DEXBasicBlock {
	return bb.Fathers
}

// SetChilds sets the child blocks.
func (bb *DEXBasicBlock) SetChilds(childs []*DEXBasicBlock) {
	bb.Childs = childs
}

// SetFathers sets the father blocks.
func (bb *DEXBasicBlock) SetFathers(fathers []*DEXBasicBlock) {
	bb.Fathers = fathers
}

// Push adds a child block.
func (bb *DEXBasicBlock) Push(child *DEXBasicBlock) {
	bb.Childs = append(bb.Childs, child)
	child.Fathers = append(child.Fathers, bb)
}

// GetSpecialIns returns a special instruction (switch/payload) at the given offset.
func (bb *DEXBasicBlock) GetSpecialIns(offset uint32) *dex.Instruction {
	for i := range bb.Instructions {
		if bb.Instructions[i].Offset == offset {
			return &bb.Instructions[i]
		}
	}
	return nil
}

// GetLastLength returns the byte length of the last instruction.
func (bb *DEXBasicBlock) GetLastLength() int {
	last := bb.GetLast()
	if last == nil {
		return 0
	}
	return dex.FormatInstructionSize(last.Opcode.Format)
}

// String returns a human-readable representation.
func (bb *DEXBasicBlock) String() string {
	return fmt.Sprintf("BasicBlock[%s] 0x%04x-0x%04x (%d insns)",
		bb.Name, bb.Start, bb.End, len(bb.Instructions))
}

// Show prints the basic block.
func (bb *DEXBasicBlock) Show() string {
	s := fmt.Sprintf("%s: 0x%04x-0x%04x\n", bb.Name, bb.Start, bb.End)
	for _, insn := range bb.Instructions {
		s += fmt.Sprintf("  %s\n", insn.FormatString(nil))
	}
	return s
}

// BasicBlocks holds all basic blocks of a method.
type BasicBlocks struct {
	blocks []*DEXBasicBlock
}

// NewBasicBlocks creates a new BasicBlocks collection.
func NewBasicBlocks() *BasicBlocks {
	return &BasicBlocks{}
}

// Push adds a basic block.
func (bbs *BasicBlocks) Push(bb *DEXBasicBlock) {
	bbs.blocks = append(bbs.blocks, bb)
}

// Pop removes and returns the block at the given index.
func (bbs *BasicBlocks) Pop(idx int) *DEXBasicBlock {
	if idx < 0 || idx >= len(bbs.blocks) {
		return nil
	}
	bb := bbs.blocks[idx]
	bbs.blocks = append(bbs.blocks[:idx], bbs.blocks[idx+1:]...)
	return bb
}

// GetBasicBlock returns the basic block at the given index.
func (bbs *BasicBlocks) GetBasicBlock(idx int) *DEXBasicBlock {
	if idx < 0 || idx >= len(bbs.blocks) {
		return nil
	}
	return bbs.blocks[idx]
}

// GetBasicBlockByOffset returns the basic block containing the given offset.
func (bbs *BasicBlocks) GetBasicBlockByOffset(offset uint32) *DEXBasicBlock {
	for _, bb := range bbs.blocks {
		if offset >= bb.Start && offset < bb.End {
			return bb
		}
	}
	return nil
}

// Len returns the number of basic blocks.
func (bbs *BasicBlocks) Len() int {
	return len(bbs.blocks)
}

// Gets returns all basic blocks.
func (bbs *BasicBlocks) Gets() []*DEXBasicBlock {
	return bbs.blocks
}

// GetEntry returns the entry block (first block).
func (bbs *BasicBlocks) GetEntry() *DEXBasicBlock {
	if len(bbs.blocks) > 0 {
		return bbs.blocks[0]
	}
	return nil
}

// GetExit returns all exit blocks (blocks with no successors).
func (bbs *BasicBlocks) GetExit() []*DEXBasicBlock {
	var exits []*DEXBasicBlock
	for _, bb := range bbs.blocks {
		if len(bb.Childs) == 0 {
			exits = append(exits, bb)
		}
	}
	return exits
}

// ExceptionAnalysis analyzes exception handling in a method.
type ExceptionAnalysis struct {
	Start      uint32
	End        uint32
	Handlers   []ExceptionHandlerEntry
	BasicBlock *DEXBasicBlock
}

// ExceptionHandlerEntry represents a single exception handler entry.
type ExceptionHandlerEntry struct {
	ExceptionType string
	HandlerAddr   uint32
	BasicBlock    *DEXBasicBlock
	IsCatchAll    bool
}

// NewExceptionAnalysis creates an exception analysis from an ExceptionRange.
func NewExceptionAnalysis(er dex.ExceptionRange, bbs *BasicBlocks) *ExceptionAnalysis {
	ea := &ExceptionAnalysis{
		Start: er.StartAddr,
		End:   er.EndAddr,
	}

	// Find the basic block for this range
	ea.BasicBlock = bbs.GetBasicBlockByOffset(er.StartAddr)

	// Process handlers
	for _, h := range er.Handlers {
		entry := ExceptionHandlerEntry{
			ExceptionType: h.ExceptionType,
			HandlerAddr:   h.HandlerAddr,
			IsCatchAll:    h.IsCatchAll,
			BasicBlock:    bbs.GetBasicBlockByOffset(h.HandlerAddr),
		}
		ea.Handlers = append(ea.Handlers, entry)
	}

	return ea
}

// Get returns a summary dict-like structure.
func (ea *ExceptionAnalysis) Get() map[string]interface{} {
	d := map[string]interface{}{
		"start": ea.Start,
		"end":   ea.End,
	}

	var handlerList []map[string]interface{}
	for _, h := range ea.Handlers {
		handlerInfo := map[string]interface{}{
			"name":     h.ExceptionType,
			"addr":     h.HandlerAddr,
			"catchAll": h.IsCatchAll,
		}
		if h.BasicBlock != nil {
			handlerInfo["basicBlock"] = h.BasicBlock.Name
		}
		handlerList = append(handlerList, handlerInfo)
	}
	d["handlers"] = handlerList

	return d
}

// ShowBuff returns a string representation.
func (ea *ExceptionAnalysis) ShowBuff() string {
	s := fmt.Sprintf("%x:%x\n", ea.Start, ea.End)
	for _, h := range ea.Handlers {
		if h.BasicBlock != nil {
			s += fmt.Sprintf("\t(%s -> %x %s)\n", h.ExceptionType, h.HandlerAddr, h.BasicBlock.Name)
		} else {
			s += fmt.Sprintf("\t(%s -> %x)\n", h.ExceptionType, h.HandlerAddr)
		}
	}
	return s
}

// Exceptions manages all exception analyses for a method.
type Exceptions struct {
	exceptions []*ExceptionAnalysis
}

// NewExceptions creates a new Exceptions collection.
func NewExceptions() *Exceptions {
	return &Exceptions{}
}

// Add adds exception ranges with their associated basic blocks.
func (e *Exceptions) Add(ranges []dex.ExceptionRange, bbs *BasicBlocks) {
	for _, er := range ranges {
		ea := NewExceptionAnalysis(er, bbs)
		e.exceptions = append(e.exceptions, ea)
	}
}

// GetException returns the exception analysis covering the given range.
func (e *Exceptions) GetException(addrStart, addrEnd uint32) *ExceptionAnalysis {
	for _, ea := range e.exceptions {
		if ea.Start >= addrStart && ea.End <= addrEnd {
			return ea
		}
		if addrEnd <= ea.End && addrStart >= ea.Start {
			return ea
		}
	}
	return nil
}

// Gets returns all exception analyses.
func (e *Exceptions) Gets() []*ExceptionAnalysis {
	return e.exceptions
}

// Len returns the number of exception analyses.
func (e *Exceptions) Len() int {
	return len(e.exceptions)
}

// BuildBasicBlocksFromCode builds basic blocks from a DalvikCode.
func BuildBasicBlocksFromCode(code *dex.DalvikCode, dexFile *dex.DexFile) (*BasicBlocks, []*ExceptionAnalysis) {
	if code == nil {
		return nil, nil
	}

	insns := code.Disassemble(dexFile)
	if len(insns) == 0 {
		return nil, nil
	}

	bbs := NewBasicBlocks()

	// Find leaders
	leaders := findLeaders(insns, code, dexFile)

	// Create blocks
	blocks := createBlocks(insns, leaders)
	for _, bb := range blocks {
		bbs.Push(bb)
	}

	// Build edges
	buildEdges(bbs, code, dexFile)

	// Build exception analyses
	var exceptionAnalyses []*ExceptionAnalysis
	if code.HasTryCatch() {
		exceptionRanges := dex.DetermineException(code, dexFile)
		for _, er := range exceptionRanges {
			ea := NewExceptionAnalysis(er, bbs)
			exceptionAnalyses = append(exceptionAnalyses, ea)

			// Attach to basic blocks
			bb := bbs.GetBasicBlockByOffset(er.StartAddr)
			if bb != nil {
				bb.Exception = ea
			}
		}
	}

	return bbs, exceptionAnalyses
}

// findLeaders finds instructions that start a basic block.
func findLeaders(insns []dex.Instruction, code *dex.DalvikCode, dexFile *dex.DexFile) map[uint32]bool {
	leaders := make(map[uint32]bool)

	if len(insns) == 0 {
		return leaders
	}

	// First instruction is always a leader
	leaders[insns[0].Offset] = true

	for i, insn := range insns {
		// Branch targets are leaders
		nexts := dex.DetermineNext(insn, insn.Offset, code)
		for _, n := range nexts {
			if n >= 0 {
				leaders[uint32(n)] = true
			}
		}

		// Instructions after branches/returns are leaders
		if insn.IsBranch() || insn.IsReturn() || insn.CanThrow() {
			if i+1 < len(insns) {
				leaders[insns[i+1].Offset] = true
			}
		}

		// Exception handler targets are leaders
		if code != nil {
			handlers := code.GetCatchHandlersForAddress(insn.Offset)
			if handlers != nil {
				for _, h := range handlers.Handlers {
					leaders[h.Addr*2] = true
				}
				if handlers.HasCatchAll {
					leaders[handlers.CatchAllAddr*2] = true
				}
			}
		}
	}

	return leaders
}

// createBlocks creates basic blocks from instructions and leaders.
func createBlocks(insns []dex.Instruction, leaders map[uint32]bool) []*DEXBasicBlock {
	if len(insns) == 0 {
		return nil
	}

	// Sort leader offsets
	leaderOffsets := make([]uint32, 0, len(leaders))
	for offset := range leaders {
		leaderOffsets = append(leaderOffsets, offset)
	}
	sort.Slice(leaderOffsets, func(i, j int) bool {
		return leaderOffsets[i] < leaderOffsets[j]
	})

	var blocks []*DEXBasicBlock
	var current *DEXBasicBlock

	for _, insn := range insns {
		if leaders[insn.Offset] {
			if current != nil {
				current.End = insn.Offset
				blocks = append(blocks, current)
			}
			current = &DEXBasicBlock{
				Name:  fmt.Sprintf("block_%04x", insn.Offset),
				Start: insn.Offset,
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

	return blocks
}

// buildEdges builds control flow edges between basic blocks.
func buildEdges(bbs *BasicBlocks, code *dex.DalvikCode, dexFile *dex.DexFile) {
	blocks := bbs.Gets()
	if len(blocks) == 0 {
		return
	}

	// Build offset -> block map
	offsetToBlock := make(map[uint32]*DEXBasicBlock)
	for _, bb := range blocks {
		offsetToBlock[bb.Start] = bb
	}

	for _, bb := range blocks {
		if len(bb.Instructions) == 0 {
			continue
		}

		lastInsn := bb.Instructions[len(bb.Instructions)-1]
		nexts := dex.DetermineNext(lastInsn, lastInsn.Offset, code)

		for _, n := range nexts {
			if n < 0 {
				// Method exit (return/throw) - block has no successors
				continue
			}

			targetBlock := offsetToBlock[uint32(n)]
			if targetBlock != nil && targetBlock != bb {
				// Add edge
				alreadyConnected := false
				for _, child := range bb.Childs {
					if child == targetBlock {
						alreadyConnected = true
						break
					}
				}
				if !alreadyConnected {
					bb.Childs = append(bb.Childs, targetBlock)
					targetBlock.Fathers = append(targetBlock.Fathers, bb)
				}
			}
		}
	}
}
