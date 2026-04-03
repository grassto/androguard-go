package analysis

import (
	"testing"

	"github.com/goandroguard/goandroguard/pkg/dex"
)

func TestDEXBasicBlock(t *testing.T) {
	bb := &DEXBasicBlock{
		Name:  "test_block",
		Start: 0,
		End:   10,
		Instructions: []dex.Instruction{
			{Opcode: dex.Opcode{Name: "const/4"}, Offset: 0},
			{Opcode: dex.Opcode{Name: "return-void", Flags: dex.FlagCanReturn}, Offset: 2},
		},
	}

	if bb.GetNbInstructions() != 2 {
		t.Errorf("GetNbInstructions() = %d, want 2", bb.GetNbInstructions())
	}

	if bb.GetFirst() == nil || bb.GetFirst().Opcode.Name != "const/4" {
		t.Error("GetFirst() failed")
	}

	if bb.GetLast() == nil || bb.GetLast().Opcode.Name != "return-void" {
		t.Error("GetLast() failed")
	}

	if bb.GetLastLength() == 0 {
		t.Error("GetLastLength() should be > 0")
	}
}

func TestDEXBasicBlockNotes(t *testing.T) {
	bb := &DEXBasicBlock{}

	bb.AddNote("note1")
	bb.AddNote("note2")

	if len(bb.GetNotes()) != 2 {
		t.Errorf("GetNotes() returned %d, want 2", len(bb.GetNotes()))
	}

	bb.ClearNotes()
	if len(bb.GetNotes()) != 0 {
		t.Errorf("After ClearNotes(), got %d notes", len(bb.GetNotes()))
	}

	bb.SetNotes([]string{"a", "b", "c"})
	if len(bb.GetNotes()) != 3 {
		t.Errorf("After SetNotes(), got %d notes", len(bb.GetNotes()))
	}
}

func TestDEXBasicBlockEdges(t *testing.T) {
	bb1 := &DEXBasicBlock{Name: "block1"}
	bb2 := &DEXBasicBlock{Name: "block2"}
	bb3 := &DEXBasicBlock{Name: "block3"}

	bb1.Push(bb2)
	bb1.Push(bb3)

	if len(bb1.Childs) != 2 {
		t.Errorf("bb1 should have 2 children, got %d", len(bb1.Childs))
	}
	if len(bb2.Fathers) != 1 {
		t.Errorf("bb2 should have 1 father, got %d", len(bb2.Fathers))
	}
}

func TestBasicBlocks(t *testing.T) {
	bbs := NewBasicBlocks()

	bb1 := &DEXBasicBlock{Name: "block1", Start: 0, End: 10}
	bb2 := &DEXBasicBlock{Name: "block2", Start: 10, End: 20}
	bb3 := &DEXBasicBlock{Name: "block3", Start: 20, End: 30}

	bbs.Push(bb1)
	bbs.Push(bb2)
	bbs.Push(bb3)

	if bbs.Len() != 3 {
		t.Errorf("Len() = %d, want 3", bbs.Len())
	}

	if bbs.GetBasicBlock(1) != bb2 {
		t.Error("GetBasicBlock(1) failed")
	}

	if bbs.GetBasicBlockByOffset(15) != bb2 {
		t.Error("GetBasicBlockByOffset(15) should return bb2")
	}

	if bbs.GetEntry() != bb1 {
		t.Error("GetEntry() should return bb1")
	}

	// Pop
	popped := bbs.Pop(1)
	if popped != bb2 || bbs.Len() != 2 {
		t.Error("Pop(1) failed")
	}
}

func TestExceptions(t *testing.T) {
	exc := NewExceptions()

	er := dex.ExceptionRange{
		StartAddr: 0,
		EndAddr:   10,
		Handlers: []dex.ExceptionHandler{
			{ExceptionType: "Ljava/lang/Exception;", HandlerAddr: 20},
		},
	}

	bbs := NewBasicBlocks()
	bbs.Push(&DEXBasicBlock{Name: "try_block", Start: 0, End: 10})
	bbs.Push(&DEXBasicBlock{Name: "catch_block", Start: 20, End: 30})

	exc.Add([]dex.ExceptionRange{er}, bbs)

	if exc.Len() != 1 {
		t.Errorf("Len() = %d, want 1", exc.Len())
	}

	ea := exc.GetException(0, 10)
	if ea == nil {
		t.Fatal("GetException(0, 10) returned nil")
	}

	if ea.Start != 0 || ea.End != 10 {
		t.Errorf("Exception range = %d:%d, want 0:10", ea.Start, ea.End)
	}

	if len(ea.Handlers) != 1 {
		t.Fatalf("Handlers count = %d, want 1", len(ea.Handlers))
	}

	if ea.Handlers[0].ExceptionType != "Ljava/lang/Exception;" {
		t.Errorf("Handler type = %q, want Ljava/lang/Exception;", ea.Handlers[0].ExceptionType)
	}
}

func TestExceptionAnalysisGet(t *testing.T) {
	ea := &ExceptionAnalysis{
		Start: 0x100,
		End:   0x200,
		Handlers: []ExceptionHandlerEntry{
			{ExceptionType: "Ljava/io/IOException;", HandlerAddr: 0x300},
		},
	}

	d := ea.Get()
	if d["start"].(uint32) != 0x100 {
		t.Error("start should be 0x100")
	}
	if d["end"].(uint32) != 0x200 {
		t.Error("end should be 0x200")
	}
}

func TestBuildBasicBlocksFromCodeSimple(t *testing.T) {
	code := &dex.DalvikCode{
		RegistersSize: 2,
		InsSize:       1,
		Insns: []uint16{
			0x1200, // const/4 v0, 0
			0x0E00, // return-void
		},
		InsnsSize: 2,
	}

	// Create a minimal DexFile for disassembly
	dexFile := &dex.DexFile{
		Header: dex.Header{
			Magic: [8]byte{'d', 'e', 'x', '\n', '0', '3', '5', '\x00'},
		},
	}

	bbs, exc := BuildBasicBlocksFromCode(code, dexFile)
	if bbs == nil {
		t.Fatal("BuildBasicBlocksFromCode returned nil")
	}

	if bbs.Len() < 1 {
		t.Errorf("Expected at least 1 basic block, got %d", bbs.Len())
	}

	if exc != nil && len(exc) > 0 {
		t.Log("Found exception blocks (unexpected but OK)")
	}
}
