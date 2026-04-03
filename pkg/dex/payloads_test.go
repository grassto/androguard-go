package dex

import (
	"encoding/binary"
	"testing"
)

func TestFillArrayDataPayload(t *testing.T) {
	// Build a fill-array-data-payload: ident=0x0300, width=1, size=4, data=[1,2,3,4]
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 0x0300) // ident
	binary.LittleEndian.PutUint16(data[2:4], 1)      // element width
	binary.LittleEndian.PutUint32(data[4:8], 4)      // size
	data[8] = 1
	data[9] = 2
	data[10] = 3
	data[11] = 4

	payload, err := ParseFillArrayDataPayload(data, 0)
	if err != nil {
		t.Fatalf("ParseFillArrayDataPayload failed: %v", err)
	}

	if payload.ElementWidth != 1 {
		t.Errorf("ElementWidth = %d, want 1", payload.ElementWidth)
	}
	if payload.Size != 4 {
		t.Errorf("Size = %d, want 4", payload.Size)
	}

	elements := payload.GetElements()
	if len(elements) != 4 {
		t.Fatalf("GetElements returned %d, want 4", len(elements))
	}
	if elements[0][0] != 1 || elements[3][0] != 4 {
		t.Errorf("Element values incorrect")
	}

	if payload.GetLength() != 12 {
		t.Errorf("GetLength = %d, want 12", payload.GetLength())
	}
}

func TestPackedSwitchPayload(t *testing.T) {
	// Build: ident=0x0100, size=3, first_key=10, targets=[0x100, 0x200, 0x300]
	data := make([]byte, 20)
	binary.LittleEndian.PutUint16(data[0:2], 0x0100) // ident
	binary.LittleEndian.PutUint16(data[2:4], 3)      // size
	binary.LittleEndian.PutUint32(data[4:8], 10)     // first_key
	binary.LittleEndian.PutUint32(data[8:12], 0x100)
	binary.LittleEndian.PutUint32(data[12:16], 0x200)
	binary.LittleEndian.PutUint32(data[16:20], 0x300)

	payload, err := ParsePackedSwitchPayload(data, 0)
	if err != nil {
		t.Fatalf("ParsePackedSwitchPayload failed: %v", err)
	}

	if payload.Size != 3 {
		t.Errorf("Size = %d, want 3", payload.Size)
	}
	if payload.FirstKey != 10 {
		t.Errorf("FirstKey = %d, want 10", payload.FirstKey)
	}

	keys := payload.GetKeys()
	if len(keys) != 3 {
		t.Fatalf("GetKeys returned %d, want 3", len(keys))
	}
	if keys[0] != 10 || keys[1] != 11 || keys[2] != 12 {
		t.Errorf("Keys = %v, want [10, 11, 12]", keys)
	}

	target, ok := payload.GetTargetForKey(11)
	if !ok || target != 0x200 {
		t.Errorf("GetTargetForKey(11) = %v, %v; want 0x200, true", target, ok)
	}

	target, ok = payload.GetTargetForKey(99)
	if ok {
		t.Errorf("GetTargetForKey(99) should return false")
	}
}

func TestSparseSwitchPayload(t *testing.T) {
	// Build: ident=0x0200, size=2, keys=[5,20], targets=[0x100, 0x200]
	data := make([]byte, 20)
	binary.LittleEndian.PutUint16(data[0:2], 0x0200) // ident
	binary.LittleEndian.PutUint16(data[2:4], 2)      // size
	binary.LittleEndian.PutUint32(data[4:8], 5)      // key[0]
	binary.LittleEndian.PutUint32(data[8:12], 20)    // key[1]
	binary.LittleEndian.PutUint32(data[12:16], 0x100) // target[0]
	binary.LittleEndian.PutUint32(data[16:20], 0x200) // target[1]

	payload, err := ParseSparseSwitchPayload(data, 0)
	if err != nil {
		t.Fatalf("ParseSparseSwitchPayload failed: %v", err)
	}

	if payload.Size != 2 {
		t.Errorf("Size = %d, want 2", payload.Size)
	}

	target, ok := payload.GetTargetForKey(20)
	if !ok || target != 0x200 {
		t.Errorf("GetTargetForKey(20) = %v, %v; want 0x200, true", target, ok)
	}

	target, ok = payload.GetTargetForKey(99)
	if ok {
		t.Errorf("GetTargetForKey(99) should return false")
	}
}

func TestPayloadErrors(t *testing.T) {
	// Too short
	_, err := ParseFillArrayDataPayload([]byte{0x00, 0x00}, 0)
	if err == nil {
		t.Error("Expected error for too short data")
	}

	// Wrong ident
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 0xFFFF)
	_, err = ParseFillArrayDataPayload(data, 0)
	if err == nil {
		t.Error("Expected error for wrong ident")
	}

	_, err = ParsePackedSwitchPayload(data, 0)
	if err == nil {
		t.Error("Expected error for wrong ident")
	}

	_, err = ParseSparseSwitchPayload(data, 0)
	if err == nil {
		t.Error("Expected error for wrong ident")
	}
}

func TestDetermineNextReturn(t *testing.T) {
	code := &DalvikCode{
		Insns: []uint16{0x000E}, // return-void
	}

	insn := Instruction{
		Opcode: Opcodes[0x0E],
		Offset: 0,
	}

	nexts := DetermineNext(insn, 0, code)
	if len(nexts) != 1 || nexts[0] != -1 {
		t.Errorf("return-void should return [-1], got %v", nexts)
	}
}

func TestDetermineNextGoto(t *testing.T) {
	insn := Instruction{
		Opcode: Opcodes[0x28], // goto
		Offset: 0,
		Operands: []OperandValue{
			{Type: OpBranch, Value: 10}, // offset of 10 * 2 = 20 bytes
		},
	}

	nexts := DetermineNext(insn, 0, nil)
	if len(nexts) != 1 || nexts[0] != 20 {
		t.Errorf("goto should return [20], got %v", nexts)
	}
}

func TestDetermineNextIf(t *testing.T) {
	insn := Instruction{
		Opcode: Opcodes[0x32], // if-eq
		Offset: 0,
		Operands: []OperandValue{
			{Type: OpRegister, Value: 0},
			{Type: OpRegister, Value: 1},
			{Type: OpBranch, Value: 10}, // offset of 10 * 2 = 20 bytes
		},
	}

	nexts := DetermineNext(insn, 0, nil)
	if len(nexts) != 2 {
		t.Fatalf("if-eq should return 2 targets, got %d", len(nexts))
	}
	if nexts[0] != 4 { // fall-through (4-byte instruction)
		t.Errorf("fall-through = %d, want 4", nexts[0])
	}
	if nexts[1] != 20 { // branch target
		t.Errorf("branch target = %d, want 20", nexts[1])
	}
}

func TestGetBranchInfo(t *testing.T) {
	// Test return
	insn := Instruction{
		Opcode:   Opcodes[0x0E], // return-void
		Offset:   0,
	}
	info := GetBranchInfo(insn, 0, nil)
	if info.Type != BranchReturn {
		t.Errorf("return-void type = %d, want BranchReturn", info.Type)
	}

	// Test goto
	insn = Instruction{
		Opcode: Opcodes[0x28],
		Offset: 0,
		Operands: []OperandValue{{Type: OpBranch, Value: 5}},
	}
	info = GetBranchInfo(insn, 0, nil)
	if info.Type != BranchGoto {
		t.Errorf("goto type = %d, want BranchGoto", info.Type)
	}
	if len(info.Targets) != 1 || info.Targets[0] != 10 {
		t.Errorf("goto targets = %v, want [10]", info.Targets)
	}
}
