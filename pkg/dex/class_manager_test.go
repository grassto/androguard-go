package dex

import (
	"testing"
)

func TestClassManagerBasic(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	// Test string access
	if cm.GetString(0) != "test" {
		t.Errorf("GetString(0) = %q, want 'test'", cm.GetString(0))
	}

	// Test string caching (call twice)
	if cm.GetString(0) != "test" {
		t.Errorf("GetString(0) cached = %q, want 'test'", cm.GetString(0))
	}
}

func TestClassManagerStringHook(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	// Before hook
	if cm.GetString(0) != "test" {
		t.Errorf("Before hook: GetString(0) = %q, want 'test'", cm.GetString(0))
	}

	// Set hook
	cm.SetHookString(0, "HOOKED")

	// After hook
	if cm.GetString(0) != "HOOKED" {
		t.Errorf("After hook: GetString(0) = %q, want 'HOOKED'", cm.GetString(0))
	}

	// Raw string should still be original
	if cm.GetRawString(0) != "test" {
		t.Errorf("GetRawString(0) = %q, want 'test'", cm.GetRawString(0))
	}

	// Remove hook
	cm.RemoveHookString(0)
	if cm.GetString(0) != "test" {
		t.Errorf("After unhook: GetString(0) = %q, want 'test'", cm.GetString(0))
	}
}

func TestClassManagerIsODEX(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	if cm.IsODEX() {
		t.Error("Regular DEX should not be ODEX")
	}
}

func TestClassManagerGetDexFile(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	if cm.GetDexFile() != dex {
		t.Error("GetDexFile should return the original DexFile")
	}
}

func TestClassManagerGetMethods(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	methods := cm.GetMethods()
	if len(methods) != len(dex.MethodIDs) {
		t.Errorf("GetMethods() returned %d, want %d", len(methods), len(dex.MethodIDs))
	}
}

func TestClassManagerGetFields(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	fields := cm.GetFields()
	if len(fields) != len(dex.FieldIDs) {
		t.Errorf("GetFields() returned %d, want %d", len(fields), len(dex.FieldIDs))
	}
}

func TestClassManagerGetTypes(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	types := cm.GetTypes()
	if len(types) != len(dex.TypeIDs) {
		t.Errorf("GetTypes() returned %d, want %d", len(types), len(dex.TypeIDs))
	}
}

func TestClassManagerGetKind(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	// Test STRING kind
	s := cm.GetKind(KindSTRING, 0)
	if s != "test" {
		t.Errorf("GetKind(STRING, 0) = %q, want 'test'", s)
	}

	// Test VTABLE_OFFSET kind
	s = cm.GetKind(KindVTABLE_OFFSET, 42)
	if s != "vtable[0x2a]" {
		t.Errorf("GetKind(VTABLE, 42) = %q, want 'vtable[0x2a]'", s)
	}

	// Test FIELD_OFFSET kind
	s = cm.GetKind(KindFIELD_OFFSET, 10)
	if s != "field[0xa]" {
		t.Errorf("GetKind(FIELD, 10) = %q, want 'field[0xa]'", s)
	}
}

func TestClassManagerInvalidateCache(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	// Fill cache
	_ = cm.GetString(0)
	_ = cm.GetType(0)

	// Invalidate
	cm.InvalidateCache()

	// Should still work
	if cm.GetString(0) != "test" {
		t.Errorf("After invalidate: GetString(0) = %q, want 'test'", cm.GetString(0))
	}
}

func TestBuildMethodDescriptor(t *testing.T) {
	tests := []struct {
		proto    ProtoInfo
		expected string
	}{
		{ProtoInfo{Parameters: nil, ReturnType: "V"}, "()V"},
		{ProtoInfo{Parameters: []string{"I"}, ReturnType: "V"}, "(I)V"},
		{ProtoInfo{Parameters: []string{"I", "Z"}, ReturnType: "I"}, "(I, Z)I"},
	}

	for _, tt := range tests {
		got := buildMethodDescriptor(tt.proto)
		if got != tt.expected {
			t.Errorf("buildMethodDescriptor(%v) = %q, want %q", tt.proto, got, tt.expected)
		}
	}
}

func TestFormatParamTypes(t *testing.T) {
	tests := []struct {
		params   []string
		expected string
	}{
		{nil, ""},
		{[]string{"I"}, "I"},
		{[]string{"I", "Z", "Ljava/lang/String;"}, "I, Z, Ljava/lang/String;"},
	}

	for _, tt := range tests {
		got := formatParamTypes(tt.params)
		if got != tt.expected {
			t.Errorf("formatParamTypes(%v) = %q, want %q", tt.params, got, tt.expected)
		}
	}
}

func TestClassManagerGetAllClassNames(t *testing.T) {
	dex := createTestDex(t)
	cm := NewClassManager(dex)

	names := cm.GetAllClassNames()
	if len(names) != len(dex.ClassDefs) {
		t.Errorf("GetAllClassNames() returned %d, want %d", len(names), len(dex.ClassDefs))
	}
}

// Helper to create a minimal test DEX
func createTestDex(t *testing.T) *DexFile {
	t.Helper()
	return &DexFile{
		StringData: []StringDataItem{{Data: "test"}},
		TypeIDs:    []TypeID{{DescriptorIdx: 0}},
		MethodIDs:  []MethodID{{ClassIdx: 0, ProtoIdx: 0, NameIdx: 0}},
		FieldIDs:   []FieldID{{ClassIdx: 0, TypeIdx: 0, NameIdx: 0}},
		ClassDefs:  []ClassDef{{ClassIdx: 0}},
		ClassData:  make(map[uint32]*ClassData),
		CodeItems:  make(map[uint32]*CodeItem),
		raw:        make([]byte, 256),
	}
}
