package analysis

import (
	"testing"

	"github.com/grassto/androguard-go/core/dex"
)

func TestBuildBasicBlocksEmpty(t *testing.T) {
	blocks := BuildBasicBlocks(nil)
	if blocks != nil {
		t.Error("Expected nil blocks for empty instructions")
	}
}

func TestBuildBasicBlocksSimple(t *testing.T) {
	insns := []dex.Instruction{
		{Opcode: dex.Opcode{Name: "const/4", Format: dex.Format11n}, Offset: 0},
		{Opcode: dex.Opcode{Name: "return-void", Format: dex.Format10x, Flags: dex.FlagCanReturn}, Offset: 2},
	}

	blocks := BuildBasicBlocks(insns)
	if len(blocks) != 1 {
		t.Errorf("Expected 1 block, got %d", len(blocks))
	}

	if !blocks[0].IsEntry {
		t.Error("Expected first block to be entry")
	}

	if !blocks[0].IsExit {
		t.Error("Expected single block with return to be exit")
	}
}

func TestFindClasses(t *testing.T) {
	a := &Analysis{
		classes: []*ClassAnalysis{
			{Name: "Lcom/example/Foo;"},
			{Name: "Lcom/example/Bar;"},
			{Name: "Lorg/test/Baz;"},
		},
	}

	// Test regex search
	result := a.FindClasses("com.example.*")
	if len(result) != 2 {
		t.Errorf("FindClasses(com.example.*) returned %d, want 2", len(result))
	}

	result = a.FindClasses(".*Baz.*")
	if len(result) != 1 {
		t.Errorf("FindClasses(.*Baz.*) returned %d, want 1", len(result))
	}
}

func TestFindMethods(t *testing.T) {
	a := &Analysis{
		methods: []*MethodAnalysis{
			{ClassName: "LFoo;", Name: "onCreate"},
			{ClassName: "LFoo;", Name: "onResume"},
			{ClassName: "LBar;", Name: "onClick"},
		},
	}

	result := a.FindMethods("onCreate")
	if len(result) != 1 {
		t.Errorf("FindMethods(onCreate) returned %d, want 1", len(result))
	}

	result = a.FindMethods("^onResume$")
	if len(result) != 1 {
		t.Errorf("FindMethods(^onResume$) returned %d, want 1", len(result))
	}
}

func TestFindStrings(t *testing.T) {
	a := &Analysis{
		strings: []*StringAnalysis{
			{Value: "https://example.com"},
			{Value: "hello world"},
			{Value: "http://test.com"},
		},
	}

	result := a.FindStrings("https?://.*")
	if len(result) != 2 {
		t.Errorf("FindStrings(https?://.*) returned %d, want 2", len(result))
	}
}

func TestFindFields(t *testing.T) {
	a := &Analysis{
		fields: []*FieldAnalysis{
			{ClassName: "LFoo;", Name: "mCount"},
			{ClassName: "LFoo;", Name: "mName"},
			{ClassName: "LBar;", Name: "mValue"},
		},
	}

	result := a.FindFields("mC.*")
	if len(result) != 1 {
		t.Errorf("FindFields(mC.*) returned %d, want 1", len(result))
	}
}

func TestGetCallGraph(t *testing.T) {
	a := &Analysis{
		methods: []*MethodAnalysis{
			{ClassName: "LFoo;", Name: "main", MethodRefs: []string{"LBar;->run", "LBaz;->process"}},
			{ClassName: "LBar;", Name: "run", MethodRefs: []string{"LBaz;->helper"}},
			{ClassName: "LBaz;", Name: "process", MethodRefs: []string{}},
			{ClassName: "LBaz;", Name: "helper", MethodRefs: []string{}},
		},
	}

	graph := a.GetCallGraph()
	if len(graph["LFoo;->main"]) != 2 {
		t.Errorf("Expected main to call 2 methods, got %d", len(graph["LFoo;->main"]))
	}
}

func TestGetAndroidAPIUsage(t *testing.T) {
	a := &Analysis{
		methods: []*MethodAnalysis{
			{ClassName: "LFoo;", Name: "init", MethodRefs: []string{
				"Landroid/app/Activity;->onCreate",
				"Landroid/os/Bundle;->get",
				"Lcom/example/Foo;->internal",
			}},
		},
	}

	apis := a.GetAndroidAPIUsage()
	if len(apis) != 2 {
		t.Errorf("Expected 2 Android APIs, got %d", len(apis))
	}
}

func TestGetMethodsByAccessFlags(t *testing.T) {
	a := &Analysis{
		methods: []*MethodAnalysis{
			{Name: "pub", AccessFlags: dex.AccPublic},
			{Name: "priv", AccessFlags: dex.AccPrivate},
			{Name: "pubStatic", AccessFlags: dex.AccPublic | dex.AccStatic},
		},
	}

	public := a.GetMethodsByAccessFlags(dex.AccPublic)
	if len(public) != 2 {
		t.Errorf("Expected 2 public methods, got %d", len(public))
	}

	static := a.GetMethodsByAccessFlags(dex.AccStatic)
	if len(static) != 1 {
		t.Errorf("Expected 1 static method, got %d", len(static))
	}
}

func TestGetClassesByAccessFlags(t *testing.T) {
	a := &Analysis{
		classes: []*ClassAnalysis{
			{Name: "pub", AccessFlags: dex.AccPublic},
			{Name: "iface", AccessFlags: dex.AccPublic | dex.AccInterface},
			{Name: "priv", AccessFlags: dex.AccPrivate},
		},
	}

	public := a.GetClassesByAccessFlags(dex.AccPublic)
	if len(public) != 2 {
		t.Errorf("Expected 2 public classes, got %d", len(public))
	}

	ifaces := a.GetClassesByAccessFlags(dex.AccInterface)
	if len(ifaces) != 1 {
		t.Errorf("Expected 1 interface, got %d", len(ifaces))
	}
}
