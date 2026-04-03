package axml

import (
	"testing"
)

func TestAXMLNodeGetAttribute(t *testing.T) {
	node := &AXMLNode{
		Name: "test",
		Attributes: []XMLAttributeNode{
			{Name: "name", Value: "TestActivity"},
			{Name: "exported", Value: "true"},
		},
	}

	if got := node.GetAttribute("name"); got != "TestActivity" {
		t.Errorf("GetAttribute(name) = %v, want TestActivity", got)
	}

	if got := node.GetAttribute("missing"); got != "" {
		t.Errorf("GetAttribute(missing) = %v, want empty", got)
	}
}

func TestAXMLNodeFindChild(t *testing.T) {
	child1 := &AXMLNode{Name: "child1"}
	child2 := &AXMLNode{Name: "child2"}
	node := &AXMLNode{
		Name:     "parent",
		Children: []*AXMLNode{child1, child2},
	}

	if got := node.FindChild("child2"); got != child2 {
		t.Error("FindChild(child2) failed")
	}

	if got := node.FindChild("missing"); got != nil {
		t.Error("FindChild(missing) should return nil")
	}
}

func TestAXMLNodeFindNodes(t *testing.T) {
	grandchild := &AXMLNode{Name: "target"}
	child := &AXMLNode{
		Name:     "child",
		Children: []*AXMLNode{grandchild},
	}
	root := &AXMLNode{
		Name:     "root",
		Children: []*AXMLNode{child},
	}

	nodes := root.FindNodes("target")
	if len(nodes) != 1 {
		t.Errorf("FindNodes(target) returned %d nodes, want 1", len(nodes))
	}
}

func TestAXMLNodeGetFullPath(t *testing.T) {
	parent := &AXMLNode{Name: "manifest"}
	child := &AXMLNode{Name: "application", Parent: parent}
	grandchild := &AXMLNode{Name: "activity", Parent: child}

	if got := grandchild.GetFullPath(); got != "/manifest/application/activity" {
		t.Errorf("GetFullPath() = %v, want /manifest/application/activity", got)
	}
}

func TestAXMLNodeCountNodes(t *testing.T) {
	grandchild := &AXMLNode{Name: "leaf"}
	child := &AXMLNode{
		Name:     "child",
		Children: []*AXMLNode{grandchild},
	}
	root := &AXMLNode{
		Name:     "root",
		Children: []*AXMLNode{child},
	}

	if got := root.CountNodes(); got != 3 {
		t.Errorf("CountNodes() = %d, want 3", got)
	}
}

func TestDetectPackedAXML(t *testing.T) {
	// Too short should not crash and not be considered packed
	if detectPackedAXML([]byte{0x00}) {
		t.Error("Expected very short data to not be packed")
	}

	// Valid AXML magic but wrong structure = not packed by this check
	data := make([]byte, 16)
	data[0] = 0x03 // ResXMLType low byte
	if detectPackedAXML(data) {
		t.Error("Expected minimal valid header to not be detected as packed")
	}
}

func TestFormatAttributeValue(t *testing.T) {
	tests := []struct {
		attr     XMLAttributeNode
		expected string
	}{
		{XMLAttributeNode{Value: "hello"}, "hello"},
		{XMLAttributeNode{ValueType: AttrTypeIntDec, ValueData: 42}, "42"},
		{XMLAttributeNode{ValueType: AttrTypeIntBoolean, ValueData: 1}, "true"},
		{XMLAttributeNode{ValueType: AttrTypeIntBoolean, ValueData: 0}, "false"},
		{XMLAttributeNode{ValueType: AttrTypeReference, ValueData: 0x7f040001}, "@0x7f040001"},
	}

	for _, tt := range tests {
		got := formatAttributeValue(tt.attr)
		if got != tt.expected {
			t.Errorf("formatAttributeValue(%v) = %v, want %v", tt.attr, got, tt.expected)
		}
	}
}
