package axml

import (
	"testing"
)

func TestGetAttributeValueType(t *testing.T) {
	tests := []struct {
		vt       uint16
		expected string
	}{
		{AttrTypeNull, "null"},
		{AttrTypeReference, "reference"},
		{AttrTypeString, "string"},
		{AttrTypeIntDec, "int_dec"},
		{AttrTypeIntHex, "int_hex"},
		{AttrTypeIntBoolean, "boolean"},
	}

	for _, tt := range tests {
		result := GetAttributeValueType(tt.vt)
		if result != tt.expected {
			t.Errorf("GetAttributeValueType(%d) = %q, want %q", tt.vt, result, tt.expected)
		}
	}
}

func TestAXMLDocument(t *testing.T) {
	doc := &AXMLDocument{
		Elements: []XMLElementNode{
			{
				Name: "manifest",
				Attributes: []XMLAttributeNode{
					{Name: "package", Value: "com.example.test"},
					{Name: "versionCode", Value: "1", ValueType: AttrTypeIntDec, ValueData: 1},
				},
			},
		},
	}

	xml := doc.GetXMLString()
	if xml == "" {
		t.Error("GetXMLString returned empty string")
	}
	t.Logf("Generated XML:\n%s", xml)
}
