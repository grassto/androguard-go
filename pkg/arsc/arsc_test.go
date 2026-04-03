package arsc

import (
	"testing"
)

func TestGetResourceValueString(t *testing.T) {
	tests := []struct {
		val      *ResourceValue
		pool     []string
		expected string
	}{
		{nil, nil, ""},
		{&ResourceValue{DataType: 0x03, Data: 0}, []string{"app_name"}, "app_name"},
		{&ResourceValue{DataType: 0x10, Data: 42}, nil, "42"},
		{&ResourceValue{DataType: 0x11, Data: 0xFF}, nil, "0xff"},
		{&ResourceValue{DataType: 0x12, Data: 1}, nil, "true"},
		{&ResourceValue{DataType: 0x12, Data: 0}, nil, "false"},
		{&ResourceValue{DataType: 0x01, Data: 0x7F040001}, nil, "@0x7f040001"},
	}

	for _, tt := range tests {
		result := GetResourceValueString(tt.val, tt.pool)
		if result != tt.expected {
			t.Errorf("GetResourceValueString(%+v) = %q, want %q", tt.val, result, tt.expected)
		}
	}
}
