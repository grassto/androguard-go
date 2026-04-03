// Package dex provides type definitions and constants for DEX file parsing.
// Reference: https://source.android.com/devices/tech/dalvik/dex-format
package dex

// Kind identifies the type of argument in a Dalvik instruction.
type Kind int

const (
	KindMETH      Kind = iota // Method reference
	KindSTRING                // String index
	KindFIELD                 // Field reference
	KindTYPE                  // Type reference
	KindVARIES                // Varies
	KindINLINE_METHOD         // Inline method
	KindVTABLE_OFFSET         // Vtable offset
	KindFIELD_OFFSET          // Field offset
	KindRAW_STRING            // Raw string
	KindPROTO                 // Prototype reference (DEX 038+)
	KindMETH_PROTO            // Method + proto reference (invoke-polymorphic)
	KindCALL_SITE             // Call site item (DEX 038+)
)

// String returns the string representation of a Kind.
func (k Kind) String() string {
	switch k {
	case KindMETH:
		return "method"
	case KindSTRING:
		return "string"
	case KindFIELD:
		return "field"
	case KindTYPE:
		return "type"
	case KindPROTO:
		return "proto"
	case KindMETH_PROTO:
		return "method+proto"
	case KindCALL_SITE:
		return "call_site"
	case KindVARIES:
		return "varies"
	case KindINLINE_METHOD:
		return "inline_method"
	case KindVTABLE_OFFSET:
		return "vtable_offset"
	case KindFIELD_OFFSET:
		return "field_offset"
	case KindRAW_STRING:
		return "raw_string"
	default:
		return "unknown"
	}
}

// Operand identifies the operand type of opcodes.
type Operand int

const (
	OperandRegister Operand = iota // Register operand
	OperandLiteral                 // Literal value operand
	OperandRaw                     // Raw operand
	OperandOffset                  // Branch offset operand
	OperandKind                    // Kind reference operand (combined with Kind enum)
)

// TypeMapItem identifies different types of map items in DEX.
const (
	MapHeaderItem              = 0x0000
	MapStringIDItem            = 0x0001
	MapTypeIDItem              = 0x0002
	MapProtoIDItem             = 0x0003
	MapFieldIDItem             = 0x0004
	MapMethodIDItem            = 0x0005
	MapClassDefItem            = 0x0006
	MapCallSiteItem            = 0x0007 // New in DEX 038
	MapMethodHandleItem        = 0x0008 // New in DEX 038
	MapMapList                 = 0x1000
	MapTypeList                = 0x1001
	MapAnnotationSetRefList    = 0x1002
	MapAnnotationSetItem       = 0x1003
	MapClassDataItem           = 0x2000
	MapCodeItem                = 0x2001
	MapStringDataItem          = 0x2002
	MapDebugInfoItem           = 0x2003
	MapAnnotationItem          = 0x2004
	MapEncodedArrayItem        = 0x2005
	MapAnnotationsDirectoryItem = 0x2006
	MapHiddenapiClassDataItem  = 0xF000
)

// TypeMapItemName returns the name of a map item type.
func TypeMapItemName(t uint16) string {
	names := map[uint16]string{
		MapHeaderItem:               "header_item",
		MapStringIDItem:             "string_id_item",
		MapTypeIDItem:               "type_id_item",
		MapProtoIDItem:              "proto_id_item",
		MapFieldIDItem:              "field_id_item",
		MapMethodIDItem:             "method_id_item",
		MapClassDefItem:             "class_def_item",
		MapCallSiteItem:             "call_site_item",
		MapMethodHandleItem:         "method_handle_item",
		MapMapList:                  "map_list",
		MapTypeList:                 "type_list",
		MapAnnotationSetRefList:     "annotation_set_ref_list",
		MapAnnotationSetItem:        "annotation_set_item",
		MapClassDataItem:            "class_data_item",
		MapCodeItem:                 "code_item",
		MapStringDataItem:           "string_data_item",
		MapDebugInfoItem:            "debug_info_item",
		MapAnnotationItem:           "annotation_item",
		MapEncodedArrayItem:         "encoded_array_item",
		MapAnnotationsDirectoryItem: "annotations_directory_item",
		MapHiddenapiClassDataItem:   "hiddenapi_class_data_item",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "unknown"
}

// Type descriptor mapping
var TypeDescriptor = map[string]string{
	"V": "void",
	"Z": "boolean",
	"B": "byte",
	"S": "short",
	"C": "char",
	"I": "int",
	"J": "long",
	"F": "float",
	"D": "double",
}

// GetTypeName converts a DEX type descriptor to a human-readable name.
func GetTypeName(descriptor string) string {
	if name, ok := TypeDescriptor[descriptor]; ok {
		return name
	}
	if len(descriptor) > 0 {
		switch descriptor[0] {
		case 'L':
			// Object type: Lcom/example/Foo; -> com.example.Foo
			if len(descriptor) > 2 {
				name := descriptor[1 : len(descriptor)-1]
				return replaceRune(name, '/', '.')
			}
		case '[':
			// Array type: [I -> int[]
			return GetTypeName(descriptor[1:]) + "[]"
		}
	}
	return descriptor
}

func replaceRune(s string, old, new rune) string {
	result := make([]rune, 0, len(s))
	for _, r := range s {
		if r == old {
			result = append(result, new)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}
