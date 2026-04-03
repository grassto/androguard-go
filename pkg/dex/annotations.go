// Package dex provides annotation parsing for DEX files.
// Annotations provide metadata about classes, methods, fields, and parameters.
package dex

import (
	"fmt"

	"github.com/goandroguard/goandroguard/internal/leb128"
)

// Annotation visibility constants
const (
	VisibilityBuild    = 0x00 // Visible at build time only
	VisibilityRuntime  = 0x01 // Visible at runtime
	VisibilitySystem   = 0x02 // Visible at runtime but only to underlying system
)

// VisibilityName returns the name of an annotation visibility.
func VisibilityName(visibility byte) string {
	switch visibility {
	case VisibilityBuild:
		return "build"
	case VisibilityRuntime:
		return "runtime"
	case VisibilitySystem:
		return "system"
	default:
		return "unknown"
	}
}

// Annotation represents a parsed annotation.
type Annotation struct {
	Visibility byte
	Type       string // Type descriptor
	Elements   []AnnotationElement
}

// AnnotationElement represents a key-value pair in an annotation.
type AnnotationElement struct {
	Name  string
	Value AnnotationValue
}

// AnnotationValue holds the value of an annotation element.
type AnnotationValue struct {
	ValueType byte
	Value     interface{}
}

// AnnotationSet holds a set of annotations for a single item.
type AnnotationSet struct {
	Entries []Annotation
}

// AnnotationsDirectory holds all annotations for a class.
type AnnotationsDirectory struct {
	ClassAnnotations    AnnotationSet
	FieldAnnotations    []FieldAnnotationSet
	MethodAnnotations   []MethodAnnotationSet
	ParameterAnnotations []ParameterAnnotationSet
}

// FieldAnnotationSet holds annotations for a field.
type FieldAnnotationSet struct {
	FieldIdx uint32
	Annotations AnnotationSet
}

// MethodAnnotationSet holds annotations for a method.
type MethodAnnotationSet struct {
	MethodIdx uint32
	Annotations AnnotationSet
}

// ParameterAnnotationSet holds annotations for method parameters.
type ParameterAnnotationSet struct {
	MethodIdx uint32
	ParameterAnnotations []AnnotationSet // One set per parameter
}

// ParseAnnotationSetRef parses an annotation_set_ref_item.
func (d *DexFile) ParseAnnotationSetRef(offset uint32) (*AnnotationSet, error) {
	if offset+4 > uint32(len(d.raw)) {
		return nil, fmt.Errorf("annotation set ref out of bounds")
	}

	off := offset
	size := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	set := &AnnotationSet{}
	for i := uint32(0); i < size; i++ {
		if off+4 > uint32(len(d.raw)) {
			break
		}
		annotationOff := leb128.ReadUint32(d.raw[off : off+4])
		off += 4

		ann, err := d.parseAnnotationItem(annotationOff)
		if err == nil {
			set.Entries = append(set.Entries, *ann)
		}
	}

	return set, nil
}

// ParseAnnotationSet parses an annotation_set_item.
func (d *DexFile) ParseAnnotationSet(offset uint32) (*AnnotationSet, error) {
	if offset+4 > uint32(len(d.raw)) {
		return nil, fmt.Errorf("annotation set out of bounds")
	}

	off := offset
	size := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	set := &AnnotationSet{}
	for i := uint32(0); i < size; i++ {
		if off+4 > uint32(len(d.raw)) {
			break
		}
		annotationOff := leb128.ReadUint32(d.raw[off : off+4])
		off += 4

		ann, err := d.parseAnnotationItem(annotationOff)
		if err == nil {
			set.Entries = append(set.Entries, *ann)
		}
	}

	return set, nil
}

func (d *DexFile) parseAnnotationItem(offset uint32) (*Annotation, error) {
	if offset+1 > uint32(len(d.raw)) {
		return nil, fmt.Errorf("annotation item out of bounds")
	}

	off := offset
	visibility := d.raw[off]
	off++

	ann := &Annotation{Visibility: visibility}

	// Parse encoded_annotation
	encodedAnn, err := d.parseEncodedAnnotation(off)
	if err != nil {
		return ann, nil
	}
	ann.Type = encodedAnn.Type
	ann.Elements = encodedAnn.Elements

	return ann, nil
}

type encodedAnnotation struct {
	Type     string
	Elements []AnnotationElement
}

func (d *DexFile) parseEncodedAnnotation(offset uint32) (*encodedAnnotation, error) {
	if offset >= uint32(len(d.raw)) {
		return nil, fmt.Errorf("encoded annotation out of bounds")
	}

	off := offset

	// type_idx (uleb128)
	typeIdx, n := leb128.ReadULEB128(d.raw[off:])
	off += uint32(n)

	ann := &encodedAnnotation{}
	if int(typeIdx) < len(d.TypeIDs) {
		ann.Type = d.GetTypeName(uint32(typeIdx))
	}

	// size (uleb128)
	size, n := leb128.ReadULEB128(d.raw[off:])
	off += uint32(n)

	for i := uint64(0); i < size; i++ {
		if off >= uint32(len(d.raw)) {
			break
		}

		// name_idx (uleb128)
		nameIdx, n1 := leb128.ReadULEB128(d.raw[off:])
		off += uint32(n1)

		// value (encoded_value)
		value, n2 := d.parseEncodedValue(off)
		off += uint32(n2)

		elem := AnnotationElement{
			Value: value,
		}
		if int(nameIdx) < len(d.StringData) {
			elem.Name = d.GetString(uint32(nameIdx))
		}

		ann.Elements = append(ann.Elements, elem)
	}

	return ann, nil
}

func (d *DexFile) parseEncodedValue(offset uint32) (AnnotationValue, int) {
	if offset+1 > uint32(len(d.raw)) {
		return AnnotationValue{}, 0
	}

	off := offset
	header := d.raw[off]
	off++

	valueType := header & 0x1F
	valueArg := (header >> 5) & 0x07

	value := AnnotationValue{ValueType: valueType}

	// Number of bytes to read
	size := int(valueArg) + 1

	switch valueType {
	case 0x00: // VALUE_BYTE
		if off < uint32(len(d.raw)) {
			value.Value = int8(d.raw[off])
		}
		return value, 2

	case 0x02: // VALUE_SHORT
		val := d.readSignedValue(off, size)
		value.Value = val
		return value, 1 + size

	case 0x03: // VALUE_CHAR
		val := d.readUnsignedValue(off, size)
		value.Value = rune(val)
		return value, 1 + size

	case 0x04: // VALUE_INT
		val := d.readSignedValue(off, size)
		value.Value = int32(val)
		return value, 1 + size

	case 0x06: // VALUE_LONG
		val := d.readSignedValue(off, size)
		value.Value = val
		return value, 1 + size

	case 0x10: // VALUE_FLOAT
		val := d.readUnsignedValue(off, size)
		// Convert to float (simplified)
		value.Value = float32(int32(val))
		return value, 1 + size

	case 0x11: // VALUE_DOUBLE
		val := d.readUnsignedValue(off, size)
		value.Value = float64(int64(val))
		return value, 1 + size

	case 0x17: // VALUE_STRING
		val := d.readUnsignedValue(off, size)
		if int(val) < len(d.StringData) {
			value.Value = d.GetString(uint32(val))
		} else {
			value.Value = fmt.Sprintf("string@%d", val)
		}
		return value, 1 + size

	case 0x18: // VALUE_TYPE
		val := d.readUnsignedValue(off, size)
		if int(val) < len(d.TypeIDs) {
			value.Value = d.GetTypeName(uint32(val))
		} else {
			value.Value = fmt.Sprintf("type@%d", val)
		}
		return value, 1 + size

	case 0x19: // VALUE_FIELD
		val := d.readUnsignedValue(off, size)
		if int(val) < len(d.FieldIDs) {
			value.Value = d.GetFieldName(uint32(val))
		} else {
			value.Value = fmt.Sprintf("field@%d", val)
		}
		return value, 1 + size

	case 0x1A: // VALUE_METHOD
		val := d.readUnsignedValue(off, size)
		if int(val) < len(d.MethodIDs) {
			value.Value = d.GetMethodName(uint32(val))
		} else {
			value.Value = fmt.Sprintf("method@%d", val)
		}
		return value, 1 + size

	case 0x1B: // VALUE_ENUM
		val := d.readUnsignedValue(off, size)
		if int(val) < len(d.FieldIDs) {
			value.Value = d.GetFieldName(uint32(val))
		} else {
			value.Value = fmt.Sprintf("enum@%d", val)
		}
		return value, 1 + size

	case 0x1C: // VALUE_ARRAY
		// Parse encoded_array
		arr, n := d.parseEncodedArray(off)
		value.Value = arr
		return value, 1 + n

	case 0x1D: // VALUE_ANNOTATION
		ann, err := d.parseEncodedAnnotation(off)
		if err != nil {
			return value, 1
		}
		value.Value = ann
		return value, 1 + len(ann.Elements)*2 // Approximate size

	case 0x1E: // VALUE_NULL
		value.Value = nil
		return value, 1

	case 0x1F: // VALUE_BOOLEAN
		value.Value = valueArg != 0
		return value, 1
	}

	return value, 1
}

func (d *DexFile) readSignedValue(offset uint32, size int) int64 {
	if offset+uint32(size) > uint32(len(d.raw)) {
		return 0
	}

	var val int64
	for i := 0; i < size; i++ {
		val |= int64(d.raw[offset+uint32(i)]) << (uint(i) * 8)
	}

	// Sign extend
	if size < 8 {
		shift := 64 - uint(size)*8
		val = (val << shift) >> shift
	}

	return val
}

func (d *DexFile) readUnsignedValue(offset uint32, size int) uint64 {
	if offset+uint32(size) > uint32(len(d.raw)) {
		return 0
	}

	var val uint64
	for i := 0; i < size; i++ {
		val |= uint64(d.raw[offset+uint32(i)]) << (uint(i) * 8)
	}

	return val
}

func (d *DexFile) parseEncodedArray(offset uint32) ([]AnnotationValue, int) {
	if offset >= uint32(len(d.raw)) {
		return nil, 0
	}

	off := offset
	size, n := leb128.ReadULEB128(d.raw[off:])
	off += uint32(n)
	totalN := n

	var values []AnnotationValue
	for i := uint64(0); i < size; i++ {
		val, n2 := d.parseEncodedValue(off)
		off += uint32(n2)
		totalN += n2
		values = append(values, val)
	}

	return values, totalN
}

// ParseAnnotationsDirectory parses an annotations_directory_item.
func (d *DexFile) ParseAnnotationsDirectory(offset uint32) (*AnnotationsDirectory, error) {
	if offset+16 > uint32(len(d.raw)) {
		return nil, fmt.Errorf("annotations directory out of bounds")
	}

	off := offset
	dir := &AnnotationsDirectory{}

	// class_annotations_off
	classAnnOff := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	// annotations_size (fields)
	fieldsSize := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	// annotations_size (methods)
	methodsSize := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	// annotations_size (parameters)
	paramsSize := leb128.ReadUint32(d.raw[off : off+4])
	off += 4

	// Parse class annotations
	if classAnnOff > 0 {
		set, err := d.ParseAnnotationSet(classAnnOff)
		if err == nil {
			dir.ClassAnnotations = *set
		}
	}

	// Parse field annotations
	for i := uint32(0); i < fieldsSize; i++ {
		if off+8 > uint32(len(d.raw)) {
			break
		}
		fieldIdx := leb128.ReadUint32(d.raw[off : off+4])
		annOff := leb128.ReadUint32(d.raw[off+4 : off+8])
		off += 8

		fieldAnn := FieldAnnotationSet{FieldIdx: fieldIdx}
		set, err := d.ParseAnnotationSet(annOff)
		if err == nil {
			fieldAnn.Annotations = *set
		}
		dir.FieldAnnotations = append(dir.FieldAnnotations, fieldAnn)
	}

	// Parse method annotations
	for i := uint32(0); i < methodsSize; i++ {
		if off+8 > uint32(len(d.raw)) {
			break
		}
		methodIdx := leb128.ReadUint32(d.raw[off : off+4])
		annOff := leb128.ReadUint32(d.raw[off+4 : off+8])
		off += 8

		methodAnn := MethodAnnotationSet{MethodIdx: methodIdx}
		set, err := d.ParseAnnotationSet(annOff)
		if err == nil {
			methodAnn.Annotations = *set
		}
		dir.MethodAnnotations = append(dir.MethodAnnotations, methodAnn)
	}

	// Parse parameter annotations
	for i := uint32(0); i < paramsSize; i++ {
		if off+8 > uint32(len(d.raw)) {
			break
		}
		methodIdx := leb128.ReadUint32(d.raw[off : off+4])
		annRefOff := leb128.ReadUint32(d.raw[off+4 : off+8])
		off += 8

		paramAnn := ParameterAnnotationSet{MethodIdx: methodIdx}

		// Parse annotation_set_ref_list
		if annRefOff > 0 && annRefOff < uint32(len(d.raw)) {
			refOff := annRefOff
			count := leb128.ReadUint32(d.raw[refOff : refOff+4])
			refOff += 4

			for j := uint32(0); j < count; j++ {
				if refOff+4 > uint32(len(d.raw)) {
					break
				}
				setOff := leb128.ReadUint32(d.raw[refOff : refOff+4])
				refOff += 4

				set, err := d.ParseAnnotationSet(setOff)
				if err == nil {
					paramAnn.ParameterAnnotations = append(paramAnn.ParameterAnnotations, *set)
				} else {
					paramAnn.ParameterAnnotations = append(paramAnn.ParameterAnnotations, AnnotationSet{})
				}
			}
		}

		dir.ParameterAnnotations = append(dir.ParameterAnnotations, paramAnn)
	}

	return dir, nil
}

// String returns a string representation of an annotation.
func (a Annotation) String() string {
	result := fmt.Sprintf("@%s (visibility: %s)\n", a.Type, VisibilityName(a.Visibility))
	for _, elem := range a.Elements {
		result += fmt.Sprintf("  %s = %v\n", elem.Name, elem.Value)
	}
	return result
}
