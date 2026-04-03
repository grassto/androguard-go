// Package axml parses Android Binary XML (AXML) format used in APK files.
// Android compiles XML files into a compact binary format for efficiency.
// Reference: https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/
package axml

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/grassto/androguard-go/internal/leb128"
)

// Chunk type constants
const (
	ResNullType             = 0x0000
	ResStringPoolType       = 0x0001
	ResTableType            = 0x0002
	ResXMLType              = 0x0003
	ResXMLStartNamespace    = 0x0100
	ResXMLEndNamespace      = 0x0101
	ResXMLStartElement      = 0x0102
	ResXMLEndElement        = 0x0103
	ResXMLCDATAType         = 0x0104
	ResXMLResourceMapType   = 0x0180
	ResTablePackageType     = 0x0200
	ResTableTypeType        = 0x0201
	ResTableTypeSpecType    = 0x0202
)

// String pool flags
const (
	SortedFlag = 1 << 0
	UTF8Flag   = 1 << 8
)

// XML event types
const (
	EventStartDocument = 0
	EventEndDocument   = 1
	EventStartElement  = 2
	EventEndElement    = 3
	EventText          = 4
)

// Attribute value types
const (
	AttrTypeNull       = 0x00
	AttrTypeReference  = 0x01
	AttrTypeAttribute  = 0x02
	AttrTypeString     = 0x03
	AttrTypeFloat      = 0x04
	AttrTypeDimension  = 0x05
	AttrTypeFraction   = 0x06
	AttrTypeIntDec     = 0x10
	AttrTypeIntHex     = 0x11
	AttrTypeIntBoolean = 0x12
	AttrTypeIntColorARGB8 = 0x1C
	AttrTypeIntColorRGB8  = 0x1D
	AttrTypeIntColorARGB4 = 0x1E
	AttrTypeIntColorRGB4  = 0x1F
)

// ARSCHeader represents the common chunk header
type ARSCHeader struct {
	ChunkType uint16
	HeaderSize uint16
	ChunkSize  uint32
}

// StringPool represents a parsed string pool
type StringPool struct {
	Strings    []string
	Styles     []uint32
	IsUTF8     bool
	IsSorted   bool
}

// XMLAttribute represents an XML element attribute
type XMLAttribute struct {
	NamespaceURI uint32
	Name         uint32
	ValueString  uint32
	ValueType    uint16
	ValueData    uint32
}

// Namespace represents a namespace declaration (xmlns:xxx=yyy)
type Namespace struct {
	Prefix uint32
	URI    uint32
	Line   uint32
}

// XMLElement represents an XML element
type XMLElement struct {
	NamespaceURI uint32
	Name         uint32
	Line         uint32
	Attributes   []XMLAttribute
}

// AXMLParser is a streaming parser for Android Binary XML
type AXMLParser struct {
	data       []byte
	offset     int
	strings    *StringPool
	eventType  int
	nsStack    []Namespace
	elements   []XMLElement
	curElement *XMLElement
	docStart   bool
}

// NewAXMLParser creates a new AXML parser from byte data.
func NewAXMLParser(data []byte) *AXMLParser {
	return &AXMLParser{
		data: data,
	}
}

// Parse processes the entire AXML and returns the parsed document.
func (p *AXMLParser) Parse() (*AXMLDocument, error) {
	doc := &AXMLDocument{}

	for {
		event, err := p.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch event {
		case EventStartElement:
			elem := XMLElementNode{
				NamespaceURI: p.GetAttributeString(p.curElement.NamespaceURI),
				Name:         p.GetAttributeString(p.curElement.Name),
				Line:         p.curElement.Line,
			}
			for _, attr := range p.curElement.Attributes {
				elem.Attributes = append(elem.Attributes, XMLAttributeNode{
					NamespaceURI: p.GetAttributeString(attr.NamespaceURI),
					Name:         p.GetAttributeString(attr.Name),
					Value:        p.GetAttributeString(attr.ValueString),
					ValueType:    attr.ValueType,
					ValueData:    attr.ValueData,
				})
			}
			doc.Elements = append(doc.Elements, elem)
		}
	}

	doc.StringPool = p.strings
	return doc, nil
}

// Next advances the parser to the next event.
func (p *AXMLParser) Next() (int, error) {
	if p.offset >= len(p.data) {
		return EventEndDocument, io.EOF
	}

	// Read chunk header
	if p.offset+8 > len(p.data) {
		return EventEndDocument, io.EOF
	}

	chunkType := binary.LittleEndian.Uint16(p.data[p.offset : p.offset+2])
	headerSize := binary.LittleEndian.Uint16(p.data[p.offset+2 : p.offset+4])
	chunkSize := binary.LittleEndian.Uint32(p.data[p.offset+4 : p.offset+8])

	switch chunkType {
	case ResXMLType:
		p.offset += int(headerSize)
		return EventStartDocument, nil

	case ResStringPoolType:
		sp, err := p.parseStringPool(p.offset, int(chunkSize))
		if err != nil {
			return -1, err
		}
		p.strings = sp
		p.offset += int(chunkSize)
		return p.Next()

	case ResXMLResourceMapType:
		// Resource map - skip for now
		p.offset += int(chunkSize)
		return p.Next()

	case ResXMLStartNamespace:
		ns := Namespace{}
		if p.offset+16 <= len(p.data) {
			ns.Line = leb128.ReadUint32(p.data[p.offset+8 : p.offset+12])
			ns.Prefix = leb128.ReadUint32(p.data[p.offset+12 : p.offset+16])
			ns.URI = leb128.ReadUint32(p.data[p.offset+16 : p.offset+20])
		}
		p.nsStack = append(p.nsStack, ns)
		p.offset += int(chunkSize)
		return p.Next()

	case ResXMLEndNamespace:
		if len(p.nsStack) > 0 {
			p.nsStack = p.nsStack[:len(p.nsStack)-1]
		}
		p.offset += int(chunkSize)
		return p.Next()

	case ResXMLStartElement:
		elem := XMLElement{}
		if p.offset+24 <= len(p.data) {
			elem.Line = leb128.ReadUint32(p.data[p.offset+8 : p.offset+12])
			elem.NamespaceURI = leb128.ReadUint32(p.data[p.offset+16 : p.offset+20])
			elem.Name = leb128.ReadUint32(p.data[p.offset+20 : p.offset+24])
		}

		// Parse attributes
		// attrStart at offset 24-25, attrSize at 26-27, attrCount at 28-29
		if p.offset+30 <= len(p.data) {
			_ = int(binary.LittleEndian.Uint16(p.data[p.offset+24 : p.offset+26])) // attrStart
			attrSize := int(binary.LittleEndian.Uint16(p.data[p.offset+26 : p.offset+28]))
			attrCount := int(binary.LittleEndian.Uint16(p.data[p.offset+28 : p.offset+30]))

			// Default attribute size is 20 bytes
			if attrSize == 0 {
				attrSize = 20
			}

			attrOff := p.offset + 36 // Attributes start after the header fields
			for i := 0; i < attrCount; i++ {
				if attrOff+20 > len(p.data) {
					break
				}
				attr := XMLAttribute{
					NamespaceURI: leb128.ReadUint32(p.data[attrOff : attrOff+4]),
					Name:         leb128.ReadUint32(p.data[attrOff+4 : attrOff+8]),
					ValueString:  leb128.ReadUint32(p.data[attrOff+8 : attrOff+12]),
					ValueType:    binary.LittleEndian.Uint16(p.data[attrOff+12 : attrOff+14]),
					ValueData:    leb128.ReadUint32(p.data[attrOff+16 : attrOff+20]),
				}
				elem.Attributes = append(elem.Attributes, attr)
				attrOff += attrSize
			}
		}

		p.curElement = &elem
		p.elements = append(p.elements, elem)
		p.offset += int(chunkSize)
		return EventStartElement, nil

	case ResXMLEndElement:
		p.offset += int(chunkSize)
		return EventEndElement, nil

	case ResXMLCDATAType:
		p.offset += int(chunkSize)
		return EventText, nil

	default:
		// Unknown chunk, skip
		p.offset += int(chunkSize)
		return p.Next()
	}
}

func (p *AXMLParser) parseStringPool(offset int, chunkSize int) (*StringPool, error) {
	if offset+28 > len(p.data) {
		return nil, fmt.Errorf("axml: string pool header too short")
	}

	data := p.data[offset:]
	sp := &StringPool{}

	stringCount := leb128.ReadUint32(data[8:12])
	styleCount := leb128.ReadUint32(data[12:16])
	flags := leb128.ReadUint32(data[16:20])
	stringsOffset := leb128.ReadUint32(data[20:24])
	stylesOffset := leb128.ReadUint32(data[24:28])

	sp.IsUTF8 = (flags & UTF8Flag) != 0
	sp.IsSorted = (flags & SortedFlag) != 0

	// Read string offsets
	stringOffsets := make([]uint32, stringCount)
	for i := uint32(0); i < stringCount; i++ {
		off := 28 + i*4
		if int(off)+4 > len(data) {
			break
		}
		stringOffsets[i] = leb128.ReadUint32(data[off : off+4])
	}

	// Read style offsets
	styleOffsets := make([]uint32, styleCount)
	for i := uint32(0); i < styleCount; i++ {
		off := 28 + stringCount*4 + i*4
		if int(off)+4 > len(data) {
			break
		}
		styleOffsets[i] = leb128.ReadUint32(data[off : off+4])
	}

	// Calculate the start of string data
	stringDataStart := int(stringsOffset)

	// Read strings
	sp.Strings = make([]string, stringCount)
	for i := uint32(0); i < stringCount; i++ {
		strOff := stringDataStart + int(stringOffsets[i])
		if strOff >= len(data) {
			continue
		}

		if sp.IsUTF8 {
			sp.Strings[i] = p.decodeUTF8(data, strOff)
		} else {
			sp.Strings[i] = p.decodeUTF16(data, strOff)
		}
	}

	_ = stylesOffset // may be unused if no styles

	return sp, nil
}

func (p *AXMLParser) decodeUTF8(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}

	// Skip length fields
	_, n1 := leb128.ReadULEB128(data[offset:])
	offset += n1
	strLen, n2 := leb128.ReadULEB128(data[offset:])
	offset += n2

	if offset+int(strLen) > len(data) {
		return ""
	}

	// Find null terminator
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

func (p *AXMLParser) decodeUTF16(data []byte, offset int) string {
	if offset+2 > len(data) {
		return ""
	}

	// For UTF-16 strings, length is stored as uint16 (not ULEB128)
	strLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip null terminator (2 bytes) if present
	// Total bytes needed: strLen * 2
	if offset+strLen*2 > len(data) {
		return ""
	}

	runes := make([]rune, 0, strLen)
	for i := 0; i < strLen; i++ {
		ch := binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		if ch == 0 {
			break
		}
		runes = append(runes, rune(ch))
	}

	return string(runes)
}

// GetAttributeString returns the string at the given index from the string pool.
func (p *AXMLParser) GetAttributeString(idx uint32) string {
	if p.strings == nil || int(idx) >= len(p.strings.Strings) {
		return ""
	}
	return p.strings.Strings[idx]
}

// GetAttributeValueType returns a human-readable string for an attribute value type.
func GetAttributeValueType(vt uint16) string {
	switch vt {
	case AttrTypeNull:
		return "null"
	case AttrTypeReference:
		return "reference"
	case AttrTypeAttribute:
		return "attribute"
	case AttrTypeString:
		return "string"
	case AttrTypeFloat:
		return "float"
	case AttrTypeDimension:
		return "dimension"
	case AttrTypeFraction:
		return "fraction"
	case AttrTypeIntDec:
		return "int_dec"
	case AttrTypeIntHex:
		return "int_hex"
	case AttrTypeIntBoolean:
		return "boolean"
	case AttrTypeIntColorARGB8:
		return "color_argb8"
	case AttrTypeIntColorRGB8:
		return "color_rgb8"
	case AttrTypeIntColorARGB4:
		return "color_argb4"
	case AttrTypeIntColorRGB4:
		return "color_rgb4"
	default:
		return fmt.Sprintf("unknown(0x%x)", vt)
	}
}

// AXMLDocument represents a fully parsed Android Binary XML document.
type AXMLDocument struct {
	StringPool *StringPool
	Elements   []XMLElementNode
}

// XMLElementNode represents a parsed XML element with resolved strings.
type XMLElementNode struct {
	NamespaceURI string
	Name         string
	Line         uint32
	Attributes   []XMLAttributeNode
}

// XMLAttributeNode represents a parsed XML attribute with resolved strings.
type XMLAttributeNode struct {
	NamespaceURI string
	Name         string
	Value        string
	ValueType    uint16
	ValueData    uint32
}

// GetXMLString returns a simplified XML string representation.
func (doc *AXMLDocument) GetXMLString() string {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")

	for _, elem := range doc.Elements {
		nsURI := elem.NamespaceURI
		name := elem.Name

		if nsURI != "" {
			sb.WriteString(fmt.Sprintf("<%s xmlns:android=\"%s\"", name, nsURI))
		} else {
			sb.WriteString(fmt.Sprintf("<%s", name))
		}

		for _, attr := range elem.Attributes {
			attrName := attr.Name
			if attr.NamespaceURI != "" {
				attrName = "android:" + attrName
			}

			if attr.Value != "" {
				sb.WriteString(fmt.Sprintf("\n    %s=\"%s\"", attrName, attr.Value))
			} else {
				switch attr.ValueType {
				case AttrTypeIntDec:
					sb.WriteString(fmt.Sprintf("\n    %s=\"%d\"", attrName, int32(attr.ValueData)))
				case AttrTypeIntHex:
					sb.WriteString(fmt.Sprintf("\n    %s=\"0x%x\"", attrName, attr.ValueData))
				case AttrTypeIntBoolean:
					if attr.ValueData != 0 {
						sb.WriteString(fmt.Sprintf("\n    %s=\"true\"", attrName))
					} else {
						sb.WriteString(fmt.Sprintf("\n    %s=\"false\"", attrName))
					}
				case AttrTypeReference:
					sb.WriteString(fmt.Sprintf("\n    %s=\"@0x%x\"", attrName, attr.ValueData))
				default:
					sb.WriteString(fmt.Sprintf("\n    %s=\"0x%x\"", attrName, attr.ValueData))
				}
			}
		}
		sb.WriteString(" />\n")
	}

	return sb.String()
}

// ParseAXML is a convenience function to parse AXML data.
func ParseAXML(data []byte) (*AXMLDocument, error) {
	parser := NewAXMLParser(data)
	return parser.Parse()
}
