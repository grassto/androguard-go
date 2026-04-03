package axml

import (
	"encoding/binary"
	"strings"
)

// --- Missing methods from Python androguard AXMLParser ---

// IsValid returns true if the parser is in a valid state.
func (p *AXMLParser) IsValid() bool {
	return p.strings != nil && len(p.data) > 0
}

// GetCurrentName returns the name of the current element.
func (p *AXMLParser) GetCurrentName() string {
	if p.curElement == nil {
		return ""
	}
	return p.GetAttributeString(p.curElement.Name)
}

// GetCurrentNamespace returns the namespace URI of the current element.
func (p *AXMLParser) GetCurrentNamespace() string {
	if p.curElement == nil {
		return ""
	}
	return p.GetAttributeString(p.curElement.NamespaceURI)
}

// GetCurrentLine returns the line number of the current element.
func (p *AXMLParser) GetCurrentLine() uint32 {
	if p.curElement == nil {
		return 0
	}
	return p.curElement.Line
}

// GetNamespaceMap returns the current namespace prefix -> URI mapping.
func (p *AXMLParser) GetNamespaceMap() map[string]string {
	result := make(map[string]string)
	for _, ns := range p.nsStack {
		prefix := p.GetAttributeString(ns.Prefix)
		uri := p.GetAttributeString(ns.URI)
		if prefix != "" && uri != "" {
			result[prefix] = uri
		}
	}
	return result
}

// GetAttributeCount returns the number of attributes on the current element.
func (p *AXMLParser) GetAttributeCount() int {
	if p.curElement == nil {
		return 0
	}
	return len(p.curElement.Attributes)
}

// GetAttributeName returns the attribute name at the given index.
func (p *AXMLParser) GetAttributeName(index int) string {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return ""
	}
	return p.GetAttributeString(p.curElement.Attributes[index].Name)
}

// GetAttributeNamespace returns the attribute namespace at the given index.
func (p *AXMLParser) GetAttributeNamespace(index int) string {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return ""
	}
	return p.GetAttributeString(p.curElement.Attributes[index].NamespaceURI)
}

// GetAttributeValue returns the string value of the attribute at the given index.
func (p *AXMLParser) GetAttributeValue(index int) string {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return ""
	}

	attr := p.curElement.Attributes[index]

	// If there's a string value, return it
	if attr.ValueString != 0xFFFFFFFF {
		s := p.GetAttributeString(attr.ValueString)
		if s != "" {
			return s
		}
	}

	// Otherwise format based on type
	return FormatAttributeValue(attr.ValueType, attr.ValueData, func(idx uint32) string {
		return p.GetAttributeString(idx)
	})
}

// GetAttributeValueType returns the value type of the attribute at the given index.
func (p *AXMLParser) GetAttributeValueType(index int) uint16 {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return 0
	}
	return p.curElement.Attributes[index].ValueType
}

// GetAttributeValueData returns the raw data of the attribute at the given index.
func (p *AXMLParser) GetAttributeValueData(index int) uint32 {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return 0
	}
	return p.curElement.Attributes[index].ValueData
}

// GetAttributeURI returns the namespace URI of the attribute at the given index.
func (p *AXMLParser) GetAttributeURI(index int) int {
	if p.curElement == nil || index < 0 || index >= len(p.curElement.Attributes) {
		return -1
	}
	return int(p.curElement.Attributes[index].NamespaceURI)
}

// GetCurrentText returns text content if current event is text.
func (p *AXMLParser) GetCurrentText() string {
	// Text is stored as CDATA
	if p.eventType == EventText && p.curElement != nil {
		return p.GetAttributeString(p.curElement.Name)
	}
	return ""
}

// FormatAttributeValue formats an attribute value based on its type.
func FormatAttributeValue(valueType uint16, valueData uint32, stringGetter func(uint32) string) string {
	switch valueType {
	case AttrTypeNull:
		return ""
	case AttrTypeReference:
		return "@" + formatHex(valueData)
	case AttrTypeAttribute:
		return "?" + formatHex(valueData)
	case AttrTypeString:
		return stringGetter(valueData)
	case AttrTypeFloat:
		return formatFloat(valueData)
	case AttrTypeDimension:
		return formatDimensionValue(valueData)
	case AttrTypeFraction:
		return formatFractionValue(valueData)
	case AttrTypeIntDec:
		return formatIntDec(int32(valueData))
	case AttrTypeIntHex:
		return "0x" + formatHex(valueData)
	case AttrTypeIntBoolean:
		if valueData != 0 {
			return "true"
		}
		return "false"
	case AttrTypeIntColorARGB8:
		return "#" + formatHex8(valueData)
	case AttrTypeIntColorRGB8:
		return "#" + formatHex6(valueData)
	case AttrTypeIntColorARGB4:
		return "#" + formatHex4(valueData)
	case AttrTypeIntColorRGB4:
		return "#" + formatHex3(valueData)
	default:
		return formatIntDec(int32(valueData))
	}
}

func formatHex(v uint32) string {
	// Simple hex formatting
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		digit := v & 0xF
		if digit < 10 {
			buf[i] = byte('0' + digit)
		} else {
			buf[i] = byte('a' + digit - 10)
		}
		v >>= 4
	}
	// Skip leading zeros
	start := 0
	for start < 7 && buf[start] == '0' {
		start++
	}
	return string(buf[start:])
}

func formatHex8(v uint32) string {
	return formatHex(v)
}

func formatHex6(v uint32) string {
	return formatHex(v & 0xFFFFFF)
}

func formatHex4(v uint32) string {
	return formatHex(v & 0xFFFF)
}

func formatHex3(v uint32) string {
	return formatHex(v & 0xFFF)
}

func formatFloat(bits uint32) string {
	f := float64(int32(bits))
	return formatFloatValue(f)
}

func formatFloatValue(f float64) string {
	// Simple float to string
	if f == float64(int64(f)) {
		return formatIntDec(int32(f))
	}
	buf := make([]byte, 0, 32)
	// Very simplified
	buf = append(buf, formatIntDec(int32(f))...)
	buf = append(buf, '.')

	frac := f - float64(int64(f))
	if frac < 0 {
		frac = -frac
	}
	for i := 0; i < 6; i++ {
		frac *= 10
		digit := int(frac)
		buf = append(buf, byte('0'+digit))
		frac -= float64(digit)
	}
	return string(buf)
}

func formatIntDec(v int32) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	buf := make([]byte, 0, 12)
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	if negative {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func formatDimensionValue(data uint32) string {
	value := float32(int32(data>>8)) / 256.0
	unit := data & 0x0F

	units := []string{"px", "dp", "sp", "pt", "in", "mm"}
	unitStr := "px"
	if int(unit) < len(units) {
		unitStr = units[unit]
	}

	return formatFloat32(value) + unitStr
}

func formatFractionValue(data uint32) string {
	value := float32(int32(data>>8)) / 256.0 * 100.0
	p := data & 0x0F

	s := formatFloat32(value)
	if p == 0 {
		return s + "%"
	}
	return s + "%p"
}

func formatFloat32(f float32) string {
	return formatFloatValue(float64(f))
}

// --- Missing AXMLPrinter methods ---

// GetBuff returns the raw XML bytes (without pretty printing).
func (p *AXMLPrinter) GetBuff() string {
	return p.GetXML(false)
}

// GetXMLBytes returns the XML as UTF-8 bytes.
func (p *AXMLPrinter) GetXMLBytes() []byte {
	return []byte(p.GetXML(true))
}

// --- StringPool helper methods ---

// GetString returns a string from the string pool by index.
func (sp *StringPool) GetString(idx int) string {
	if sp == nil || idx < 0 || idx >= len(sp.Strings) {
		return ""
	}
	return sp.Strings[idx]
}

// GetStyle returns a style index from the string pool.
func (sp *StringPool) GetStyle(idx int) uint32 {
	if sp == nil || idx < 0 || idx >= len(sp.Styles) {
		return 0
	}
	return sp.Styles[idx]
}

// Len returns the number of strings in the pool.
func (sp *StringPool) Len() int {
	if sp == nil {
		return 0
	}
	return len(sp.Strings)
}

// --- AXMLDocument enhancements ---

// GetElementsByTagName returns all elements with the given tag name.
func (doc *AXMLDocument) GetElementsByTagName(name string) []XMLElementNode {
	var result []XMLElementNode
	for _, elem := range doc.Elements {
		if elem.Name == name {
			result = append(result, elem)
		}
	}
	return result
}

// GetElementByAttribute returns elements matching an attribute name/value.
func (doc *AXMLDocument) GetElementByAttribute(attrName, attrValue string) []XMLElementNode {
	var result []XMLElementNode
	for _, elem := range doc.Elements {
		for _, attr := range elem.Attributes {
			if attr.Name == attrName && attr.Value == attrValue {
				result = append(result, elem)
				break
			}
		}
	}
	return result
}

// GetAttributeValues returns all values for a given attribute across elements.
func (doc *AXMLDocument) GetAttributeValues(tagName, attrName string) []string {
	var values []string
	for _, elem := range doc.Elements {
		if elem.Name == tagName {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName && attr.Value != "" {
					values = append(values, attr.Value)
				}
			}
		}
	}
	return values
}

// FindAttribute finds a specific attribute value on a tag.
func (doc *AXMLDocument) FindAttribute(tagName, attrName string) string {
	for _, elem := range doc.Elements {
		if elem.Name == tagName {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName {
					return attr.Value
				}
			}
		}
	}
	return ""
}

// CountElements returns the number of elements with the given name.
func (doc *AXMLDocument) CountElements(name string) int {
	count := 0
	for _, elem := range doc.Elements {
		if elem.Name == name {
			count++
		}
	}
	return count
}

// GetNamespaces returns all namespace URI -> prefix mappings from the document.
func (doc *AXMLDocument) GetNamespaces() map[string]string {
	ns := make(map[string]string)
	for _, elem := range doc.Elements {
		for _, attr := range elem.Attributes {
			if strings.HasPrefix(attr.Name, "xmlns:") {
				prefix := strings.TrimPrefix(attr.Name, "xmlns:")
				ns[attr.Value] = prefix
			}
		}
	}
	return ns
}

// IsEmpty returns true if the document has no elements.
func (doc *AXMLDocument) IsEmpty() bool {
	return len(doc.Elements) == 0
}

// ParseValue parses a hex string like "@0x7f040001" to uint32.
func ParseValue(s string) (uint32, bool) {
	if len(s) < 3 || (s[0] != '@' && s[0] != '?') {
		return 0, false
	}

	var v uint32
	for _, c := range s[3:] { // skip @0x or ?0x
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint32(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint32(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}

// readUint32LE is a helper to read uint32 little-endian.
func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}
