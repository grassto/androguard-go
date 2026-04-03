package axml

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// AXMLPrinter converts AXML binary data into a well-formed XML document.
// It handles namespace resolution, attribute formatting, and packed detection.
type AXMLPrinter struct {
	parser     *AXMLParser
	root       *XMLNode
	current    *XMLNode
	stack      []*XMLNode
	nsMap      map[string]string // prefix -> URI
	nsStack    []map[string]string
	isPacked   bool
	isValid    bool
	errors     []string
}

// XMLNode represents a single XML element in the output tree.
type XMLNode struct {
	Name       string
	Namespace  string
	Attributes map[string]string
	Children   []*XMLNode
	Parent     *XMLNode
	Text       string
	Comment    string
	Line       uint32
}

// NewAXMLPrinter creates a new printer from raw AXML data.
func NewAXMLPrinter(data []byte) *AXMLPrinter {
	p := &AXMLPrinter{
		parser:   NewAXMLParser(data),
		nsMap:    make(map[string]string),
		isPacked: detectPackedAXML(data),
		isValid:  true,
	}

	p.parse()
	return p
}

// parse processes all AXML events and builds the XML tree.
func (p *AXMLPrinter) parse() {
	for {
		event, err := p.parser.Next()
		if err != nil {
			break
		}

		switch event {
		case EventStartElement:
			p.handleStartElement()
		case EventEndElement:
			p.handleEndElement()
		case EventText:
			p.handleText()
		case EventEndDocument:
			return
		}
	}
}

func (p *AXMLPrinter) handleStartElement() {
	if p.parser.curElement == nil {
		return
	}

	name := p.parser.GetAttributeString(p.parser.curElement.Name)
	if name == "" {
		return // Skip empty tag names
	}

	nsURI := p.parser.GetAttributeString(p.parser.curElement.NamespaceURI)

	// Build full tag name with namespace prefix
	tagName := p.resolveTagName(nsURI, name)

	node := &XMLNode{
		Name:      tagName,
		Namespace: nsURI,
		Attributes: make(map[string]string),
		Parent:    p.current,
		Line:      p.parser.curElement.Line,
	}

	// Add attributes
	for _, attr := range p.parser.curElement.Attributes {
		attrNS := p.parser.GetAttributeString(attr.NamespaceURI)
		attrName := p.parser.GetAttributeString(attr.Name)

		fullAttrName := p.resolveTagName(attrNS, attrName)
		
		// Format attribute value
		var value string
		attrValueStr := p.parser.GetAttributeString(attr.ValueString)
		if attrValueStr != "" {
			value = p.fixValue(attrValueStr)
		} else {
			value = formatValue(attr.ValueType, attr.ValueData, func(idx int) string {
				if p.parser.strings != nil && idx < len(p.parser.strings.Strings) {
					return p.parser.strings.Strings[idx]
				}
				return ""
			})
		}

		node.Attributes[fullAttrName] = value
	}

	if p.root == nil {
		p.root = node
	} else if p.current != nil {
		p.current.Children = append(p.current.Children, node)
	}

	p.current = node
	p.stack = append(p.stack, node)
}

func (p *AXMLPrinter) handleEndElement() {
	if len(p.stack) > 0 {
		p.stack = p.stack[:len(p.stack)-1]
		if len(p.stack) > 0 {
			p.current = p.stack[len(p.stack)-1]
		} else {
			p.current = nil
		}
	}
}

func (p *AXMLPrinter) handleText() {
	if p.current != nil && p.parser.curElement != nil {
		text := p.parser.GetAttributeString(p.parser.curElement.Name)
		if text != "" {
			p.current.Text = text
		}
	}
}

func (p *AXMLPrinter) resolveTagName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	// Find prefix for namespace
	for prefix, uri := range p.nsMap {
		if uri == namespace {
			return prefix + ":" + name
		}
	}

	// Common namespace prefixes
	switch namespace {
	case "http://schemas.android.com/apk/res/android":
		return "android:" + name
	case "http://schemas.android.com/apk/res-auto":
		return "app:" + name
	case "http://www.w3.org/2000/xmlns/":
		return "xmlns:" + name
	}

	return name
}

// formatValue formats an attribute value based on its type.
func formatValue(valueType uint16, valueData uint32, stringGetter func(int) string) string {
	switch valueType {
	case AttrTypeNull:
		return ""
	case AttrTypeReference:
		return fmt.Sprintf("@0x%x", valueData)
	case AttrTypeAttribute:
		return fmt.Sprintf("?0x%x", valueData)
	case AttrTypeString:
		return stringGetter(int(valueData))
	case AttrTypeFloat:
		// Interpret as float
		bits := valueData
		return fmt.Sprintf("%g", float32(bits))
	case AttrTypeDimension:
		return formatDimension(valueData)
	case AttrTypeFraction:
		return formatFraction(valueData)
	case AttrTypeIntDec:
		return fmt.Sprintf("%d", int32(valueData))
	case AttrTypeIntHex:
		return fmt.Sprintf("%#x", valueData)
	case AttrTypeIntBoolean:
		if valueData != 0 {
			return "true"
		}
		return "false"
	case AttrTypeIntColorARGB8:
		return fmt.Sprintf("#%08x", valueData)
	case AttrTypeIntColorRGB8:
		return fmt.Sprintf("#%06x", valueData&0xFFFFFF)
	case AttrTypeIntColorARGB4:
		return fmt.Sprintf("#%04x", valueData&0xFFFF)
	case AttrTypeIntColorRGB4:
		return fmt.Sprintf("#%03x", valueData&0xFFF)
	default:
		return fmt.Sprintf("%d", valueData)
	}
}

// formatDimension formats a dimension value (e.g., 12dp, 14sp).
func formatDimension(data uint32) string {
	value := float32(int32(data>>8)) / 256.0
	unit := data & 0x0F

	units := []string{"px", "dp", "sp", "pt", "in", "mm"}
	if int(unit) < len(units) {
		return fmt.Sprintf("%g%s", value, units[unit])
	}
	return fmt.Sprintf("%gpx", value)
}

// formatFraction formats a fraction value (e.g., 50%).
func formatFraction(data uint32) string {
	value := float32(int32(data>>8)) / 256.0 * 100.0
	p := data & 0x0F
	if p == 0 {
		return fmt.Sprintf("%g%%", value)
	}
	return fmt.Sprintf("%g%%p", value)
}

// fixValue fixes common issues in attribute values.
func (p *AXMLPrinter) fixValue(value string) string {
	// Replace null bytes
	value = strings.ReplaceAll(value, "\x00", "")
	return value
}

// GetRoot returns the root XML node.
func (p *AXMLPrinter) GetRoot() *XMLNode {
	return p.root
}

// GetXML returns the XML as a formatted string.
func (p *AXMLPrinter) GetXML(pretty bool) string {
	if p.root == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")

	if pretty {
		p.nodeToXML(&sb, p.root, 0, true)
	} else {
		p.nodeToXML(&sb, p.root, 0, false)
	}

	return sb.String()
}

func (p *AXMLPrinter) nodeToXML(sb *strings.Builder, node *XMLNode, indent int, pretty bool) {
	indentStr := ""
	newline := ""
	if pretty {
		indentStr = strings.Repeat("    ", indent)
		newline = "\n"
	}

	// Open tag
	sb.WriteString(indentStr + "<" + node.Name)

	// Attributes
	for name, value := range node.Attributes {
		sb.WriteString(fmt.Sprintf(" %s=\"%s\"", name, escapeXML(value)))
	}

	if len(node.Children) == 0 && node.Text == "" {
		sb.WriteString(" />" + newline)
	} else {
		sb.WriteString(">" + newline)

		if node.Text != "" {
			sb.WriteString(escapeXML(node.Text))
			if pretty {
				sb.WriteString("\n")
			}
		}

		for _, child := range node.Children {
			p.nodeToXML(sb, child, indent+1, pretty)
		}

		sb.WriteString(indentStr + "</" + node.Name + ">" + newline)
	}
}

// escapeXML escapes special XML characters.
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// IsValid returns true if the AXML was parsed successfully.
func (p *AXMLPrinter) IsValid() bool {
	return p.isValid && p.root != nil
}

// IsPacked returns true if the AXML appears to be packed/obfuscated.
func (p *AXMLPrinter) IsPacked() bool {
	return p.isPacked
}

// GetErrors returns any parsing errors encountered.
func (p *AXMLPrinter) GetErrors() []string {
	return p.errors
}

// FindElement finds the first element with the given tag name.
func (p *AXMLPrinter) FindElement(tagName string) *XMLNode {
	if p.root == nil {
		return nil
	}
	return findElementRecursive(p.root, tagName)
}

func findElementRecursive(node *XMLNode, tagName string) *XMLNode {
	if node.Name == tagName {
		return node
	}
	for _, child := range node.Children {
		if found := findElementRecursive(child, tagName); found != nil {
			return found
		}
	}
	return nil
}

// FindElements finds all elements with the given tag name.
func (p *AXMLPrinter) FindElements(tagName string) []*XMLNode {
	if p.root == nil {
		return nil
	}
	var result []*XMLNode
	findElementsRecursive(p.root, tagName, &result)
	return result
}

func findElementsRecursive(node *XMLNode, tagName string, result *[]*XMLNode) {
	if node.Name == tagName {
		*result = append(*result, node)
	}
	for _, child := range node.Children {
		findElementsRecursive(child, tagName, result)
	}
}

// GetAttributeValue returns the value of an attribute on the root element.
func (p *AXMLPrinter) GetAttributeValue(attrName string) string {
	if p.root == nil {
		return ""
	}
	return p.root.Attributes[attrName]
}

// ToFlatDocument converts the tree back to the flat AXMLDocument format.
func (p *AXMLPrinter) ToFlatDocument() *AXMLDocument {
	doc := &AXMLDocument{
		StringPool: p.parser.strings,
	}

	if p.root != nil {
		flattenNodes(p.root, &doc.Elements)
	}

	return doc
}

func flattenNodes(node *XMLNode, elements *[]XMLElementNode) {
	elem := XMLElementNode{
		Name: node.Name,
		Line: node.Line,
	}

	for name, value := range node.Attributes {
		attr := XMLAttributeNode{
			Name:  name,
			Value: value,
		}
		elem.Attributes = append(elem.Attributes, attr)
	}

	*elements = append(*elements, elem)

	for _, child := range node.Children {
		flattenNodes(child, elements)
	}
}

// Line is the line number (added to XMLNode)
type xmlNodeLine struct {
	Line uint32
}

// Extend XMLNode to include Line field - we'll add it inline
// Actually we need to update the struct, let me add it properly

// ParseAXMLToPrinter is a convenience function that parses AXML data and returns a printer.
func ParseAXMLToPrinter(data []byte) *AXMLPrinter {
	return NewAXMLPrinter(data)
}

// Quick helper to check if data is valid AXML
func IsValidAXML(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	return binary.LittleEndian.Uint32(data[0:4]) == ResXMLType
}
