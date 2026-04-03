package axml

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// AXMLNode represents a hierarchical XML node in the parsed tree.
type AXMLNode struct {
	Name         string
	NamespaceURI string
	Attributes   []XMLAttributeNode
	Children     []*AXMLNode
	Parent       *AXMLNode
	Text         string
	Comment      string
	Line         uint32
}

// AXMLDocumentEnhanced represents a fully parsed AXML with hierarchical structure.
type AXMLDocumentEnhanced struct {
	Root       *AXMLNode
	StringPool *StringPool
	NSMap      map[string]string // prefix -> URI
	IsPacked   bool
	Raw        []byte
}

// ParseAXMLEnhanced parses AXML data into a hierarchical document tree.
func ParseAXMLEnhanced(data []byte) (*AXMLDocumentEnhanced, error) {
	parser := NewAXMLParser(data)
	doc := &AXMLDocumentEnhanced{
		Raw:   data,
		NSMap: make(map[string]string),
	}

	// Detect packed/obfuscated AXML
	doc.IsPacked = detectPackedAXML(data)

	// Build tree structure
	var root *AXMLNode
	var current *AXMLNode
	var nsMap map[string]string
	var nsStack []map[string]string
	var comments []string
	var depth int

	for {
		event, err := parser.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch event {
		case EventStartDocument:
			nsMap = make(map[string]string)
			nsStack = append(nsStack, nsMap)

		case EventStartElement:
			node := &AXMLNode{
				Name:         parser.GetAttributeString(parser.curElement.Name),
				NamespaceURI: parser.GetAttributeString(parser.curElement.NamespaceURI),
				Line:         parser.curElement.Line,
				Parent:       current,
			}

			// Attach comment if available
			if len(comments) > 0 {
				node.Comment = comments[len(comments)-1]
				comments = comments[:len(comments)-1]
			}

			// Add attributes
			for _, attr := range parser.curElement.Attributes {
				node.Attributes = append(node.Attributes, XMLAttributeNode{
					NamespaceURI: parser.GetAttributeString(attr.NamespaceURI),
					Name:         parser.GetAttributeString(attr.Name),
					Value:        parser.GetAttributeString(attr.ValueString),
					ValueType:    attr.ValueType,
					ValueData:    attr.ValueData,
				})
			}

			if root == nil {
				root = node
				current = node
			} else {
				current.Children = append(current.Children, node)
				current = node
			}
			depth++

		case EventEndElement:
			if current != nil && current.Parent != nil {
				current = current.Parent
			}
			depth--

		case EventText:
			if current != nil {
				// Text content would be in CDATA
				current.Text = parser.GetAttributeString(parser.curElement.Name)
			}
		}
	}

	doc.Root = root
	doc.StringPool = parser.strings

	// Build NSMap from root namespace declarations
	if root != nil {
		for _, attr := range root.Attributes {
			if strings.HasPrefix(attr.Name, "xmlns:") {
				prefix := strings.TrimPrefix(attr.Name, "xmlns:")
				doc.NSMap[prefix] = attr.Value
			}
		}
	}

	return doc, nil
}

// detectPackedAXML detects common AXML obfuscation/packing patterns.
func detectPackedAXML(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for valid magic
	if binary.LittleEndian.Uint32(data[0:4]) != ResXMLType {
		return true // Not a valid AXML
	}

	// Check string pool for obfuscated strings
	// Packed AXMLs often have very short or random string pools
	headerSize := int(binary.LittleEndian.Uint16(data[4:6]))
	if headerSize+8 > len(data) {
		return false
	}

	chunkType := binary.LittleEndian.Uint16(data[headerSize : headerSize+2])
	if chunkType == ResStringPoolType {
		stringCount := binary.LittleEndian.Uint32(data[headerSize+8 : headerSize+12])
		// Very few strings might indicate packing
		if stringCount < 3 && stringCount > 0 {
			// Check if any strings look garbled
			return true
		}
	}

	return false
}

// IsPacked returns true if the AXML appears to be packed or obfuscated.
func IsPacked(data []byte) bool {
	return detectPackedAXML(data)
}

// GetAllAttributes returns all attributes for a node with their resolved values.
func (node *AXMLNode) GetAllAttributes() map[string]string {
	result := make(map[string]string)
	for _, attr := range node.Attributes {
		key := attr.Name
		if attr.NamespaceURI != "" {
			key = attr.NamespaceURI + ":" + attr.Name
		}
		result[key] = attr.Value
	}
	return result
}

// GetAttribute returns the value of an attribute by name (ignoring namespace).
func (node *AXMLNode) GetAttribute(name string) string {
	for _, attr := range node.Attributes {
		if attr.Name == name {
			return attr.Value
		}
	}
	return ""
}

// GetAttributeNS returns the value of an attribute by namespace and name.
func (node *AXMLNode) GetAttributeNS(namespace, name string) string {
	for _, attr := range node.Attributes {
		if attr.NamespaceURI == namespace && attr.Name == name {
			return attr.Value
		}
	}
	return ""
}

// FindChild returns the first child with the given name.
func (node *AXMLNode) FindChild(name string) *AXMLNode {
	for _, child := range node.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

// FindChildren returns all children with the given name.
func (node *AXMLNode) FindChildren(name string) []*AXMLNode {
	var result []*AXMLNode
	for _, child := range node.Children {
		if child.Name == name {
			result = append(result, child)
		}
	}
	return result
}

// FindChildrenByNS returns all children in the given namespace.
func (node *AXMLNode) FindChildrenByNS(namespace string) []*AXMLNode {
	var result []*AXMLNode
	for _, child := range node.Children {
		if child.NamespaceURI == namespace {
			result = append(result, child)
		}
	}
	return result
}

// Depth returns the depth of this node in the tree (root = 0).
func (node *AXMLNode) Depth() int {
	depth := 0
	n := node.Parent
	for n != nil {
		depth++
		n = n.Parent
	}
	return depth
}

// XPath-like query: FindNodes finds all descendant nodes matching the name.
func (node *AXMLNode) FindNodes(name string) []*AXMLNode {
	var result []*AXMLNode
	if node.Name == name {
		result = append(result, node)
	}
	for _, child := range node.Children {
		result = append(result, child.FindNodes(name)...)
	}
	return result
}

// FindNodesByAttr finds all descendant nodes with a specific attribute value.
func (node *AXMLNode) FindNodesByAttr(attrName, attrValue string) []*AXMLNode {
	var result []*AXMLNode
	if node.GetAttribute(attrName) == attrValue {
		result = append(result, node)
	}
	for _, child := range node.Children {
		result = append(result, child.FindNodesByAttr(attrName, attrValue)...)
	}
	return result
}

// ToXML generates XML string with proper indentation.
func (doc *AXMLDocumentEnhanced) ToXML() string {
	if doc.Root == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	doc.nodeToXML(&sb, doc.Root, 0)
	return sb.String()
}

func (doc *AXMLDocumentEnhanced) nodeToXML(sb *strings.Builder, node *AXMLNode, indent int) {
	indentStr := strings.Repeat("    ", indent)

	if node.Comment != "" {
		sb.WriteString(fmt.Sprintf("%s<!-- %s -->\n", indentStr, node.Comment))
	}

	sb.WriteString(indentStr + "<")

	if node.NamespaceURI != "" {
		// Find prefix
		prefix := ""
		for p, uri := range doc.NSMap {
			if uri == node.NamespaceURI {
				prefix = p
				break
			}
		}
		if prefix != "" {
			sb.WriteString(prefix + ":")
		}
	}
	sb.WriteString(node.Name)

	// Attributes
	for _, attr := range node.Attributes {
		sb.WriteString("\n" + indentStr + "    ")
		if attr.NamespaceURI != "" {
			prefix := ""
			for p, uri := range doc.NSMap {
				if uri == attr.NamespaceURI {
					prefix = p
					break
				}
			}
			if prefix != "" {
				sb.WriteString(prefix + ":")
			}
		}
		sb.WriteString(fmt.Sprintf("%s=\"%s\"", attr.Name, formatAttributeValue(attr)))
	}

	if len(node.Children) == 0 && node.Text == "" {
		sb.WriteString(" />\n")
	} else {
		sb.WriteString(">\n")
		if node.Text != "" {
			sb.WriteString(node.Text + "\n")
		}
		for _, child := range node.Children {
			doc.nodeToXML(sb, child, indent+1)
		}
		sb.WriteString(fmt.Sprintf("%s</%s>\n", indentStr, node.Name))
	}
}

func formatAttributeValue(attr XMLAttributeNode) string {
	if attr.Value != "" {
		return attr.Value
	}

	switch attr.ValueType {
	case AttrTypeIntDec:
		return fmt.Sprintf("%d", int32(attr.ValueData))
	case AttrTypeIntHex:
		return fmt.Sprintf("0x%x", attr.ValueData)
	case AttrTypeIntBoolean:
		if attr.ValueData != 0 {
			return "true"
		}
		return "false"
	case AttrTypeReference:
		return fmt.Sprintf("@0x%x", attr.ValueData)
	default:
		return fmt.Sprintf("0x%x", attr.ValueData)
	}
}

// CountNodes returns the total number of nodes in the tree.
func (node *AXMLNode) CountNodes() int {
	count := 1
	for _, child := range node.Children {
		count += child.CountNodes()
	}
	return count
}

// GetFullPath returns the full path of this node (like /manifest/application/activity).
func (node *AXMLNode) GetFullPath() string {
	parts := []string{}
	n := node
	for n != nil {
		parts = append([]string{n.Name}, parts...)
		n = n.Parent
	}
	return "/" + strings.Join(parts, "/")
}
