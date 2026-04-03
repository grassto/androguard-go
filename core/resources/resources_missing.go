package resources

import (
	"fmt"
	"strings"
)

// --- Missing methods from Python androguard ARSCParser ---

// GetResourceString returns string resource values for a given entry.
func (table *ResourceTable) GetResourceString(entry ResourceEntry) []string {
	var results []string
	if entry.Value != nil && entry.Value.DataType == 0x03 { // String type
		if int(entry.Value.Data) < len(table.StringPool) {
			results = append(results, table.StringPool[entry.Value.Data])
		}
	}
	return results
}

// GetResourceID returns the resource ID for a given entry.
func (table *ResourceTable) GetResourceID(entry ResourceEntry) []string {
	var results []string
	if entry.Value != nil && entry.Value.DataType == 0x01 { // Reference type
		results = append(results, fmt.Sprintf("@0x%08x", entry.Value.Data))
	}
	return results
}

// GetResourceBool returns boolean resource values for a given entry.
func (table *ResourceTable) GetResourceBool(entry ResourceEntry) []string {
	var results []string
	if entry.Value != nil && entry.Value.DataType == 0x12 { // Boolean type
		if entry.Value.Data != 0 {
			results = append(results, "true")
		} else {
			results = append(results, "false")
		}
	}
	return results
}

// GetResourceInteger returns integer resource values for a given entry.
func (table *ResourceTable) GetResourceInteger(entry ResourceEntry) []string {
	var results []string
	if entry.Value != nil && entry.Value.DataType == 0x10 { // Int dec
		results = append(results, fmt.Sprintf("%d", int32(entry.Value.Data)))
	}
	return results
}

// GetResourceColor returns color resource values for a given entry.
func (table *ResourceTable) GetResourceColor(entry ResourceEntry) []string {
	var results []string
	if entry.Value == nil {
		return results
	}

	switch entry.Value.DataType {
	case 0x1C: // Color ARGB8
		results = append(results, fmt.Sprintf("#%08x", entry.Value.Data))
	case 0x1D: // Color RGB8
		results = append(results, fmt.Sprintf("#%06x", entry.Value.Data&0xFFFFFF))
	case 0x1E: // Color ARGB4
		results = append(results, fmt.Sprintf("#%04x", entry.Value.Data&0xFFFF))
	case 0x1F: // Color RGB4
		results = append(results, fmt.Sprintf("#%03x", entry.Value.Data&0xFFF))
	}
	return results
}

// GetResourceDimension returns dimension resource values for a given entry.
func (table *ResourceTable) GetResourceDimension(entry ResourceEntry) []string {
	var results []string
	if entry.Value == nil || entry.Value.DataType != 0x05 { // Dimension type
		return results
	}

	value := float32(int32(entry.Value.Data>>8)) / 256.0
	unit := entry.Value.Data & 0x0F

	units := []string{"px", "dp", "sp", "pt", "in", "mm"}
	unitStr := "px"
	if int(unit) < len(units) {
		unitStr = units[unit]
	}

	results = append(results, fmt.Sprintf("%g%s", value, unitStr))
	return results
}

// GetResourceStyle returns style resource values for a given entry.
func (table *ResourceTable) GetResourceStyle(entry ResourceEntry) []string {
	var results []string
	if entry.Complex == nil {
		return results
	}

	for _, me := range entry.Complex.Entries {
		keyName := ""
		for _, pkg := range table.Packages {
			if int(me.Name) < len(pkg.KeyStrings) {
				keyName = pkg.KeyStrings[me.Name]
				break
			}
		}
		value := GetResourceValueString(&me.Value, table.StringPool)
		results = append(results, keyName+"="+value)
	}
	return results
}

// FindResourceByName finds a resource entry by name across all types.
func (table *ResourceTable) FindResourceByName(name string) []ResourceEntry {
	var results []ResourceEntry
	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			for _, entry := range typ.Entries {
				if entry.Name == name {
					results = append(results, entry)
				}
			}
		}
	}
	return results
}

// FindResourceByID finds a resource by its ID (package|type|entry).
func (table *ResourceTable) FindResourceByID(packageID, typeID, entryID uint32) *ResourceEntry {
	for _, pkg := range table.Packages {
		if pkg.ID != packageID {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.ID != typeID {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Index == entryID {
					return &entry
				}
			}
		}
	}
	return nil
}

// GetResourceNames returns all resource names for a given type.
func (table *ResourceTable) GetResourceNames(typeName string) []string {
	var names []string
	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			if typ.Name == typeName {
				for _, entry := range typ.Entries {
					if entry.Name != "" {
						names = append(names, entry.Name)
					}
				}
			}
		}
	}
	return names
}

// GetResourceTypes returns all type names in the table.
func (table *ResourceTable) GetResourceTypes() []string {
	typeMap := make(map[string]bool)
	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			if typ.Name != "" {
				typeMap[typ.Name] = true
			}
		}
	}

	types := make([]string, 0, len(typeMap))
	for t := range typeMap {
		types = append(types, t)
	}
	return types
}

// GetPackageName returns the first package name.
func (table *ResourceTable) GetPackageName() string {
	if len(table.Packages) > 0 {
		return table.Packages[0].Name
	}
	return ""
}

// GetPackageID returns the first package ID.
func (table *ResourceTable) GetPackageID() uint32 {
	if len(table.Packages) > 0 {
		return table.Packages[0].ID
	}
	return 0
}

// ResolveResourceReference resolves a resource reference string like "@0x7f040001".
func (table *ResourceTable) ResolveResourceReference(ref string) string {
	if !strings.HasPrefix(ref, "@0x") && !strings.HasPrefix(ref, "@0X") {
		return ref
	}

	var resID uint32
	_, err := fmt.Sscanf(ref, "@0x%x", &resID)
	if err != nil {
		return ref
	}

	// resource ID format: 0xPPTTEEEE
	packageID := (resID >> 24) & 0xFF
	typeID := (resID >> 16) & 0xFF
	entryID := resID & 0xFFFF

	for _, pkg := range table.Packages {
		if pkg.ID != packageID {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.ID != typeID {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Index == entryID && entry.Value != nil {
					return GetResourceValueString(entry.Value, table.StringPool)
				}
			}
		}
	}

	return ref
}

// GetLocale returns the locale configuration for a resource type.
func (typ ResourceType) GetLocale() string {
	lang := string([]byte{typ.Config.Language[0], typ.Config.Language[1]})
	country := string([]byte{typ.Config.Country[0], typ.Config.Country[1]})

	lang = strings.TrimRight(lang, "\x00")
	country = strings.TrimRight(country, "\x00")

	if lang == "" {
		return "default"
	}
	if country == "" {
		return lang
	}
	return lang + "-" + country
}

// GetDensity returns the screen density for a resource type.
func (typ ResourceType) GetDensity() uint16 {
	return typ.Config.Density
}

// GetOrientation returns the orientation for a resource type.
func (typ ResourceType) GetOrientation() string {
	switch typ.Config.Orientation {
	case 1:
		return "port"
	case 2:
		return "land"
	case 3:
		return "square"
	default:
		return "any"
	}
}

// CountEntries returns the number of entries in a resource type.
func (typ ResourceType) CountEntries() int {
	return len(typ.Entries)
}

// GetEntryByIndex returns the entry at the given index.
func (typ ResourceType) GetEntryByIndex(idx uint32) *ResourceEntry {
	for i := range typ.Entries {
		if typ.Entries[i].Index == idx {
			return &typ.Entries[i]
		}
	}
	return nil
}

// GetEntryByName returns the entry with the given name.
func (typ ResourceType) GetEntryByName(name string) *ResourceEntry {
	for i := range typ.Entries {
		if typ.Entries[i].Name == name {
			return &typ.Entries[i]
		}
	}
	return nil
}

// HasComplexValue returns true if the entry has a complex (map) value.
func (entry ResourceEntry) HasComplexValue() bool {
	return entry.Complex != nil
}

// GetValue returns the formatted value string.
func (entry ResourceEntry) GetValueString(pool []string) string {
	if entry.Value != nil {
		return GetResourceValueString(entry.Value, pool)
	}
	if entry.Complex != nil {
		return fmt.Sprintf("complex(%d entries)", len(entry.Complex.Entries))
	}
	return ""
}

// GetPackagesNames returns all package names in the resource table.
func (table *ResourceTable) GetPackagesNames() []string {
	names := make([]string, 0, len(table.Packages))
	for _, pkg := range table.Packages {
		if pkg.Name != "" {
			names = append(names, pkg.Name)
		}
	}
	return names
}

// GetLocales returns all locales found in the resource table.
func (table *ResourceTable) GetLocales(packageName string) []string {
	localeMap := make(map[string]bool)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			lang := string([]byte{typ.Config.Language[0], typ.Config.Language[1]})
			country := string([]byte{typ.Config.Country[0], typ.Config.Country[1]})
			lang = strings.TrimRight(lang, "\x00")
			country = strings.TrimRight(country, "\x00")

			if lang == "" {
				localeMap["default"] = true
			} else if country == "" {
				localeMap[lang] = true
			} else {
				localeMap[lang+"-"+country] = true
			}
		}
	}

	locales := make([]string, 0, len(localeMap))
	for l := range localeMap {
		locales = append(locales, l)
	}
	return locales
}

// GetTypes returns type names for a given package and optional locale.
func (table *ResourceTable) GetTypes(packageName string, locale string) []string {
	typeMap := make(map[string]bool)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if locale != "" {
				lang := string([]byte{typ.Config.Language[0], typ.Config.Language[1]})
				lang = strings.TrimRight(lang, "\x00")
				if lang != locale && locale != "default" {
					continue
				}
			}
			if typ.Name != "" {
				typeMap[typ.Name] = true
			}
		}
	}

	types := make([]string, 0, len(typeMap))
	for t := range typeMap {
		types = append(types, t)
	}
	return types
}

// GetStringResources returns string resources as a map of name -> value.
func (table *ResourceTable) GetStringResources(packageName string) map[string]string {
	result := make(map[string]string)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "string" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil && entry.Value.DataType == 0x03 {
					if int(entry.Value.Data) < len(table.StringPool) {
						result[entry.Name] = table.StringPool[entry.Value.Data]
					}
				}
			}
		}
	}
	return result
}

// GetIntegerResources returns integer resources as a map of name -> value.
func (table *ResourceTable) GetIntegerResources(packageName string) map[string]int32 {
	result := make(map[string]int32)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "integer" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil && entry.Value.DataType == 0x10 {
					result[entry.Name] = int32(entry.Value.Data)
				}
			}
		}
	}
	return result
}

// GetBoolResources returns boolean resources as a map of name -> value.
func (table *ResourceTable) GetBoolResources(packageName string) map[string]bool {
	result := make(map[string]bool)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "bool" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil && entry.Value.DataType == 0x12 {
					result[entry.Name] = entry.Value.Data != 0
				}
			}
		}
	}
	return result
}

// GetColorResources returns color resources as a map of name -> hex string.
func (table *ResourceTable) GetColorResources(packageName string) map[string]string {
	result := make(map[string]string)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "color" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil {
					vals := table.GetResourceColor(entry)
					if len(vals) > 0 {
						result[entry.Name] = vals[0]
					}
				}
			}
		}
	}
	return result
}

// GetDimenResources returns dimension resources as a map of name -> value string.
func (table *ResourceTable) GetDimenResources(packageName string) map[string]string {
	result := make(map[string]string)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "dimen" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil {
					vals := table.GetResourceDimension(entry)
					if len(vals) > 0 {
						result[entry.Name] = vals[0]
					}
				}
			}
		}
	}
	return result
}

// GetIDResources returns ID resources as a map of name -> resource ID string.
func (table *ResourceTable) GetIDResources(packageName string) map[string]string {
	result := make(map[string]string)
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != "id" {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Value != nil {
					result[entry.Name] = fmt.Sprintf("@0x%08x", entry.Value.Data)
				}
			}
		}
	}
	return result
}

// GetResIDByKey returns the resource ID for a given package, type, and key name.
func (table *ResourceTable) GetResIDByKey(packageName, resourceType, key string) *uint32 {
	for _, pkg := range table.Packages {
		if pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name != resourceType {
				continue
			}
			for _, entry := range typ.Entries {
				if entry.Name == key {
					// Resource ID: package | type | entry
					resID := (pkg.ID << 24) | (typ.ID << 16) | entry.Index
					return &resID
				}
			}
		}
	}
	return nil
}

// GetPublicResources returns public resources as a list of (type, name, id) tuples.
func (table *ResourceTable) GetPublicResources(packageName string) []PublicResource {
	var result []PublicResource
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			for _, entry := range typ.Entries {
				if entry.Name != "" {
					resID := (pkg.ID << 24) | (typ.ID << 16) | entry.Index
					result = append(result, PublicResource{
						Type:  typ.Name,
						Name:  entry.Name,
						ID:    resID,
						IDHex: fmt.Sprintf("@0x%08x", resID),
					})
				}
			}
		}
	}
	return result
}

// PublicResource represents a public resource entry.
type PublicResource struct {
	Type  string
	Name  string
	ID    uint32
	IDHex string
}

// GetResourceXMLName returns the XML reference name for a resource ID.
// Example: 0x7f040001 -> "@string/app_name"
func (table *ResourceTable) GetResourceXMLName(resID uint32) string {
	packageID := (resID >> 24) & 0xFF
	typeID := (resID >> 16) & 0xFF
	entryID := resID & 0xFFFF

	for _, pkg := range table.Packages {
		if pkg.ID != packageID {
			continue
		}
		var typeName string
		for _, ts := range pkg.TypeSpecs {
			if ts.ID == typeID {
				typeName = ts.Name
				break
			}
		}
		if typeName == "" {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.ID == typeID {
				for _, entry := range typ.Entries {
					if entry.Index == entryID && entry.Name != "" {
						return fmt.Sprintf("@%s/%s", typeName, entry.Name)
					}
				}
			}
		}
	}
	return fmt.Sprintf("@0x%08x", resID)
}

// GetResolvedStrings returns all resolved string values.
func (table *ResourceTable) GetResolvedStrings() []string {
	result := make([]string, len(table.StringPool))
	copy(result, table.StringPool)
	return result
}

// GetTypeConfigs returns configuration variants for a given type.
func (table *ResourceTable) GetTypeConfigs(packageName, typeName string) []ResTableConfig {
	var configs []ResTableConfig
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typeName == "" || typ.Name == typeName {
				configs = append(configs, typ.Config)
			}
		}
	}
	return configs
}

// GetResConfigs returns resource entries with their configurations for a type.
func (table *ResourceTable) GetResConfigs(packageName, typeName string) []ResConfigEntry {
	var result []ResConfigEntry
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name == typeName {
				for _, entry := range typ.Entries {
					valStr := ""
					if entry.Value != nil {
						valStr = GetResourceValueString(entry.Value, table.StringPool)
					}
					result = append(result, ResConfigEntry{
						Config: typ.Config,
						Name:   entry.Name,
						Value:  valStr,
					})
				}
			}
		}
	}
	return result
}

// ResConfigEntry pairs a resource entry with its configuration.
type ResConfigEntry struct {
	Config ResTableConfig
	Name   string
	Value  string
}

// GetItems returns all resource entries for a package.
func (table *ResourceTable) GetItems(packageName string) []ResourceEntry {
	var entries []ResourceEntry
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			entries = append(entries, typ.Entries...)
		}
	}
	return entries
}

// GetResolvedResConfigs returns resolved resource configurations with values.
func (table *ResourceTable) GetResolvedResConfigs(packageName, typeName string) []ResolvedConfig {
	var result []ResolvedConfig
	for _, pkg := range table.Packages {
		if packageName != "" && pkg.Name != packageName {
			continue
		}
		for _, typ := range pkg.Types {
			if typ.Name == typeName {
				for _, entry := range typ.Entries {
					if entry.Value != nil {
						result = append(result, ResolvedConfig{
							Name:   entry.Name,
							Config: typ.Config,
							Value:  GetResourceValueString(entry.Value, table.StringPool),
						})
					}
				}
			}
		}
	}
	return result
}

// ResolvedConfig holds a resolved resource configuration.
type ResolvedConfig struct {
	Name   string
	Config ResTableConfig
	Value  string
}
