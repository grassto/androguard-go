package apk

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/goandroguard/goandroguard/pkg/arsc"
)

// IsPacked returns true if the APK appears to be packed or obfuscated.
// Common packers include Bangcle, Qihoo 360, Ali, Tencent Legu, etc.
func (a *APK) IsPacked() bool {
	// Check for packer-specific files in the APK
	packerFiles := []string{
		"libexec.so",
		"libexecmain.so",
		"libsecexe.so",
		"libsecmain.so",
		"libDexHelper.so",
		"libjiagu.so",
		"libjiagu_art.so",
		"libjiagu_x86.so",
		"libsgmain.so",
		"libsgsecuritybody.so",
		"libtup.so",
		"libshell.so",
		"mix.dex",
		"shell.dex",
		"cache.bin",
	}

	for _, name := range a.GetFileNames() {
		base := filepath.Base(name)
		for _, pf := range packerFiles {
			if base == pf {
				return true
			}
		}
	}

	// Check for unusual number of DEX files or very small main DEX
	if len(a.dexFiles) > 0 {
		// If main DEX is suspiciously small, might be packed
		if len(a.dexFiles) > 0 && a.dexFiles[0].Header.FileSize < 500 {
			return true
		}
	}

	return false
}

// IsValidAPK returns true if the APK appears to be a valid Android package.
func (a *APK) IsValidAPK() bool {
	// Must have AndroidManifest.xml
	if a.manifest == nil {
		return false
	}

	// Must have a package name
	if a.GetPackageName() == "" {
		return false
	}

	// Must have at least one DEX file
	if len(a.dexFiles) == 0 {
		return false
	}

	return true
}

// IsMultiDex returns true if the APK contains multiple DEX files.
func (a *APK) IsMultiDex() bool {
	return len(a.dexFiles) > 1
}

// GetDexNames returns the names of all DEX files in the APK.
func (a *APK) GetDexNames() []string {
	var names []string
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "classes") && strings.HasSuffix(f.Name, ".dex") {
			names = append(names, f.Name)
		}
	}
	return names
}

// GetAppName returns the application name, optionally resolving resource references.
func (a *APK) GetAppName() string {
	label := a.GetApplicationLabel()
	if label == "" {
		return ""
	}

	// If it's a resource reference like @0x7f040001, try to resolve it
	if strings.HasPrefix(label, "@") && a.resourcesTable != nil {
		resolved := a.resolveResourceString(label)
		if resolved != "" {
			return resolved
		}
	}

	return label
}

// resolveResourceString attempts to resolve a resource reference string.
func (a *APK) resolveResourceString(ref string) string {
	if !strings.HasPrefix(ref, "@0x") && !strings.HasPrefix(ref, "@0X") {
		return ""
	}

	// Parse the hex resource ID
	var resID uint32
	_, err := fmt.Sscanf(ref, "@0x%x", &resID)
	if err != nil {
		return ""
	}

	// resource ID format: 0xPPTTEEEE where PP=package, TT=type, EEEE=entry
	_ = (resID >> 24) & 0xFF // package
	typeID := (resID >> 16) & 0xFF
	entryID := resID & 0xFFFF

	for _, pkg := range a.resourcesTable.Packages {
		for _, typ := range pkg.Types {
			if typ.ID == typeID {
				for _, entry := range typ.Entries {
					if entry.Index == entryID && entry.Value != nil {
						return arsc.GetResourceValueString(entry.Value, a.resourcesTable.StringPool)
					}
				}
			}
		}
	}

	return ""
}

// GetAppIcon returns the path to the application icon in the APK.
func (a *APK) GetAppIcon() string {
	icon := a.getManifestAttribute("application", "icon")
	if icon == "" {
		return ""
	}

	// If it's a resource reference, try to resolve to a file path
	if strings.HasPrefix(icon, "@") {
		resolved := a.resolveResourceToFilePath(icon)
		if resolved != "" {
			return resolved
		}
	}

	return icon
}

// resolveResourceToFilePath resolves a resource reference to a file path in the APK.
func (a *APK) resolveResourceToFilePath(ref string) string {
	if !strings.HasPrefix(ref, "@0x") && !strings.HasPrefix(ref, "@0X") {
		return ""
	}

	var resID uint32
	_, err := fmt.Sscanf(ref, "@0x%x", &resID)
	if err != nil {
		return ""
	}

	typeID := (resID >> 16) & 0xFF
	entryID := resID & 0xFFFF

	for _, pkg := range a.resourcesTable.Packages {
		for _, typ := range pkg.Types {
			if typ.ID == typeID {
				for _, entry := range typ.Entries {
					if entry.Index == entryID && entry.Value != nil {
						if entry.Value.DataType == 0x03 { // String type
							if int(entry.Value.Data) < len(a.resourcesTable.StringPool) {
								return a.resourcesTable.StringPool[entry.Value.Data]
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// GetActivityAliases returns the activity aliases declared in the manifest.
func (a *APK) GetActivityAliases() []map[string]string {
	var aliases []map[string]string
	if a.manifest == nil {
		return aliases
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == "activity-alias" {
			alias := make(map[string]string)
			for _, attr := range elem.Attributes {
				if attr.NamespaceURI == nsAndroid || attr.NamespaceURI == "" {
					alias[attr.Name] = attr.Value
				}
			}
			if len(alias) > 0 {
				aliases = append(aliases, alias)
			}
		}
	}
	return aliases
}

// GetIntentFilters returns intent filters for a given component.
func (a *APK) GetIntentFilters(componentType string) map[string][]map[string]string {
	result := make(map[string][]map[string]string)
	if a.manifest == nil {
		return result
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"
	var currentComponent string
	var currentFilter map[string]string
	var currentActions []string
	var currentCategories []string
	inIntentFilter := false

	for _, elem := range a.manifest.Elements {
		if elem.Name == componentType {
			// Get component name
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && (attr.NamespaceURI == nsAndroid || attr.NamespaceURI == "") {
					currentComponent = attr.Value
				}
			}
		} else if elem.Name == "intent-filter" && currentComponent != "" {
			inIntentFilter = true
			currentFilter = make(map[string]string)
			currentActions = nil
			currentCategories = nil
		} else if inIntentFilter {
			if elem.Name == "action" {
				for _, attr := range elem.Attributes {
					if attr.Name == "name" {
						currentActions = append(currentActions, attr.Value)
					}
				}
			} else if elem.Name == "category" {
				for _, attr := range elem.Attributes {
					if attr.Name == "name" {
						currentCategories = append(currentCategories, attr.Value)
					}
				}
			} else if elem.Name == "data" {
				for _, attr := range elem.Attributes {
					currentFilter[attr.Name] = attr.Value
				}
			}

			// Check if we've left the intent-filter
			if elem.Name != "action" && elem.Name != "category" && elem.Name != "data" {
				inIntentFilter = false
				if len(currentActions) > 0 {
					for _, action := range currentActions {
						filter := map[string]string{"action": action}
						for k, v := range currentFilter {
							filter[k] = v
						}
						for _, cat := range currentCategories {
							filter["category"] = cat
						}
						result[currentComponent] = append(result[currentComponent], filter)
					}
				}
				currentComponent = ""
			}
		}
	}

	return result
}

// GetDetailsPermissions returns detailed information about permissions.
func (a *APK) GetDetailsPermissions() map[string][]string {
	result := make(map[string][]string)
	if a.manifest == nil {
		return result
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == "uses-permission" || elem.Name == "uses-permission-sdk-23" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" {
					details := []string{}
					// Get additional attributes
					for _, a := range elem.Attributes {
						if a.Name == "maxSdkVersion" {
							details = append(details, "maxSdkVersion="+a.Value)
						}
					}
					if elem.Name == "uses-permission-sdk-23" {
						details = append(details, "runtime")
					}
					result[attr.Value] = details
				}
			}
		} else if elem.Name == "permission" {
			var permName string
			var details []string
			for _, attr := range elem.Attributes {
				if attr.Name == "name" {
					permName = attr.Value
				} else if attr.NamespaceURI == nsAndroid || attr.NamespaceURI == "" {
					details = append(details, attr.Name+"="+attr.Value)
				}
			}
			if permName != "" {
				result[permName] = details
			}
		}
	}

	return result
}

// GetDeclaredPermissions returns permissions declared by this app.
func (a *APK) GetDeclaredPermissions() []string {
	var permissions []string
	if a.manifest == nil {
		return permissions
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "permission" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					permissions = append(permissions, attr.Value)
				}
			}
		}
	}
	return permissions
}

// GetLibraries returns shared libraries declared in the manifest.
func (a *APK) GetLibraries() []string {
	var libraries []string
	if a.manifest == nil {
		return libraries
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "uses-library" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					libraries = append(libraries, attr.Value)
				}
			}
		}
	}
	return libraries
}

// GetFeatures returns hardware/software features required by the app.
func (a *APK) GetFeatures() []string {
	var features []string
	if a.manifest == nil {
		return features
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "uses-feature" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					features = append(features, attr.Value)
				}
			}
		}
	}
	return features
}

// IsWearable returns true if the app targets Android Wear.
func (a *APK) IsWearable() bool {
	for _, f := range a.GetFeatures() {
		if f == "android.hardware.type.watch" {
			return true
		}
	}
	return false
}

// IsLeanback returns true if the app targets Android TV (leanback).
func (a *APK) IsLeanback() bool {
	for _, f := range a.GetFeatures() {
		if f == "android.software.leanback" {
			return true
		}
	}
	return false
}

// GetEffectiveTargetSdkVersion returns the effective target SDK version as an integer.
func (a *APK) GetEffectiveTargetSdkVersion() int {
	target := a.GetTargetSDKVersion()
	if target == "" {
		// Default to min SDK if target not specified
		min := a.GetMinSDKVersion()
		if min != "" {
			var v int
			if _, err := fmt.Sscanf(min, "%d", &v); err == nil {
				return v
			}
		}
		return 1 // Default to API 1
	}
	var v int
	if _, err := fmt.Sscanf(target, "%d", &v); err == nil {
		return v
	}
	return 1
}

// GetFilesTypes returns a map of filename to detected file type.
func (a *APK) GetFilesTypes() map[string]string {
	types := make(map[string]string)
	for _, f := range a.zipReader.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := make([]byte, 16)
		n, _ := rc.Read(buf)
		rc.Close()

		if n >= 4 {
			types[f.Name] = detectFileType(buf[:n], f.Name)
		}
	}
	return types
}

// detectFileType detects file type from magic bytes and filename.
func detectFileType(buf []byte, name string) string {
	if len(buf) < 4 {
		return "unknown"
	}

	// DEX
	if len(buf) >= 8 && string(buf[:4]) == "dex\n" {
		return "dex"
	}

	// ZIP/APK
	if buf[0] == 0x50 && buf[1] == 0x4B {
		if strings.HasSuffix(name, ".apk") {
			return "apk"
		}
		return "zip"
	}

	// ELF
	if buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
		return "elf"
	}

	// PNG
	if buf[0] == 0x89 && buf[1] == 'P' && buf[2] == 'N' && buf[3] == 'G' {
		return "png"
	}

	// JPEG
	if buf[0] == 0xFF && buf[1] == 0xD8 {
		return "jpeg"
	}

	// GIF
	if string(buf[:3]) == "GIF" {
		return "gif"
	}

	// XML
	if len(buf) >= 5 && (string(buf[:5]) == "<?xml" || string(buf[:5]) == "<!-- ") {
		return "xml"
	}

	// ARSC
	ext := filepath.Ext(name)
	switch ext {
	case ".arsc":
		return "arsc"
	case ".so":
		return "elf"
	case ".xml":
		return "xml"
	case ".json":
		return "json"
	case ".properties":
		return "properties"
	case ".MF":
		return "manifest"
	case ".RSA", ".DSA", ".EC":
		return "pkcs7"
	case ".SF":
		return "signature"
	}

	return "unknown"
}

// GetFilesCRC32 returns a map of filename to CRC32 checksum.
func (a *APK) GetFilesCRC32() map[string]uint32 {
	crcs := make(map[string]uint32)
	for _, f := range a.zipReader.File {
		crcs[f.Name] = f.CRC32
	}
	return crcs
}

// GetMainActivities returns the main activities (launcher activities).
func (a *APK) GetMainActivities() []string {
	var mains []string
	if a.manifest == nil {
		return mains
	}

	intentFilters := a.GetIntentFilters("activity")
	for component, filters := range intentFilters {
		for _, filter := range filters {
			if filter["action"] == "android.intent.action.MAIN" &&
				filter["category"] == "android.intent.category.LAUNCHER" {
				mains = append(mains, component)
			}
		}
	}

	return mains
}

// GetMainActivity returns the first main activity, or empty string.
func (a *APK) GetMainActivity() string {
	mains := a.GetMainActivities()
	if len(mains) > 0 {
		return mains[0]
	}
	return ""
}

// GetNativeLibraries returns native library names (.so files).
func (a *APK) GetNativeLibraries() []string {
	var libs []string
	for _, name := range a.GetFileNames() {
		if strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so") {
			libs = append(libs, name)
		}
	}
	return libs
}

// GetAssetFiles returns files in the assets/ directory.
func (a *APK) GetAssetFiles() []string {
	var assets []string
	for _, name := range a.GetFileNames() {
		if strings.HasPrefix(name, "assets/") {
			assets = append(assets, name)
		}
	}
	return assets
}

// GetResourceFiles returns files in the res/ directory.
func (a *APK) GetResourceFiles() []string {
	var res []string
	for _, name := range a.GetFileNames() {
		if strings.HasPrefix(name, "res/") {
			res = append(res, name)
		}
	}
	return res
}

// HasDuplicateAPKSignatureIDs returns true if the APK has duplicate signature related IDs.
func (a *APK) HasDuplicateAPKSignatureIDs() bool {
	// Check for both v1 and v2/v3 signatures being present
	// which can sometimes indicate repackaging
	return a.IsSignedV1() && (a.IsSignedV2() || a.IsSignedV3())
}

// GetResValue resolves a resource identifier string.
func (a *APK) GetResValue(name string) string {
	if a.resourcesTable == nil || a.manifest == nil {
		return name
	}

	if strings.HasPrefix(name, "@string/") {
		// Look up string resource
		stringName := strings.TrimPrefix(name, "@string/")
		for _, pkg := range a.resourcesTable.Packages {
			for _, typ := range pkg.Types {
				if typ.Name == "string" {
					for _, entry := range typ.Entries {
						if entry.Name == stringName && entry.Value != nil {
							return arsc.GetResourceValueString(entry.Value, a.resourcesTable.StringPool)
						}
					}
				}
			}
		}
	}

	return name
}

// FindTags finds all tags matching the given name with optional attribute filters.
func (a *APK) FindTags(tagName string, attributeFilter map[string]string) []string {
	var results []string
	if a.manifest == nil {
		return results
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name != tagName {
			continue
		}

		matched := true
		for filterKey, filterVal := range attributeFilter {
			found := false
			for _, attr := range elem.Attributes {
				if attr.Name == filterKey && attr.Value == filterVal {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}

		if matched {
			// Return the element name attribute if present
			for _, attr := range elem.Attributes {
				if attr.Name == "name" {
					results = append(results, attr.Value)
					break
				}
			}
		}
	}

	return results
}

// GetTargetSdkFromResources attempts to resolve target SDK from resources.
func (a *APK) GetTargetSdkFromResources() int {
	if a.resourcesTable == nil {
		return 0
	}

	// Look for targetSdkVersion in the resource table
	for _, pkg := range a.resourcesTable.Packages {
		for _, typ := range pkg.Types {
			if typ.Name == "integer" {
				for _, entry := range typ.Entries {
					if strings.Contains(entry.Name, "targetSdkVersion") ||
						strings.Contains(entry.Name, "target_sdk_version") {
						if entry.Value != nil {
							return int(entry.Value.Data)
						}
					}
				}
			}
		}
	}

	return 0
}

// GetOverlayTarget returns the target package for overlay APKs.
func (a *APK) GetOverlayTarget() string {
	if a.manifest == nil {
		return ""
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "overlay" {
			for _, attr := range elem.Attributes {
				if attr.Name == "targetPackage" {
					return attr.Value
				}
			}
		}
	}
	return ""
}

// GetOverlayPriority returns the priority of an overlay APK.
func (a *APK) GetOverlayPriority() int {
	if a.manifest == nil {
		return 0
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "overlay" {
			for _, attr := range elem.Attributes {
				if attr.Name == "priority" {
					var v int
					if _, err := fmt.Sscanf(attr.Value, "%d", &v); err == nil {
						return v
					}
				}
			}
		}
	}
	return 0
}

// GetSplitName returns the split name for split APKs.
func (a *APK) GetSplitName() string {
	if a.manifest == nil {
		return ""
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "manifest" {
			for _, attr := range elem.Attributes {
				if attr.Name == "split" {
					return attr.Value
				}
			}
		}
	}
	return ""
}

// APKDigestAlgorithmNames maps algorithm IDs to names.
var APKDigestAlgorithmNames = map[uint32]string{
	0x0101: "SHA-256",
	0x0102: "SHA-512",
	0x0201: "SHA-256",
	0x0202: "SHA-512",
	0x0301: "SHA-256",
}

// GetDigestAlgorithmName returns the name of a digest algorithm by ID.
func GetDigestAlgorithmName(algoID uint32) string {
	if name, ok := APKDigestAlgorithmNames[algoID]; ok {
		return name
	}
	return fmt.Sprintf("unknown(0x%x)", algoID)
}

// GetSignaturesV2Digests returns v2 signature digests.
func (a *APK) GetSignaturesV2Digests() []APKDigest {
	if a.signatureBlock == nil {
		return nil
	}
	var digests []APKDigest
	for _, signer := range a.signatureBlock.V2Signers {
		digests = append(digests, signer.SignedData.Digests...)
	}
	return digests
}

// GetSignaturesV2Certs returns v2 signature certificates as raw bytes.
func (a *APK) GetSignaturesV2Certs() [][]byte {
	if a.signatureBlock == nil {
		return nil
	}
	var certs [][]byte
	for _, signer := range a.signatureBlock.V2Signers {
		certs = append(certs, signer.SignedData.Certificates...)
	}
	return certs
}

// GetAllAttributeValues returns all values for a given attribute across matching tags.
func (a *APK) GetAllAttributeValues(tagName, attrName string) []string {
	var values []string
	if a.manifest == nil {
		return values
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == tagName {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName {
					if attr.NamespaceURI == "" || attr.NamespaceURI == nsAndroid {
						if attr.Value != "" {
							values = append(values, attr.Value)
						}
					}
				}
			}
		}
	}
	return values
}

// parseColorValue parses a color resource value string.
func parseColorValue(val string) uint32 {
	if !strings.HasPrefix(val, "#") {
		return 0
	}

	hex := strings.TrimPrefix(val, "#")
	var color uint32
	switch len(hex) {
	case 3: // #RGB
		var r, g, b byte
		fmt.Sscanf(hex, "%1x%1x%1x", &r, &g, &b)
		color = binary.BigEndian.Uint32([]byte{0xFF, r | (r << 4), g | (g << 4), b | (b << 4)})
	case 4: // #ARGB
		var a, r, g, b byte
		fmt.Sscanf(hex, "%1x%1x%1x%1x", &a, &r, &g, &b)
		color = binary.BigEndian.Uint32([]byte{a | (a << 4), r | (r << 4), g | (g << 4), b | (b << 4)})
	case 6: // #RRGGBB
		fmt.Sscanf(hex, "%06x", &color)
		color |= 0xFF000000
	case 8: // #AARRGGBB
		fmt.Sscanf(hex, "%08x", &color)
	}

	return color
}
