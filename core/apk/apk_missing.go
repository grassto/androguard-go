package apk

import (
	"io"
	"strings"

	"github.com/grassto/androguard-go/core/axml"
	"github.com/grassto/androguard-go/core/dex"
	"github.com/grassto/androguard-go/core/resources"
)

// --- Missing methods from Python androguard APK class ---

// GetFilename returns the APK filename.
func (a *APK) GetFilename() string {
	return a.filename
}

// GetDex returns the bytes of the main (first) DEX file.
func (a *APK) GetDex() []byte {
	for _, f := range a.zipReader.File {
		if f.Name == "classes.dex" {
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil
			}
			return data
		}
	}
	return nil
}

// GetAllDex returns an iterator-like slice of all DEX file bytes.
func (a *APK) GetAllDex() [][]byte {
	var dexFiles [][]byte
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "classes") && strings.HasSuffix(f.Name, ".dex") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err == nil && data != nil {
				dexFiles = append(dexFiles, data)
			}
		}
	}
	return dexFiles
}

// GetAndroidManifestAXML returns the AXMLPrinter for the manifest.
func (a *APK) GetAndroidManifestAXML() *axml.AXMLPrinter {
	if a.manifestRaw == nil {
		return nil
	}
	return axml.NewAXMLPrinter(a.manifestRaw)
}

// GetAndroidResources returns the parsed ARSC resource table.
func (a *APK) GetAndroidResources() *resources.ResourceTable {
	return a.resourcesTable
}

// GetRaw returns the raw APK bytes.
func (a *APK) GetRaw() []byte {
	return a.raw
}

// GetDexFile returns the parsed DexFile at the given index.
func (a *APK) GetDexFile(idx int) *dex.DexFile {
	if idx < 0 || idx >= len(a.dexFiles) {
		return nil
	}
	return a.dexFiles[idx]
}

// GetUsesImpliedPermissionList returns permissions implied by uses-features.
func (a *APK) GetUsesImpliedPermissionList() []string {
	var implied []string
	features := a.GetFeatures()
	minSDK := a.GetMinSDKVersion()
	targetSDK := a.GetTargetSDKVersion()

	// Map features to implied permissions
	featurePermMap := map[string]string{
		"android.hardware.camera":                  "android.permission.CAMERA",
		"android.hardware.location":                "android.permission.ACCESS_FINE_LOCATION",
		"android.hardware.location.gps":            "android.permission.ACCESS_FINE_LOCATION",
		"android.hardware.location.network":        "android.permission.ACCESS_COARSE_LOCATION",
		"android.hardware.bluetooth":               "android.permission.BLUETOOTH",
		"android.hardware.bluetooth_le":            "android.permission.BLUETOOTH",
		"android.hardware.nfc":                     "android.permission.NFC",
		"android.hardware.sensor.accelerometer":    "android.permission.BODY_SENSORS",
		"android.hardware.sensor.compass":          "android.permission.BODY_SENSORS",
		"android.hardware.sensor.gyroscope":        "android.permission.BODY_SENSORS",
		"android.hardware.sensor.proximity":        "android.permission.BODY_SENSORS",
		"android.hardware.sensor.light":            "android.permission.BODY_SENSORS",
		"android.hardware.sensor.barometer":        "android.permission.BODY_SENSORS",
		"android.hardware.telephony":               "android.permission.READ_PHONE_STATE",
		"android.hardware.wifi":                    "android.permission.ACCESS_WIFI_STATE",
		"android.hardware.touchscreen":             "",
		"android.hardware.microphone":              "android.permission.RECORD_AUDIO",
	}

	for _, feature := range features {
		if perm, ok := featurePermMap[feature]; ok && perm != "" {
			// Check if permission is already declared
			alreadyDeclared := false
			for _, p := range a.GetPermissions() {
				if p == perm {
					alreadyDeclared = true
					break
				}
			}
			if !alreadyDeclared {
				implied = append(implied, perm)
			}
		}
	}

	// Handle SDK version implications
	_ = minSDK
	_ = targetSDK

	return implied
}

// GetRequestedAOSPPermissions returns AOSP (Android Open Source Project) permissions.
func (a *APK) GetRequestedAOSPPermissions() []string {
	var aospPerms []string
	allPerms := a.GetPermissions()

	for _, perm := range allPerms {
		if strings.HasPrefix(perm, "android.permission.") {
			aospPerms = append(aospPerms, perm)
		}
	}

	return aospPerms
}

// GetRequestedAOSPPermissionsDetails returns detailed AOSP permissions.
func (a *APK) GetRequestedAOSPPermissionsDetails() map[string][]string {
	result := make(map[string][]string)
	details := a.GetDetailsPermissions()

	for perm, info := range details {
		if strings.HasPrefix(perm, "android.permission.") {
			result[perm] = info
		}
	}

	return result
}

// GetRequestedThirdPartyPermissions returns third-party (non-AOSP) permissions.
func (a *APK) GetRequestedThirdPartyPermissions() []string {
	var thirdParty []string
	allPerms := a.GetPermissions()

	for _, perm := range allPerms {
		if !strings.HasPrefix(perm, "android.permission.") &&
			!strings.HasPrefix(perm, "com.google.android.") {
			thirdParty = append(thirdParty, perm)
		}
	}

	return thirdParty
}

// GetDeclaredPermissionsDetails returns detailed declared permissions.
func (a *APK) GetDeclaredPermissionsDetails() map[string][]string {
	result := make(map[string][]string)
	if a.manifest == nil {
		return result
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == "permission" {
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

// IsAndroidTV returns true if the app targets Android TV.
func (a *APK) IsAndroidTV() bool {
	// Check for leanback feature
	for _, f := range a.GetFeatures() {
		if f == "android.software.leanback" {
			return true
		}
	}

	// Check for TV launcher category
	if a.manifest != nil {
		for _, elem := range a.manifest.Elements {
			if elem.Name == "category" {
				for _, attr := range elem.Attributes {
					if attr.Name == "name" && attr.Value == "android.intent.category.LEANBACK_LAUNCHER" {
						return true
					}
				}
			}
		}
	}

	return false
}

// GetFilesInformation returns file information tuples (name, type, size).
func (a *APK) GetFilesInformation() []FileInfo {
	var files []FileInfo
	types := a.GetFilesTypes()

	for _, f := range a.zipReader.File {
		fi := FileInfo{
			Name: f.Name,
			Type: types[f.Name],
			Size: f.UncompressedSize64,
		}
		files = append(files, fi)
	}

	return files
}

// FileInfo holds file information from the APK.
type FileInfo struct {
	Name string
	Type string
	Size uint64
}

// GetAttributeValue returns the first value of an attribute in a tag.
func (a *APK) GetAttributeValue(tagName, attrName string) string {
	if a.manifest == nil {
		return ""
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == tagName {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName {
					if attr.NamespaceURI == "" || attr.NamespaceURI == nsAndroid {
						return attr.Value
					}
				}
			}
		}
	}

	return ""
}

// GetValueFromTag returns a value from a nested tag structure.
func (a *APK) GetValueFromTag(parentTag, childTag, attrName string) string {
	if a.manifest == nil {
		return ""
	}

	inParent := false
	for _, elem := range a.manifest.Elements {
		if elem.Name == parentTag {
			inParent = true
			continue
		}

		if inParent && elem.Name == childTag {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName {
					return attr.Value
				}
			}
			inParent = false
		}

		if elem.Name == parentTag {
			inParent = false
		}
	}

	return ""
}

// IsTagMatched checks if a tag matches the given attribute filters.
func (a *APK) IsTagMatched(tagName string, attributeFilter map[string]string) bool {
	if a.manifest == nil {
		return false
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name != tagName {
			continue
		}

		matched := true
		for filterKey, filterVal := range attributeFilter {
			found := false
			for _, attr := range elem.Attributes {
				if attr.Name == filterKey && (attr.NamespaceURI == "" || attr.NamespaceURI == nsAndroid) {
					if attr.Value == filterVal {
						found = true
						break
					}
				}
			}
			if !found {
				matched = false
				break
			}
		}

		if matched {
			return true
		}
	}

	return false
}

// GetMainActivityFromXML returns main activities parsed from raw manifest XML.
func (a *APK) GetMainActivityFromXML() []string {
	var activities []string
	if a.manifest == nil {
		return activities
	}

	intentFilters := a.GetIntentFilters("activity")
	for component, filters := range intentFilters {
		for _, filter := range filters {
			if filter["action"] == "android.intent.action.MAIN" &&
				filter["category"] == "android.intent.category.LAUNCHER" {
				activities = append(activities, component)
				break
			}
		}
	}

	return activities
}

// GetPackageFromXML returns the package name from raw XML attribute lookup.
func (a *APK) GetPackageFromXML() string {
	return a.GetAttributeValue("manifest", "package")
}

// GetVersionCodeFromXML returns version code from raw XML.
func (a *APK) GetVersionCodeFromXML() string {
	return a.GetAttributeValue("manifest", "versionCode")
}

// GetVersionNameFromXML returns version name from raw XML.
func (a *APK) GetVersionNameFromXML() string {
	return a.GetAttributeValue("manifest", "versionName")
}

// GetAllFiles returns all files in the APK as a map of name -> type.
func (a *APK) GetAllFiles() map[string]string {
	return a.GetFilesTypes()
}

// GetWearableFeatures returns features related to wearables.
func (a *APK) GetWearableFeatures() []string {
	var wearable []string
	for _, f := range a.GetFeatures() {
		if strings.Contains(f, "watch") || strings.Contains(f, "wearable") {
			wearable = append(wearable, f)
		}
	}
	return wearable
}

// GetTVFeatures returns features related to TV.
func (a *APK) GetTVFeatures() []string {
	var tv []string
	for _, f := range a.GetFeatures() {
		if strings.Contains(f, "leanback") || strings.Contains(f, "television") {
			tv = append(tv, f)
		}
	}
	return tv
}

// GetAutomotiveFeatures returns features related to Android Auto.
func (a *APK) GetAutomotiveFeatures() []string {
	var auto []string
	for _, f := range a.GetFeatures() {
		if strings.Contains(f, "automotive") || strings.Contains(f, "car") {
			auto = append(auto, f)
		}
	}
	return auto
}
