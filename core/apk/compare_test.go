package apk

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// apkPath is the test APK path
var apkPath = "../../testdata/com.test.intent_filter.apk"

func TestAPKPackageName(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if got := a.GetPackageName(); got != "com.test.intent_filter" {
		t.Errorf("GetPackageName() = %q, want %q", got, "com.test.intent_filter")
	}
}

func TestAPKVersion(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if got := a.GetVersionName(); got != "1.0" {
		t.Errorf("GetVersionName() = %q, want %q", got, "1.0")
	}
	if got := a.GetVersionCode(); got != "1" {
		t.Errorf("GetVersionCode() = %q, want %q", got, "1")
	}
}

func TestAPKSDKVersions(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if got := a.GetMinSDKVersion(); got != "19" {
		t.Errorf("GetMinSDKVersion() = %q, want %q", got, "19")
	}
	if got := a.GetTargetSDKVersion(); got != "28" {
		t.Errorf("GetTargetSDKVersion() = %q, want %q", got, "28")
	}
	// max_sdk should be empty
	if got := a.GetMaxSDKVersion(); got != "" {
		t.Errorf("GetMaxSDKVersion() = %q, want empty", got)
	}
}

func TestAPKActivities(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	want := []string{
		"com.test.intent_filter.MainActivity",
		"com.test.intent_filter.TestActivity",
	}
	got := a.GetActivities()
	sort.Strings(got)
	sort.Strings(want)
	if !equalStringSlice(got, want) {
		t.Errorf("GetActivities() = %v, want %v", got, want)
	}
}

func TestAPKServices(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	want := []string{"com.test.intent_filter.TestService"}
	got := a.GetServices()
	if !equalStringSlice(got, want) {
		t.Errorf("GetServices() = %v, want %v", got, want)
	}
}

func TestAPKReceivers(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	want := []string{"com.test.intent_filter.TestReceiver"}
	got := a.GetReceivers()
	if !equalStringSlice(got, want) {
		t.Errorf("GetReceivers() = %v, want %v", got, want)
	}
}

func TestAPKProviders(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	got := a.GetProviders()
	if len(got) != 0 {
		t.Errorf("GetProviders() = %v, want empty", got)
	}
}

func TestAPKPermissions(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	got := a.GetPermissions()
	if len(got) != 0 {
		t.Errorf("GetPermissions() = %v, want empty", got)
	}
}

func TestAPKDexNames(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	want := []string{"classes.dex"}
	got := a.GetDexNames()
	if !equalStringSlice(got, want) {
		t.Errorf("GetDexNames() = %v, want %v", got, want)
	}
	if !a.IsMultiDex() == false {
		t.Errorf("IsMultiDex() = %v, want false", a.IsMultiDex())
	}
}

func TestAPKFileCount(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	files := a.GetFileNames()
	// Python says there are 483 files
	if len(files) != 483 {
		t.Errorf("GetFileNames() count = %d, want 483", len(files))
	}
}

func TestAPKMainActivities(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	want := []string{"com.test.intent_filter.MainActivity"}
	got := a.GetMainActivities()
	sort.Strings(got)
	sort.Strings(want)
	if !equalStringSlice(got, want) {
		t.Errorf("GetMainActivities() = %v, want %v", got, want)
	}
}

func TestAPKManifestXML(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	xml := a.GetManifestXML()
	if xml == "" {
		t.Error("GetManifestXML() returned empty string")
	}
	// Check it contains expected attributes
	if !contains(xml, "com.test.intent_filter") {
		t.Error("Manifest XML doesn't contain package name")
	}
}

func TestAPKSignatures(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if a.IsSignedV1() {
		t.Error("IsSignedV1() = true, want false")
	}
	if !a.IsSignedV2() {
		t.Error("IsSignedV2() = false, want true")
	}
	if a.IsSignedV3() {
		t.Error("IsSignedV3() = true, want false")
	}
}

func TestAPKCertificates(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	certs := a.GetCertificates()
	if len(certs) == 0 {
		t.Fatal("GetCertificates() returned empty")
	}
}

func TestAPKAppName(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	got := a.GetAppName()
	if got != "intent-filter" {
		t.Errorf("GetAppName() = %q, want %q", got, "intent-filter")
	}
}

func TestAPKIsValidAPK(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !a.IsValidAPK() {
		t.Error("IsValidAPK() = false, want true")
	}
}

func TestAPKAppIcon(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	icon := a.GetAppIcon()
	if icon == "" {
		t.Error("GetAppIcon() returned empty string")
	}
	// Python says: res/mipmap-anydpi-v26/ic_launcher.xml
	if icon != "res/mipmap-anydpi-v26/ic_launcher.xml" {
		t.Errorf("GetAppIcon() = %q, want %q", icon, "res/mipmap-anydpi-v26/ic_launcher.xml")
	}
}

// TestDumpAll dumps all APK info for comparison with Python output
func TestDumpAll(t *testing.T) {
	a, err := Open(apkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	result := map[string]interface{}{
		"package":          a.GetPackageName(),
		"version_name":     a.GetVersionName(),
		"version_code":     a.GetVersionCode(),
		"app_name":         a.GetAppName(),
		"min_sdk":          a.GetMinSDKVersion(),
		"target_sdk":       a.GetTargetSDKVersion(),
		"max_sdk":          a.GetMaxSDKVersion(),
		"activities":       a.GetActivities(),
		"services":         a.GetServices(),
		"receivers":        a.GetReceivers(),
		"providers":        a.GetProviders(),
		"permissions":      a.GetPermissions(),
		"file_count":       len(a.GetFileNames()),
		"dex_names":        a.GetDexNames(),
		"is_multidex":      a.IsMultiDex(),
		"main_activities":  a.GetMainActivities(),
		"declared_perms":   a.GetDeclaredPermissions(),
		"libraries":        a.GetLibraries(),
		"features":         a.GetFeatures(),
		"app_icon":         a.GetAppIcon(),
		"is_valid_apk":     a.IsValidAPK(),
		"is_signed_v1":     a.IsSignedV1(),
		"is_signed_v2":     a.IsSignedV2(),
		"is_signed_v3":     a.IsSignedV3(),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
