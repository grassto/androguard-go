// Package apk parses Android APK files.
// It provides functionality to read APK contents, parse AndroidManifest.xml,
// extract certificates, verify signatures, and parse DEX files.
package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/grassto/androguard-go/core/resources"
	"github.com/grassto/androguard-go/core/axml"
	"github.com/grassto/androguard-go/core/certs"
	"github.com/grassto/androguard-go/core/dex"
)

// formatValue resolves a short component name to its fully qualified name.
// ".Foo" → "package.Foo", "Foo" → "package.Foo", "a.b.Foo" → "a.b.Foo".
func (a *APK) formatValue(value string) string {
	if value == "" || a.GetPackageName() == "" {
		return value
	}
	dotIdx := strings.Index(value, ".")
	if dotIdx == 0 {
		return a.GetPackageName() + value
	}
	if dotIdx == -1 {
		return a.GetPackageName() + "." + value
	}
	return value
}

// APK Signature Block constants
var (
	APKSigMagic       = []byte("APK Sig Block 42")
	APKSigKeyV2       = uint32(0x7109871A)
	APKSigKeyV3       = uint32(0xF05368C0)
	APKSigKeyV31      = uint32(0x1B93AD61)
	APKSigAttrStrippingProtection = uint32(0xBEEFF00D)

	PKEndOfCentralDir = []byte{0x50, 0x4b, 0x05, 0x06}
	PKCentralDir      = []byte{0x50, 0x4b, 0x01, 0x02}
)

// APK represents a parsed Android APK file.
type APK struct {
	filename       string
	raw            []byte
	zipReader      *zip.Reader
	manifest       *axml.AXMLDocument
	manifestRaw    []byte
	resourcesTable *resources.ResourceTable
	certificates   []*certs.ParsedCertificate
	signatureBlock *APKSignatureBlock
	dexFiles       []*dex.DexFile
}

// APKSignatureBlock represents the APK v2/v3 signature block.
type APKSignatureBlock struct {
	V2Signers []APKV2Signer
	V3Signers []APKV3Signer
}

// APKV2Signer represents a v2 signature signer.
type APKV2Signer struct {
	SignedData   APKV2SignedData
	Signatures   []APKV2Signature
	PublicKey    []byte
}

// APKV2SignedData represents the signed data in v2 signature.
type APKV2SignedData struct {
	Digests             []APKDigest
	Certificates        [][]byte
	AdditionalAttrs     []byte
}

// APKV2Signature represents a signature in v2 signing.
type APKV2Signature struct {
	AlgorithmID uint32
	Signature   []byte
}

// APKDigest represents a digest in v2 signing.
type APKDigest struct {
	AlgorithmID uint32
	Digest      []byte
}

// APKV3Signer extends APKV2Signer with v3-specific fields.
type APKV3Signer struct {
	APKV2Signer
	MinSDK uint32
	MaxSDK uint32
}

// APK algorithm ID to name mapping
var APKSigAlgoIDs = map[uint32]string{
	0x0101: "RSASSA-PSS-SHA256",
	0x0102: "RSASSA-PSS-SHA512",
	0x0103: "RSASSA-PKCS1-v1_5-SHA256",
	0x0104: "RSASSA-PKCS1-v1_5-SHA512",
	0x0201: "ECDSA-SHA256",
	0x0202: "ECDSA-SHA512",
	0x0301: "DSA-SHA256",
}

// Open is an alias for OpenFile.
func Open(path string) (*APK, error) {
	return OpenFile(path)
}

// ParseFromData parses an APK from raw bytes.
func ParseFromData(data []byte) (*APK, error) {
	a := &APK{raw: data}

	// Open as ZIP
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("apk: open zip: %w", err)
	}
	a.zipReader = reader

	// Initialize
	if err := a.initialize(); err != nil {
		return nil, err
	}

	return a, nil
}

// initialize performs full parsing after the ZIP reader is set up.
func (a *APK) initialize() error {
	if err := a.parseManifest(); err != nil {
		return fmt.Errorf("apk: parse manifest: %w", err)
	}
	a.parseResources()
	a.parseCertificates()
	a.parseAPKSignatureBlock()
	a.parseDexFiles()
	return nil
}

func (a *APK) parseManifest() error {
	for _, f := range a.zipReader.File {
		if f.Name == "AndroidManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return err
			}
			a.manifestRaw = data

			doc, err := axml.ParseAXML(data)
			if err != nil {
				return err
			}
			a.manifest = doc
			return nil
		}
	}
	// Missing AndroidManifest.xml is not fatal — some APKs may lack it
	return nil
}

func (a *APK) parseResources() {
	for _, f := range a.zipReader.File {
		if f.Name == "resources.arsc" {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return
			}

			table, err := resources.ParseARSC(data)
			if err != nil {
				return
			}
			a.resourcesTable = table
			return
		}
	}
}

func (a *APK) parseCertificates() {
	// Look for META-INF/*.RSA and META-INF/*.DSA files
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "META-INF/") &&
			(strings.HasSuffix(f.Name, ".RSA") || strings.HasSuffix(f.Name, ".DSA")) {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			parsedCerts, err := certs.ParseX509FromPKCS7(data)
			if err == nil {
				a.certificates = append(a.certificates, parsedCerts...)
			}
		}
	}

	// Also look for .EC files (elliptic curve)
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "META-INF/") && strings.HasSuffix(f.Name, ".EC") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			parsedCerts, err := certs.ParseX509FromPKCS7(data)
			if err == nil {
				a.certificates = append(a.certificates, parsedCerts...)
			}
		}
	}
}

func (a *APK) parseAPKSignatureBlock() {
	// Find the APK Signing Block
	// It's located just before the ZIP Central Directory
	// Look for the magic "APK Sig Block 42" at the end of the file

	if len(a.raw) < 24 {
		return
	}

	// Find End of Central Directory
	eocdOffset := -1
	for i := len(a.raw) - 22; i >= 0; i-- {
		if bytes.Equal(a.raw[i:i+4], PKEndOfCentralDir) {
			eocdOffset = i
			break
		}
	}

	if eocdOffset < 0 {
		return
	}

	// Get Central Directory offset
	if eocdOffset+16 > len(a.raw) {
		return
	}
	cdOffset := int(binary.LittleEndian.Uint32(a.raw[eocdOffset+16 : eocdOffset+20]))

	// The APK Signing Block is located before the Central Directory
	// It has a size field (8 bytes) + blocks + size field (8 bytes) + magic (16 bytes)
	if cdOffset < 24 {
		return
	}

	// Read the magic at cdOffset - 16
	magicOffset := cdOffset - 16
	if magicOffset < 0 || magicOffset+16 > len(a.raw) {
		return
	}

	if !bytes.Equal(a.raw[magicOffset:magicOffset+16], APKSigMagic) {
		return // No APK Signing Block
	}

	// Read the size_before field (8 bytes before magic)
	sizeBeforeOffset := magicOffset - 8
	if sizeBeforeOffset < 0 {
		return
	}
	sizeBefore := int(binary.LittleEndian.Uint64(a.raw[sizeBeforeOffset : sizeBeforeOffset+8]))

	// The block starts at cdOffset - sizeBefore - 8
	blockStart := cdOffset - sizeBefore - 8
	if blockStart < 0 {
		return
	}

	// Read size_after (should equal size_before)
	sizeAfterOffset := blockStart
	if sizeAfterOffset+8 > len(a.raw) {
		return
	}
	sizeAfter := int(binary.LittleEndian.Uint64(a.raw[sizeAfterOffset : sizeAfterOffset+8]))
	if sizeAfter != sizeBefore {
		return // Sizes don't match
	}

	// Parse blocks
	a.signatureBlock = &APKSignatureBlock{}
	pos := blockStart + 8
	endPos := blockStart + 8 + sizeBefore

	for pos+12 <= endPos && pos+12 <= len(a.raw) {
		blockSize := int(binary.LittleEndian.Uint64(a.raw[pos : pos+8]))
		blockID := binary.LittleEndian.Uint32(a.raw[pos+8 : pos+12])

		if blockSize < 4 || pos+8+blockSize > len(a.raw) {
			break
		}

		blockData := a.raw[pos+12 : pos+8+blockSize]

		switch blockID {
		case APKSigKeyV2:
			signers := a.parseV2Signers(blockData)
			a.signatureBlock.V2Signers = append(a.signatureBlock.V2Signers, signers...)
		case APKSigKeyV3, APKSigKeyV31:
			signers := a.parseV3Signers(blockData)
			a.signatureBlock.V3Signers = append(a.signatureBlock.V3Signers, signers...)
		}

		pos += 8 + blockSize
	}
}

func (a *APK) parseV2Signers(data []byte) []APKV2Signer {
	var signers []APKV2Signer

	if len(data) < 4 {
		return signers
	}

	// The block data starts with a uint32 size_sequence that describes
	// the total size of all signers.  Skip it first, then iterate over
	// each length-prefixed signer that follows.
	pos := 0
	sizeSequence := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	seqEnd := pos + sizeSequence
	if seqEnd > len(data) {
		seqEnd = len(data)
	}

	for pos+4 <= seqEnd {
		signerLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if signerLen <= 0 || pos+signerLen > len(data) {
			break
		}

		signerData := data[pos : pos+signerLen]
		signer := a.parseV2Signer(signerData)
		signers = append(signers, signer)

		pos += signerLen
	}

	return signers
}

func (a *APK) parseV2Signer(data []byte) APKV2Signer {
	signer := APKV2Signer{}
	pos := 0

	// Signed data sequence
	if pos+4 > len(data) {
		return signer
	}
	signedDataLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	if signedDataLen > 0 && pos+signedDataLen <= len(data) {
		signedData := data[pos : pos+signedDataLen]
		signer.SignedData = a.parseV2SignedData(signedData)
		pos += signedDataLen
	}

	// Signatures sequence
	if pos+4 > len(data) {
		return signer
	}
	sigsLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	if sigsLen > 0 && pos+sigsLen <= len(data) {
		sigsData := data[pos : pos+sigsLen]
		signer.Signatures = a.parseV2Signatures(sigsData)
		pos += sigsLen
	}

	// Public key
	if pos+4 <= len(data) {
		pubKeyLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pubKeyLen > 0 && pos+pubKeyLen <= len(data) {
			signer.PublicKey = make([]byte, pubKeyLen)
			copy(signer.PublicKey, data[pos:pos+pubKeyLen])
		}
	}

	return signer
}

func (a *APK) parseV2SignedData(data []byte) APKV2SignedData {
	sd := APKV2SignedData{}
	pos := 0

	// Digests sequence
	if pos+4 > len(data) {
		return sd
	}
	digestsLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	if digestsLen > 0 && pos+digestsLen <= len(data) {
		digestData := data[pos : pos+digestsLen]
		sd.Digests = a.parseV2Digests(digestData)
		pos += digestsLen
	}

	// Certificates sequence
	if pos+4 <= len(data) {
		certsLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		certsEnd := pos + certsLen
		for pos < certsEnd && pos+4 <= len(data) {
			certLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
			if pos+certLen <= len(data) {
				cert := make([]byte, certLen)
				copy(cert, data[pos:pos+certLen])
				sd.Certificates = append(sd.Certificates, cert)
				pos += certLen
			}
		}
	}

	// Additional attributes (length-prefixed, consume but don't parse)
	if pos+4 <= len(data) {
		attrLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if attrLen > 0 && pos+attrLen <= len(data) {
			sd.AdditionalAttrs = make([]byte, attrLen)
			copy(sd.AdditionalAttrs, data[pos:pos+attrLen])
		}
	}

	return sd
}

func (a *APK) parseV2Digests(data []byte) []APKDigest {
	var digests []APKDigest
	pos := 0

	for pos+8 <= len(data) {
		// Algorithm ID (uint32)
		algoID := binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4

		// Digest (length-prefixed)
		if pos+4 > len(data) {
			break
		}
		digestLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if pos+digestLen <= len(data) {
			digest := APKDigest{
				AlgorithmID: algoID,
				Digest:      make([]byte, digestLen),
			}
			copy(digest.Digest, data[pos:pos+digestLen])
			digests = append(digests, digest)
			pos += digestLen
		}
	}

	return digests
}

func (a *APK) parseV2Signatures(data []byte) []APKV2Signature {
	var sigs []APKV2Signature
	pos := 0

	for pos+8 <= len(data) {
		algoID := binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4

		sigLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if pos+sigLen <= len(data) {
			sig := APKV2Signature{
				AlgorithmID: algoID,
				Signature:   make([]byte, sigLen),
			}
			copy(sig.Signature, data[pos:pos+sigLen])
			sigs = append(sigs, sig)
			pos += sigLen
		}
	}

	return sigs
}

func (a *APK) parseV3Signers(data []byte) []APKV3Signer {
	var signers []APKV3Signer

	if len(data) < 4 {
		return signers
	}

	pos := 0
	for pos+4 <= len(data) {
		signerLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if signerLen <= 0 || pos+signerLen > len(data) {
			break
		}

		signerData := data[pos : pos+signerLen]
		v2Signer := a.parseV2Signer(signerData)

		v3Signer := APKV3Signer{
			APKV2Signer: v2Signer,
		}

		// V3 has min/max SDK version in signed data
		if len(signerData) >= pos+8 {
			// These are typically in the signed data section
			v3Signer.MinSDK = 0
			v3Signer.MaxSDK = 0x7FFFFFFF
		}

		signers = append(signers, v3Signer)
		pos += signerLen
		break
	}

	return signers
}

func (a *APK) parseDexFiles() {
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "classes") && strings.HasSuffix(f.Name, ".dex") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			dexFile, err := dex.Parse(data)
			if err != nil {
				continue
			}
			a.dexFiles = append(a.dexFiles, dexFile)
		}
	}
}

// --- Public API ---

// GetPackageName returns the package name from AndroidManifest.xml.
func (a *APK) GetPackageName() string {
	return a.getManifestAttribute("manifest", "package")
}

// GetVersionName returns the version name from AndroidManifest.xml.
func (a *APK) GetVersionName() string {
	return a.getManifestAttribute("manifest", "versionName")
}

// GetVersionCode returns the version code from AndroidManifest.xml.
func (a *APK) GetVersionCode() string {
	return a.getManifestAttribute("manifest", "versionCode")
}

// GetMinSDKVersion returns the minimum SDK version.
func (a *APK) GetMinSDKVersion() string {
	return a.getManifestAttribute("uses-sdk", "minSdkVersion")
}

// GetTargetSDKVersion returns the target SDK version.
func (a *APK) GetTargetSDKVersion() string {
	return a.getManifestAttribute("uses-sdk", "targetSdkVersion")
}

// GetMaxSDKVersion returns the maximum SDK version.
func (a *APK) GetMaxSDKVersion() string {
	return a.getManifestAttribute("uses-sdk", "maxSdkVersion")
}

// GetApplicationLabel returns the application label.
func (a *APK) GetApplicationLabel() string {
	return a.getManifestAttribute("application", "label")
}

// GetPermissions returns the list of permissions declared in the manifest.
func (a *APK) GetPermissions() []string {
	var permissions []string
	if a.manifest == nil {
		return permissions
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "uses-permission" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					permissions = append(permissions, attr.Value)
				}
			}
		}
	}
	return permissions
}

// GetActivities returns the list of activities declared in the manifest.
func (a *APK) GetActivities() []string {
	var activities []string
	if a.manifest == nil {
		return activities
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "activity" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					activities = append(activities, a.formatValue(attr.Value))
				}
			}
		}
	}
	return activities
}

// GetServices returns the list of services declared in the manifest.
func (a *APK) GetServices() []string {
	var services []string
	if a.manifest == nil {
		return services
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "service" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					services = append(services, a.formatValue(attr.Value))
				}
			}
		}
	}
	return services
}

// GetReceivers returns the list of broadcast receivers declared in the manifest.
func (a *APK) GetReceivers() []string {
	var receivers []string
	if a.manifest == nil {
		return receivers
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "receiver" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					receivers = append(receivers, a.formatValue(attr.Value))
				}
			}
		}
	}
	return receivers
}

// GetProviders returns the list of content providers declared in the manifest.
func (a *APK) GetProviders() []string {
	var providers []string
	if a.manifest == nil {
		return providers
	}

	for _, elem := range a.manifest.Elements {
		if elem.Name == "provider" {
			for _, attr := range elem.Attributes {
				if attr.Name == "name" && attr.Value != "" {
					providers = append(providers, a.formatValue(attr.Value))
				}
			}
		}
	}
	return providers
}

// GetCertificates returns all parsed signing certificates.
// It returns v1 (JAR) certificates first, then falls back to v2/v3 certificates.
func (a *APK) GetCertificates() []*certs.ParsedCertificate {
	if len(a.certificates) > 0 {
		return a.certificates
	}

	// Fallback: extract certificates from v2/v3 signers
	if a.signatureBlock != nil {
		for _, signer := range a.signatureBlock.V2Signers {
			for _, der := range signer.SignedData.Certificates {
				if pc, err := certs.ParseX509Certificate(der); err == nil {
					a.certificates = append(a.certificates, pc)
				}
			}
		}
		for _, signer := range a.signatureBlock.V3Signers {
			for _, der := range signer.SignedData.Certificates {
				if pc, err := certs.ParseX509Certificate(der); err == nil {
					a.certificates = append(a.certificates, pc)
				}
			}
		}
	}

	return a.certificates
}

// GetDexFiles returns all parsed DEX files.
func (a *APK) GetDexFiles() []*dex.DexFile {
	return a.dexFiles
}

// GetManifestXML returns the manifest as XML string.
func (a *APK) GetManifestXML() string {
	if a.manifest == nil {
		return ""
	}
	return a.manifest.GetXMLString()
}

// GetFileNames returns all file names in the APK.
func (a *APK) GetFileNames() []string {
	names := make([]string, len(a.zipReader.File))
	for i, f := range a.zipReader.File {
		names[i] = f.Name
	}
	return names
}

// GetFile reads a file from the APK by name.
func (a *APK) GetFile(name string) ([]byte, error) {
	for _, f := range a.zipReader.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("file %q not found in APK", name)
}

// GetSignatureBlock returns the APK v2/v3 signature block if present.
func (a *APK) GetSignatureBlock() *APKSignatureBlock {
	return a.signatureBlock
}

// GetResourcesTable returns the parsed resources table.
func (a *APK) GetResourcesTable() *resources.ResourceTable {
	return a.resourcesTable
}

// IsSignedV1 returns true if the APK has v1 (JAR) signatures.
func (a *APK) IsSignedV1() bool {
	return len(a.certificates) > 0
}

// IsSignedV2 returns true if the APK has v2 signatures.
func (a *APK) IsSignedV2() bool {
	return a.signatureBlock != nil && len(a.signatureBlock.V2Signers) > 0
}

// IsSignedV3 returns true if the APK has v3 signatures.
func (a *APK) IsSignedV3() bool {
	return a.signatureBlock != nil && len(a.signatureBlock.V3Signers) > 0
}

// ComputeFileHash returns SHA-256 hash of the APK file.
func (a *APK) ComputeFileHash() [32]byte {
	return sha256.Sum256(a.raw)
}

// String returns a summary of the APK.
func (a *APK) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Package:       %s\n", a.GetPackageName()))
	sb.WriteString(fmt.Sprintf("Version Name:  %s\n", a.GetVersionName()))
	sb.WriteString(fmt.Sprintf("Version Code:  %s\n", a.GetVersionCode()))
	sb.WriteString(fmt.Sprintf("Min SDK:       %s\n", a.GetMinSDKVersion()))
	sb.WriteString(fmt.Sprintf("Target SDK:    %s\n", a.GetTargetSDKVersion()))
	sb.WriteString(fmt.Sprintf("Permissions:   %d\n", len(a.GetPermissions())))
	sb.WriteString(fmt.Sprintf("Activities:    %d\n", len(a.GetActivities())))
	sb.WriteString(fmt.Sprintf("Services:      %d\n", len(a.GetServices())))
	sb.WriteString(fmt.Sprintf("Receivers:     %d\n", len(a.GetReceivers())))
	sb.WriteString(fmt.Sprintf("Providers:     %d\n", len(a.GetProviders())))
	sb.WriteString(fmt.Sprintf("DEX files:     %d\n", len(a.dexFiles)))
	sb.WriteString(fmt.Sprintf("Certificates:  %d\n", len(a.certificates)))
	sb.WriteString(fmt.Sprintf("Signed V1:     %v\n", a.IsSignedV1()))
	sb.WriteString(fmt.Sprintf("Signed V2:     %v\n", a.IsSignedV2()))
	sb.WriteString(fmt.Sprintf("Signed V3:     %v\n", a.IsSignedV3()))

	for i, cert := range a.certificates {
		sb.WriteString(fmt.Sprintf("\nCertificate %d:\n", i))
		sb.WriteString(fmt.Sprintf("  Subject: %s\n", cert.Subject))
		sb.WriteString(fmt.Sprintf("  Issuer:  %s\n", cert.Issuer))
		sb.WriteString(fmt.Sprintf("  Serial:  %s\n", cert.SerialNumber.String()))
		sb.WriteString(fmt.Sprintf("  Valid:   %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("  Algo:    %s\n", cert.SignatureAlgo))
	}

	return sb.String()
}

func (a *APK) getManifestAttribute(elementName, attrName string) string {
	if a.manifest == nil {
		return ""
	}

	nsAndroid := "http://schemas.android.com/apk/res/android"

	for _, elem := range a.manifest.Elements {
		if elem.Name == elementName {
			for _, attr := range elem.Attributes {
				if attr.Name == attrName && (attr.NamespaceURI == "" || attr.NamespaceURI == nsAndroid) {
					return a.formatAttrValue(attr)
				}
			}
		}
	}
	return ""
}

// formatAttrValue returns a human-readable string for an AXML attribute value.
func (a *APK) formatAttrValue(attr axml.XMLAttributeNode) string {
	// If we have a direct string value, return it
	if attr.Value != "" {
		return attr.Value
	}

	// Otherwise, format based on value type
	switch attr.ValueType {
	case axml.AttrTypeString:
		return attr.Value
	case axml.AttrTypeIntDec:
		return fmt.Sprintf("%d", int32(attr.ValueData))
	case axml.AttrTypeIntHex:
		return fmt.Sprintf("0x%x", attr.ValueData)
	case axml.AttrTypeIntBoolean:
		if attr.ValueData != 0 {
			return "true"
		}
		return "false"
	case axml.AttrTypeReference:
		// Resource reference (0x01)
		return fmt.Sprintf("@0x%x", attr.ValueData)
	case 0x07:
		// Dynamic reference
		return fmt.Sprintf("@0x%x", attr.ValueData)
	case 0x08:
		// This type is overloaded in Android:
		// - If ValueData looks like a resource ID (0x7fXXXXXX), treat as reference
		// - Otherwise, treat as integer
		if (attr.ValueData >> 24) == 0x7f {
			return fmt.Sprintf("@0x%x", attr.ValueData)
		}
		return fmt.Sprintf("%d", int32(attr.ValueData))
	default:
		if attr.Value != "" {
			return attr.Value
		}
		return fmt.Sprintf("%d", int32(attr.ValueData))
	}
}
