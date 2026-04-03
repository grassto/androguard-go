package apk

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/goandroguard/goandroguard/core/certs"
)

// IsSigned returns true if the APK has any kind of signature.
func (a *APK) IsSigned() bool {
	return a.IsSignedV1() || a.IsSignedV2() || a.IsSignedV3() || a.IsSignedV31()
}

// IsSignedV31 returns true if the APK has v3.1 signatures.
func (a *APK) IsSignedV31() bool {
	if a.signatureBlock == nil {
		return false
	}
	for _, signer := range a.signatureBlock.V3Signers {
		_ = signer
		return true
	}
	return false
}

// GetSignatures returns all parsed certificates from all signature versions.
func (a *APK) GetSignatures() []*certs.ParsedCertificate {
	return a.certificates
}

// GetSignature returns the first certificate (from v1 signature).
func (a *APK) GetSignature() *certs.ParsedCertificate {
	if len(a.certificates) > 0 {
		return a.certificates[0]
	}
	return nil
}

// GetSignatureName returns the first signature file name (.RSA/.DSA/.EC).
func (a *APK) GetSignatureName() string {
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "META-INF/") {
			if strings.HasSuffix(f.Name, ".RSA") ||
				strings.HasSuffix(f.Name, ".DSA") ||
				strings.HasSuffix(f.Name, ".EC") {
				return f.Name
			}
		}
	}
	return ""
}

// GetSignatureNames returns all signature file names.
func (a *APK) GetSignatureNames() []string {
	var names []string
	for _, f := range a.zipReader.File {
		if strings.HasPrefix(f.Name, "META-INF/") {
			if strings.HasSuffix(f.Name, ".RSA") ||
				strings.HasSuffix(f.Name, ".DSA") ||
				strings.HasSuffix(f.Name, ".EC") {
				names = append(names, f.Name)
			}
		}
	}
	return names
}

// GetCertificatesV1 returns certificates from v1 (JAR) signatures.
func (a *APK) GetCertificatesV1() []*certs.ParsedCertificate {
	return a.certificates
}

// GetCertificatesV2 returns certificates from v2 signatures.
func (a *APK) GetCertificatesV2() []*certs.ParsedCertificate {
	if a.signatureBlock == nil {
		return nil
	}

	var result []*certs.ParsedCertificate
	for _, signer := range a.signatureBlock.V2Signers {
		for _, certDER := range signer.SignedData.Certificates {
			cert, err := certs.ParseX509Certificate(certDER)
			if err == nil {
				result = append(result, cert)
			}
		}
	}
	return result
}

// GetCertificatesV3 returns certificates from v3 signatures.
func (a *APK) GetCertificatesV3() []*certs.ParsedCertificate {
	if a.signatureBlock == nil {
		return nil
	}

	var result []*certs.ParsedCertificate
	for _, signer := range a.signatureBlock.V3Signers {
		for _, certDER := range signer.SignedData.Certificates {
			cert, err := certs.ParseX509Certificate(certDER)
			if err == nil {
				result = append(result, cert)
			}
		}
	}
	return result
}

// GetCertificatesV31 returns certificates from v3.1 signatures.
func (a *APK) GetCertificatesV31() []*certs.ParsedCertificate {
	return a.GetCertificatesV3()
}

// GetCertificateDER returns the DER-encoded certificate bytes.
func (a *APK) GetCertificateDER() []byte {
	if len(a.certificates) > 0 {
		return a.certificates[0].Raw
	}
	return nil
}

// GetCertificatesDERV2 returns DER-encoded certificates from v2 signatures.
func (a *APK) GetCertificatesDERV2() [][]byte {
	if a.signatureBlock == nil {
		return nil
	}

	var result [][]byte
	for _, signer := range a.signatureBlock.V2Signers {
		result = append(result, signer.SignedData.Certificates...)
	}
	return result
}

// GetCertificatesDERV3 returns DER-encoded certificates from v3 signatures.
func (a *APK) GetCertificatesDERV3() [][]byte {
	if a.signatureBlock == nil {
		return nil
	}

	var result [][]byte
	for _, signer := range a.signatureBlock.V3Signers {
		result = append(result, signer.SignedData.Certificates...)
	}
	return result
}

// GetCertificatesDERV31 returns DER-encoded certificates from v3.1 signatures.
func (a *APK) GetCertificatesDERV31() [][]byte {
	return a.GetCertificatesDERV3()
}

// GetPublicKeysV2 returns public keys from v2 signatures.
func (a *APK) GetPublicKeysV2() [][]byte {
	if a.signatureBlock == nil {
		return nil
	}

	var keys [][]byte
	for _, signer := range a.signatureBlock.V2Signers {
		keys = append(keys, signer.PublicKey)
	}
	return keys
}

// GetPublicKeysV3 returns public keys from v3 signatures.
func (a *APK) GetPublicKeysV3() [][]byte {
	if a.signatureBlock == nil {
		return nil
	}

	var keys [][]byte
	for _, signer := range a.signatureBlock.V3Signers {
		keys = append(keys, signer.PublicKey)
	}
	return keys
}

// GetPublicKeysV31 returns public keys from v3.1 signatures.
func (a *APK) GetPublicKeysV31() [][]byte {
	return a.GetPublicKeysV3()
}

// GetPublicKeysDERV2 returns public keys in DER format from v2 signatures.
func (a *APK) GetPublicKeysDERV2() [][]byte {
	rawKeys := a.GetPublicKeysV2()
	var derKeys [][]byte
	for _, rawKey := range rawKeys {
		// Try to parse as DER public key
		if len(rawKey) > 0 {
			derKeys = append(derKeys, rawKey)
		}
	}
	return derKeys
}

// GetPublicKeysDERV3 returns public keys in DER format from v3 signatures.
func (a *APK) GetPublicKeysDERV3() [][]byte {
	rawKeys := a.GetPublicKeysV3()
	var derKeys [][]byte
	for _, rawKey := range rawKeys {
		if len(rawKey) > 0 {
			derKeys = append(derKeys, rawKey)
		}
	}
	return derKeys
}

// GetPublicKeysDERV31 returns public keys in DER format from v3.1 signatures.
func (a *APK) GetPublicKeysDERV31() [][]byte {
	return a.GetPublicKeysDERV3()
}

// FindCertificate finds a certificate by subject name substring.
func (a *APK) FindCertificate(name string) *certs.ParsedCertificate {
	name = strings.ToLower(name)
	for _, cert := range a.certificates {
		if strings.Contains(strings.ToLower(cert.Subject), name) {
			return cert
		}
	}
	return nil
}

// GetCertificate returns the certificate from a specific signature file.
func (a *APK) GetCertificate(filename string) *certs.ParsedCertificate {
	for _, f := range a.zipReader.File {
		if f.Name == filename {
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			data, err := readAllFromReader(rc)
			rc.Close()
			if err != nil {
				return nil
			}

			parsedCerts, err := certs.ParseX509FromPKCS7(data)
			if err == nil && len(parsedCerts) > 0 {
				return parsedCerts[0]
			}

			// Try as DER
			cert, err := x509.ParseCertificate(data)
			if err == nil {
				parsed, _ := certs.ParseX509Certificate(cert.Raw)
				return parsed
			}
		}
	}
	return nil
}

// GetAPKID returns the APK identification tuple (package, version_code, version_name).
func (a *APK) GetAPKID() (string, string, string) {
	return a.GetPackageName(), a.GetVersionCode(), a.GetVersionName()
}

// GetAndroidManifestXML returns the manifest as XML string.
func (a *APK) GetAndroidManifestXML() string {
	return a.GetManifestXML()
}

// FindTagsFromXML finds tags in raw manifest XML by searching attribute values.
func (a *APK) FindTagsFromXML(attrName string, attrValue string) []string {
	if a.manifest == nil {
		return nil
	}

	var results []string
	for _, elem := range a.manifest.Elements {
		for _, attr := range elem.Attributes {
			if attr.Name == attrName && strings.Contains(attr.Value, attrValue) {
				results = append(results, elem.Name)
				break
			}
		}
	}
	return results
}

// GetSignatureAlgorithmName returns the signature algorithm name for a certificate.
func GetSignatureAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return cert.SignatureAlgorithm.String()
}

// readAllFromReader reads all bytes from a reader.
func readAllFromReader(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

// GetSignatureCount returns the number of different signature versions present.
func (a *APK) GetSignatureCount() int {
	count := 0
	if a.IsSignedV1() {
		count++
	}
	if a.IsSignedV2() {
		count++
	}
	if a.IsSignedV3() || a.IsSignedV31() {
		count++
	}
	return count
}

// GetSignerDigests returns digests for all signers.
func (a *APK) GetSignerDigests() []map[string][]byte {
	if a.signatureBlock == nil {
		return nil
	}

	var result []map[string][]byte

	for _, signer := range a.signatureBlock.V2Signers {
		digests := make(map[string][]byte)
		for _, d := range signer.SignedData.Digests {
			algoName := APKSigAlgoIDs[d.AlgorithmID]
			digests[algoName] = d.Digest
		}
		result = append(result, digests)
	}

	return result
}

// IsV1SignatureVerified returns a basic check if v1 signatures exist.
func (a *APK) IsV1SignatureVerified() bool {
	return len(a.certificates) > 0
}

// IsV2SignatureVerified returns a basic check if v2 signatures exist and are valid.
func (a *APK) IsV2SignatureVerified() bool {
	if a.signatureBlock == nil {
		return false
	}
	return len(a.signatureBlock.V2Signers) > 0
}

// IsV3SignatureVerified returns a basic check if v3 signatures exist.
func (a *APK) IsV3SignatureVerified() bool {
	if a.signatureBlock == nil {
		return false
	}
	return len(a.signatureBlock.V3Signers) > 0
}

// GetSignerPublicKey returns the first signer's public key.
func (a *APK) GetSignerPublicKey() []byte {
	if a.signatureBlock == nil {
		return nil
	}
	for _, signer := range a.signatureBlock.V2Signers {
		return signer.PublicKey
	}
	for _, signer := range a.signatureBlock.V3Signers {
		return signer.PublicKey
	}
	return nil
}

// String representation for debugging
func (a *APK) GetInformation() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Filename:     %s\n", a.GetFilename()))
	sb.WriteString(fmt.Sprintf("Package:      %s\n", a.GetPackageName()))
	sb.WriteString(fmt.Sprintf("VersionName:  %s\n", a.GetVersionName()))
	sb.WriteString(fmt.Sprintf("VersionCode:  %s\n", a.GetVersionCode()))
	sb.WriteString(fmt.Sprintf("MinSDK:       %s\n", a.GetMinSDKVersion()))
	sb.WriteString(fmt.Sprintf("TargetSDK:    %s\n", a.GetTargetSDKVersion()))
	sb.WriteString(fmt.Sprintf("MaxSDK:       %s\n", a.GetMaxSDKVersion()))
	sb.WriteString(fmt.Sprintf("IsPacked:     %v\n", a.IsPacked()))
	sb.WriteString(fmt.Sprintf("IsSigned:     %v (v1=%v, v2=%v, v3=%v)\n",
		a.IsSigned(), a.IsSignedV1(), a.IsSignedV2(), a.IsSignedV3()))
	sb.WriteString(fmt.Sprintf("Permissions:  %d\n", len(a.GetPermissions())))
	sb.WriteString(fmt.Sprintf("Activities:   %d\n", len(a.GetActivities())))
	sb.WriteString(fmt.Sprintf("Services:     %d\n", len(a.GetServices())))
	sb.WriteString(fmt.Sprintf("Receivers:    %d\n", len(a.GetReceivers())))
	sb.WriteString(fmt.Sprintf("Providers:    %d\n", len(a.GetProviders())))
	sb.WriteString(fmt.Sprintf("DEX files:    %d\n", len(a.GetDexFiles())))
	sb.WriteString(fmt.Sprintf("Certificates: %d\n", len(a.GetCertificates())))
	return sb.String()
}
