// Package certs provides X.509 certificate parsing utilities for APK signature verification.
package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// ParsedCertificate represents a parsed X.509 certificate with key fields extracted.
type ParsedCertificate struct {
	Raw          []byte
	Subject      string
	Issuer       string
	SerialNumber *big.Int
	NotBefore    time.Time
	NotAfter     time.Time
	SignatureAlgo string
	PublicKeyAlgo string
	IsCA         bool
	KeyUsages    []string
	Extensions   []Extension
}

// Extension represents a certificate extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// ParseX509Certificate parses an X.509 certificate from DER-encoded bytes.
func ParseX509Certificate(derBytes []byte) (*ParsedCertificate, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("certs: parse certificate: %w", err)
	}

	pc := &ParsedCertificate{
		Raw:           derBytes,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		SignatureAlgo: signatureAlgoString(cert.SignatureAlgorithm),
		PublicKeyAlgo: cert.PublicKeyAlgorithm.String(),
		IsCA:          cert.IsCA,
	}

	// Extract key usages
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "Content Commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "Data Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "Certificate Sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		pc.KeyUsages = append(pc.KeyUsages, "CRL Sign")
	}

	// Extract extensions
	for _, ext := range cert.Extensions {
		pc.Extensions = append(pc.Extensions, Extension{
			ID:       ext.Id,
			Critical: ext.Critical,
			Value:    ext.Value,
		})
	}

	return pc, nil
}

// ParseX509FromPEM parses a certificate from PEM-encoded bytes.
func ParseX509FromPEM(pemBytes []byte) (*ParsedCertificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("certs: no PEM block found")
	}
	return ParseX509Certificate(block.Bytes)
}

// ParseX509FromPKCS7 extracts certificates from a PKCS#7 signature blob.
// This handles the common case where certificates are embedded in the PKCS#7 structure.
func ParseX509FromPKCS7(pkcs7Data []byte) ([]*ParsedCertificate, error) {
	var certs []*ParsedCertificate

	// Simple PKCS#7 certificate extraction by searching for DER-encoded certificates
	// Look for certificate headers in the PKCS#7 data
	offset := 0
	for offset < len(pkcs7Data)-4 {
		// Look for SEQUENCE tag (0x30) that starts a certificate
		if pkcs7Data[offset] == 0x30 {
			// Try to parse as certificate
			remaining := pkcs7Data[offset:]

			// Calculate length
			length, headerLen := parseDERLength(remaining)
			if length > 0 && headerLen > 0 {
				totalLen := headerLen + length
				if totalLen <= len(remaining) {
					// Try parsing this chunk as a certificate
					cert, err := x509.ParseCertificate(remaining[:totalLen])
					if err == nil && cert != nil {
						pc, err := ParseX509Certificate(remaining[:totalLen])
						if err == nil {
							certs = append(certs, pc)
							offset += totalLen
							continue
						}
					}
				}
			}
		}
		offset++
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("certs: no certificates found in PKCS#7 data")
	}

	return certs, nil
}

func parseDERLength(data []byte) (length int, headerLen int) {
	if len(data) < 2 {
		return 0, 0
	}

	// Skip tag byte
	pos := 1
	lengthByte := data[pos]
	pos++

	if lengthByte&0x80 == 0 {
		// Short form
		return int(lengthByte), pos
	}

	// Long form
	numBytes := int(lengthByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
		return 0, 0
	}

	length = 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}

	return length, pos
}

func signatureAlgoString(algo x509.SignatureAlgorithm) string {
	switch algo {
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	case x509.SHA256WithRSAPSS:
		return "SHA256WithRSAPSS"
	case x509.SHA384WithRSAPSS:
		return "SHA384WithRSAPSS"
	case x509.SHA512WithRSAPSS:
		return "SHA512WithRSAPSS"
	default:
		return fmt.Sprintf("Unknown(%d)", algo)
	}
}

// GetCertNameString formats a pkix.Name into a readable string.
func GetCertNameString(name pkix.Name, short bool) string {
	if short {
		parts := []string{}
		if len(name.Organization) > 0 {
			parts = append(parts, "O="+name.Organization[0])
		}
		if len(name.OrganizationalUnit) > 0 {
			parts = append(parts, "OU="+name.OrganizationalUnit[0])
		}
		if name.CommonName != "" {
			parts = append(parts, "CN="+name.CommonName)
		}
		return fmt.Sprintf("%v", parts)
	}
	return name.String()
}
