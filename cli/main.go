// Package main provides the androguard CLI tool.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/grassto/androguard-go/core/apk"
	"github.com/grassto/androguard-go/core/axml"
	"github.com/grassto/androguard-go/core/resources"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "info":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: androguard info <apk_file>")
			os.Exit(1)
		}
		showAPKInfo(os.Args[2])

	case "axml":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: androguard axml <axml_file>")
			os.Exit(1)
		}
		showAXML(os.Args[2])

	case "arsc":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: androguard arsc <arsc_file>")
			os.Exit(1)
		}
		showARSC(os.Args[2])

	case "manifest":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: androguard manifest <apk_file>")
			os.Exit(1)
		}
		showManifest(os.Args[2])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("androguard - Android APK analysis tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  androguard info <apk_file>      Show APK information")
	fmt.Println("  androguard manifest <apk_file>  Show AndroidManifest.xml")
	fmt.Println("  androguard axml <axml_file>     Parse and show AXML file")
	fmt.Println("  androguard arsc <arsc_file>     Parse and show ARSC file")
}

func showAPKInfo(path string) {
	a, err := apk.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Package:       %s\n", a.GetPackageName())
	fmt.Printf("Version Name:  %s\n", a.GetVersionName())
	fmt.Printf("Version Code:  %s\n", a.GetVersionCode())
	fmt.Printf("Min SDK:       %s\n", a.GetMinSDKVersion())
	fmt.Printf("Target SDK:    %s\n", a.GetTargetSDKVersion())
	fmt.Printf("App Name:      %s\n", a.GetAppName())
	fmt.Printf("Activities:    %d\n", len(a.GetActivities()))
	fmt.Printf("Services:      %d\n", len(a.GetServices()))
	fmt.Printf("Receivers:     %d\n", len(a.GetReceivers()))
	fmt.Printf("Providers:     %d\n", len(a.GetProviders()))
	fmt.Printf("Permissions:   %d\n", len(a.GetPermissions()))
	fmt.Printf("DEX Files:     %d\n", len(a.GetDexFiles()))
	fmt.Printf("Certificates:  %d\n", len(a.GetCertificates()))
	fmt.Printf("Signed V1:     %v\n", a.IsSignedV1())
	fmt.Printf("Signed V2:     %v\n", a.IsSignedV2())
	fmt.Printf("Signed V3:     %v\n", a.IsSignedV3())
	fmt.Printf("Is Packed:     %v\n", a.IsPacked())
	fmt.Printf("Is Valid APK:  %v\n", a.IsValidAPK())
	fmt.Printf("Is MultiDex:   %v\n", a.IsMultiDex())

	if len(a.GetCertificates()) > 0 {
		fmt.Println("\nCertificate:")
		cert := a.GetCertificates()[0]
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer:  %s\n", cert.Issuer)
		fmt.Printf("  Valid:   %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
	}
}

func showManifest(path string) {
	a, err := apk.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(a.GetManifestXML())
}

func showAXML(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printer := axml.NewAXMLPrinter(data)

	if printer.IsPacked() {
		fmt.Println("# WARNING: AXML appears to be packed/obfuscated")
	}

	fmt.Println(printer.GetXML(true))
}

func showARSC(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	table, err := resources.ParseARSC(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ARSC: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("String Pool: %d strings\n", len(table.StringPool))
	fmt.Printf("Packages:    %d\n", len(table.Packages))

	for _, pkg := range table.Packages {
		fmt.Printf("\nPackage: %s (ID: %d)\n", pkg.Name, pkg.ID)
		fmt.Printf("  Type Strings: %d\n", len(pkg.TypeStrings))
		fmt.Printf("  Key Strings:  %d\n", len(pkg.KeyStrings))
		fmt.Printf("  Type Specs:   %d\n", len(pkg.TypeSpecs))
		fmt.Printf("  Types:        %d\n", len(pkg.Types))

		for _, typ := range pkg.Types {
			configStr := formatConfig(typ.Config)
			fmt.Printf("    %s (%d entries)%s\n", typ.Name, len(typ.Entries), configStr)
		}
	}
}

func formatConfig(config resources.ResTableConfig) string {
	parts := []string{}

	if config.MCC != 0 {
		parts = append(parts, fmt.Sprintf("mcc=%d", config.MCC))
	}
	if config.MNC != 0 {
		parts = append(parts, fmt.Sprintf("mnc=%d", config.MNC))
	}
	lang := string([]byte{config.Language[0], config.Language[1]})
	if lang != "\x00\x00" {
		parts = append(parts, fmt.Sprintf("lang=%s", strings.TrimRight(lang, "\x00")))
	}
	if config.Density != 0 {
		parts = append(parts, fmt.Sprintf("dpi=%d", config.Density))
	}

	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, ", ") + "]"
}
