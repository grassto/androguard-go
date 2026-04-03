package apk

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
)

// OpenFile opens and parses an APK file from the given filesystem path.
func OpenFile(path string) (*APK, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("apk: read file: %w", err)
	}

	a := &APK{filename: path, raw: data}

	// Open as ZIP
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("apk: open zip: %w", err)
	}
	a.zipReader = reader

	// Initialize all parsers
	if err := a.initialize(); err != nil {
		return nil, err
	}

	return a, nil
}
