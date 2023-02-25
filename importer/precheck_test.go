// SPDX-License-Identifier: Apache-2.0

//go:build prechecks

package importer

import (
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/CycloneDX/license-scanner/licenses"
	"github.com/CycloneDX/license-scanner/normalizer"
)

func TestPreChecks(t *testing.T) {
	licenseLibrary, err := licenses.NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}

	if err := licenseLibrary.AddAll(); err != nil {
		t.Fatalf("licenseLibrary.AddAll() error = %v", err)
	}

	for _, lic := range licenseLibrary.LicenseMap {
		lic := lic
		t.Run(lic.GetID(), func(t *testing.T) {
			// Collect the primary patterns
			// Add any associated patterns to the list
			var patterns []*licenses.PrimaryPatterns
			patterns = append(patterns, lic.PrimaryPatterns...)
			patterns = append(patterns, lic.AssociatedPatterns...)

			// Test each pattern
			for _, pattern := range patterns {

				fName := path.Base(pattern.FileName)
				if fName == "license_info.json" {
					continue
				}

				if strings.Contains(lic.GetID(), "CC-") &&
					(strings.Contains(pattern.FileName, "license_title") || strings.Contains(pattern.FileName, "license_acronym")) {
					// Ignore regex only CC patterns.
					continue
				}

				if strings.HasSuffix(fName, ".template.txt") || strings.HasPrefix(fName, "license_") || strings.HasPrefix(fName, "associated_") {
					pattern := pattern
					t.Run(pattern.FileName, func(t *testing.T) {
						t.Parallel()

						// Normalize the pattern
						normalizedPatternData := normalizer.NewNormalizationData(pattern.Text, true)
						err := normalizedPatternData.NormalizeText()
						if err != nil {
							t.Errorf("pattern normalize text error: %v", err)
						}

						staticBlocks := GetStaticBlocks(normalizedPatternData)

						// Join static blocks with separator.
						normalizedPatternData.NormalizedText = strings.Join(staticBlocks, " <<regex>> ")

						dir := path.Dir(pattern.FileName)
						base := path.Base(pattern.FileName)
						var f string
						// spdx template always has suffix (and never starts with license_ or associated_
						// custom pattern requires prefix (but could also use the .template.txt suffix e.g. copied from spdx file)
						if strings.HasSuffix(fName, ".template.txt") && !(strings.HasPrefix(fName, "license_") || strings.HasPrefix(fName, "associated_")) {
							// ../precheck/<id>.json
							f = path.Join(dir, "..", "precheck", base) // sibling precheck dir
							ext := ".template.txt"
							f = f[0:len(f)-len(ext)] + ".json" // Replace .template.txt with .json
						} else {
							// prechecks_license_*.json
							f = path.Join(dir, "prechecks_"+base) // Add prefix
							ext := path.Ext(f)
							f = f[0:len(f)-len(ext)] + ".json" // Replace .txt with .json
						}
						trimmedStaticBlocks := []string{}
						for i := range staticBlocks {
							trimmed := strings.TrimSpace(staticBlocks[i])
							if len(trimmed) > 1 { // SKIP the single chars
								trimmedStaticBlocks = append(trimmedStaticBlocks, trimmed)
							}
						}
						b, err := os.ReadFile(f)
						if err != nil {
							if !os.IsNotExist(err) {
								t.Errorf("Error on ReadFile %v: %v", f, err)
							}
						} else {
							var readPreChecks licenses.LicensePreChecks
							err := json.Unmarshal(b, &readPreChecks)
							if err != nil {
								t.Errorf("Error on Unmarshal %v: %v", pattern.FileName, err)
							} else {
								if d := cmp.Diff(readPreChecks.StaticBlocks, trimmedStaticBlocks); d != "" {
									// Overwrite the file to update the StaticBlocks
									readPreChecks.StaticBlocks = trimmedStaticBlocks
									t.Errorf("Didn't get expected License: (-want, +got): %v", d)
								}
							}
						}
					})
				}
			}
		})
	}
}
