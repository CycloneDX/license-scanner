// SPDX-License-Identifier: Apache-2.0

//go:build prechecks

package importer

import (
	"encoding/json"
	"flag"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

var fix = flag.Bool("fix", false, "Write/update precheck files if needed.")

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
							} else {
								if *fix {
									// Write a new file. This was done to create the files from embedded prechecks.
									if err := WritePreChecksFile(trimmedStaticBlocks, f); err != nil {
										t.Errorf("Error writing new file %v: %v", f, err)
									}
									t.Skipf("Wrote new file %v", f)
								}
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
									if *fix {
										// Write a new file. This was done to create the files from embedded preChecks.
										if err := WritePreChecksFile(readPreChecks.StaticBlocks, f); err != nil {
											t.Errorf("Error writing file %v: %v", f, err)
										}
										t.Errorf("Updated file %v", f)
									}
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
