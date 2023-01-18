// SPDX-License-Identifier: Apache-2.0

//go:build unit

package identifier

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IBM/license-scanner/licenses"
)

const (
	resources = "../resources"
	spdx      = "default"
)

var testDataDir = path.Join(resources, "spdx", spdx, "testdata")
var options = Options{
	ForceResult: false,
	Enhancements: Enhancements{
		AddNotes:       "",
		AddTextBlocks:  true,
		FlagAcceptable: false,
		FlagCopyrights: true,
		FlagKeywords:   false,
	},
}

func Test_identifyLicensesInSPDXTestDataDirectory(t *testing.T) {
	t.Parallel()
	licenseLibrary, err := licenses.NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}
	if err := licenseLibrary.AddAllSPDX(); err != nil {
		t.Fatalf("licenseLibrary.AddAllSPDX() error = %v", err)
	}

	results, err := IdentifyLicensesInDirectory(testDataDir, options, licenseLibrary)
	if err != nil {
		t.Errorf("IdentifyLicensesInDirectory(%v) err = %v", testDataDir, err)
	}

	const expected = 541
	actual := 0
	for _, result := range results {
		result := result
		t.Run(result.File, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(result.File, "/invalid/") {
				wantLicenseID := strings.TrimSuffix(path.Base(result.File), ".txt")
				wantLicenseID = strings.TrimPrefix(wantLicenseID, "deprecated_")
				if _, ok := result.Matches[wantLicenseID]; !ok {
					t.Error("Did not get: ", wantLicenseID)
				}
				actual++
			}
		})
	}

	if actual := len(results); actual != expected {
		t.Errorf("IdentifyLicensesInDirectory(%v) len(results) expected %v actual: %v", testDataDir, expected, actual)
	}

}

func Test_identifyLicensesInSPDXTestDataFiles(t *testing.T) {
	t.Parallel()

	licenseLibrary, err := licenses.NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}
	if err := licenseLibrary.AddAllSPDX(); err != nil {
		t.Fatalf("licenseLibrary.AddAllSPDX() error = %v", err)
	}

	type tf struct {
		name string
		path string
	}

	var tfs []tf

	err = filepath.WalkDir(testDataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
			return err
		}
		if !d.IsDir() {
			tfs = append(tfs, tf{name: d.Name(), path: path})
		} else {
			// skip subdirs (e.g. /invalid)
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		fmt.Printf("error walking the path %v: %v\n", resources, err)
		return
	}

	for _, tc := range tfs {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			wantLicenseID := strings.TrimSuffix(tc.name, ".txt")
			wantLicenseID = strings.TrimPrefix(wantLicenseID, "deprecated_")
			got, err := IdentifyLicensesInFile(tc.path, options, licenseLibrary)
			if err != nil {
				t.Errorf("IdentifyLicensesInFile(%v) err = %v", tc.path, err)
			}

			if _, ok := got.Matches[wantLicenseID]; ok {
				t.Logf("GOT %v", wantLicenseID)
			} else {
				t.Errorf("IdentifyLicensesInFile() mismatched. want = %+v, got %v", wantLicenseID, got)
			}
		})
	}
}
