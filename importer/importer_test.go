// SPDX-License-Identifier: Apache-2.0

//go:build unit

package importer

import (
	"os"
	"path"
	"testing"

	"github.com/CycloneDX/license-scanner/configurer"

	"github.com/mrutkows/sbom-utility/log"
)

type args map[string]string

func removeOutput(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("error removing output dir: %v", err)
	}
}

func TestImporter_Import(t *testing.T) {
	const testImp = "_TestImporter_Import_" // Unique-ish name for testing embedded resources
	testData := path.Join("..", "testdata", "importer")
	testOutputPath := path.Join(testData, "output")
	baseSPDXDir := "../resources/spdx"
	baseCustomDir := "../resources/custom"
	defer removeOutput(t, testOutputPath)                    // Used for --spdxPath and --customPath output
	defer removeOutput(t, path.Join(baseSPDXDir, testImp))   // Used for embedded resources output (spdx/*)
	defer removeOutput(t, path.Join(baseCustomDir, testImp)) // Used for embedded resources output (custom/*)

	tests := []struct {
		args    args
		wantErr bool // true to test and skip so that known problems can be added/skipped for future fixes
	}{
		{
			args:    args{},
			wantErr: true,
		},
		{
			args: args{
				"spdx":       testImp,
				"spdxPath":   testImp,
				"custom":     testImp,
				"customPath": testImp,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdx":   testImp,
				"custom": testImp,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdxPath":   testImp,
				"customPath": testImp,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdxPath": testImp,
				"custom":   testImp,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdx":       testImp,
				"customPath": testImp,
			},
			wantErr: true,
		},
		{
			args: args{
				"customPath": testOutputPath,
			},
			wantErr: false,
		},
		{
			args: args{
				"spdxPath": testOutputPath,
			},
			wantErr: false,
		},
		{
			args: args{
				"custom": testImp,
			},
			wantErr: false,
		},
		{
			args: args{
				"spdx": testImp,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests { //nolint:paralleltest
		tt := tt
		name := testImp
		for k, v := range tt.args {
			name = name + "_" + k + "_" + v
		}
		t.Run(name, func(t *testing.T) {
			flagSet := configurer.NewDefaultFlags()
			arguments := []string{"--addAll", testData}
			for k, v := range tt.args {
				arguments = append(arguments, "--"+k, v)
			}
			_ = flagSet.Parse(arguments)

			config, err := configurer.InitConfig(flagSet)
			if err != nil {
				t.Fatal("unexpected InitConfig error")
			}

			err = Import(config)
			if tt.wantErr == (err == nil) {
				t.Fatalf("wantErr=%v, but got err=%v", tt.wantErr, err)
			}

			if err == nil {
				// verify that it did what it does
				verifyOutput(t, tt.args, baseCustomDir, baseSPDXDir)

				// Run Import() again as a convenient test proving that import fails when the destination is not empty.
				err = Import(config)
				if err == nil { // wantErr can be true (will just err again) or false (it should err this 2nd time around)
					t.Fatalf("second import should err, but got err==nil")
				}
			}
		})
	}
}

func TestImporter_Update(t *testing.T) {
	const embeddedTestData = "testdata" // embedded resources must exist at start time (testdata will disappear at build time)
	testData := path.Join("..", "testdata", "importer")
	baseSPDXDir := "../resources/spdx"
	baseCustomDir := "../resources/custom"

	// Remove the generated precheck files after Update() tests are over
	defer removeCustomPreCheckFiles(t, baseCustomDir, embeddedTestData) // --customPath
	defer removeSPDXPreCheckDir(t, baseSPDXDir, embeddedTestData)       // --SPDXPath
	defer removeCustomPreCheckFiles(t, "", testData)                    // --custom
	defer removeSPDXPreCheckDir(t, "", testData)                        // --spdx

	const any = "any"
	tests := []struct {
		args    args
		wantErr bool // true to test and skip so that known problems can be added/skipped for future fixes
	}{
		{
			args:    args{},
			wantErr: true,
		},
		{
			args: args{
				"spdx":       any,
				"spdxPath":   any,
				"custom":     any,
				"customPath": any,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdx":   any,
				"custom": any,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdxPath":   any,
				"customPath": any,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdxPath": any,
				"custom":   any,
			},
			wantErr: true,
		},
		{
			args: args{
				"spdx":       any,
				"customPath": any,
			},
			wantErr: true,
		},
		{
			args: args{
				"customPath": testData,
			},
			wantErr: false,
		},
		{
			args: args{
				"spdxPath": testData,
			},
			wantErr: false,
		},
		{
			args: args{
				"custom": embeddedTestData,
			},
			wantErr: false,
		},
		{
			args: args{
				"spdx": embeddedTestData,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests { //nolint:paralleltest
		tt := tt
		name := embeddedTestData
		for k, v := range tt.args {
			name = name + "_" + k + "_" + v
		}
		t.Run(name, func(t *testing.T) {
			flagSet := configurer.NewDefaultFlags()
			arguments := []string{"--updateAll"}
			for k, v := range tt.args {
				arguments = append(arguments, "--"+k, v)
			}
			_ = flagSet.Parse(arguments)
			config, err := configurer.InitConfig(flagSet)
			if err != nil {
				t.Fatal("unexpected InitConfig error")
			}

			err = Update(config)
			if tt.wantErr == (err == nil) {
				t.Fatalf("wantErr=%v, but got err=%v", tt.wantErr, err)
			}

			if !tt.wantErr {
				verifyUpdateOutput(t, tt.args, baseCustomDir, baseSPDXDir)
			}

		})
	}
}

func verifyOutput(t *testing.T, args args, baseCustomDir string, baseSPDXDir string) {
	t.Helper()

	for k, v := range args {
		switch k {
		case "custom":
			testForCustomFiles(t, baseCustomDir, v)
		case "spdx":
			testForSPDXFiles(t, baseSPDXDir, v)
		case "customPath":
			testForCustomFiles(t, "", v)
		case "spdxPath":
			testForSPDXFiles(t, "", v)
		}
	}
}

func verifyUpdateOutput(t *testing.T, args args, baseCustomDir string, baseSPDXDir string) {
	t.Helper()

	for k, v := range args {
		switch k {
		case "custom":
			testForCustomPreCheckFiles(t, baseCustomDir, v)
		case "spdx":
			testForSPDXPreCheckFiles(t, baseSPDXDir, v)
		case "customPath":
			testForCustomPreCheckFiles(t, "", v)
		case "spdxPath":
			testForSPDXPreCheckFiles(t, "", v)
		}
	}
}

func testForCustomFiles(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	customFiles := []string{
		"associated_text.txt",
		"license_info.json",
		"license_text.txt",
		"optional_text.txt",
		"prechecks_associated_text.json",
		"prechecks_license_text.json",
		"prechecks_optional_text.json",
	}

	d := path.Join(baseDir, subDirs, "license_patterns", "TESTIMP")
	ff := customFiles
	for _, f := range ff {
		f := path.Join(d, f)
		if _, err := os.Lstat(f); err != nil {
			t.Error(err)
		}
	}
}

func removeCustomPreCheckFiles(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	customFiles := []string{
		"prechecks_associated_text.json",
		"prechecks_license_text.json",
		"prechecks_optional_text.json",
	}

	d := path.Join(baseDir, subDirs, "license_patterns", "TESTIMP")
	ff := customFiles
	for _, f := range ff {
		f := path.Join(d, f)
		if err := os.Remove(f); err != nil {
			t.Error(err)
		}
	}
}

func testForCustomPreCheckFiles(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	customFiles := []string{
		"prechecks_associated_text.json",
		"prechecks_license_text.json",
		"prechecks_optional_text.json",
	}

	d := path.Join(baseDir, subDirs, "license_patterns", "TESTIMP")
	ff := customFiles
	for _, f := range ff {
		f := path.Join(d, f)
		if _, err := os.Lstat(f); err != nil {
			t.Error(err)
		}
	}
}

func testForSPDXFiles(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	fmap := map[string][]string{
		"json": {
			"licenses.json",
			"exceptions.json",
		},
		"precheck": {
			"0BSD.json",
			"AAL.json",
		},
		"template": {
			"0BSD.template.txt",
			"AAL.template.txt",
		},
		"testdata": {
			"0BSD.txt",
			"AAL.txt",
		},
	}

	for k, ff := range fmap {
		d := path.Join(baseDir, subDirs, k)
		for _, f := range ff {
			f := path.Join(d, f)
			if _, err := os.Lstat(f); err != nil {
				t.Error(err)
			}
		}
	}
}

func removeSPDXPreCheckDir(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	d := path.Join(baseDir, subDirs, "precheck")
	if err := os.RemoveAll(d); err != nil {
		t.Error(err)
	}
}

func testForSPDXPreCheckFiles(t *testing.T, baseDir string, subDirs string) {
	t.Helper()

	fmap := map[string][]string{
		"precheck": {
			"0BSD.json",
			"AAL.json",
		},
	}

	for k, ff := range fmap {
		d := path.Join(baseDir, subDirs, k)
		for _, f := range ff {
			f := path.Join(d, f)
			if _, err := os.Lstat(f); err != nil {
				t.Error(err)
			}
		}
	}
}

//nolint:funlen
func TestImporter_Validate(t *testing.T) {
	t.Parallel()

	// This test is particularly useful when DEBUG is set to show diff validate() errors. So force it on/off.
	Logger.SetLevel(log.DEBUG)

	// Using this list instead of a ReadDir to help document why each one of these is/was needed (in the reasons)
	tests := []struct {
		reasons string // why are we testing this now and future
		id      string
		wantErr bool // true to test and skip so that known problems can be added/skipped for future fixes
	}{
		{
			reasons: "0BSD should validate out-of-the-box",
			id:      "0BSD",
			wantErr: false,
		},
		{
			reasons: "Afmparse fixed testdata no space between comma-and",
			id:      "Afmparse",
			wantErr: false,
		},
		{
			reasons: "Beerware 3.20 needed modification to work with 2 email addrs - email1",
			id:      "Beerware",
			wantErr: false,
		},
		{
			reasons: "Beerware 3.20 needed modification to work with 2 email addrs - email2",
			id:      "Beerware-email2",
			wantErr: false,
		},
		{
			reasons: "Beerware 3.20 needed modification to work with 2 email addrs - email3",
			id:      "Beerware-email3",
			wantErr: false,
		},
		{
			reasons: "BlueOak-1.0.0 fixed omitable line prefix ## needs to be normalized like line comment",
			id:      "BlueOak-1.0.0",
			wantErr: false,
		},
		{
			reasons: "CC-BY-3.0 fixed testdata space before comma '(iv) ,'",
			id:      "CC-BY-3.0",
			wantErr: false,
		},
		{
			reasons: "CC-BY-NC-SA-2.0-DE 3.20",
			id:      "CC-BY-NC-SA-2.0-DE",
			wantErr: false,
		},
		{
			reasons: "CC-BY-NC-SA-2.0-FR template mod removed several extra ' . '",
			id:      "CC-BY-NC-SA-2.0-FR",
			wantErr: false,
		},
		{
			reasons: "CC-BY-SA-3.0 fixed testdata space before comma after (iv) ",
			id:      "CC-BY-SA-3.0",
			wantErr: false,
		},
		{
			reasons: "COIL-1.0 fixed ## markdown prefix in normalizer",
			id:      "COIL-1.0",
			wantErr: false,
		},
		{
			reasons: "Community-Spec-1.0 'Scope for: 1)' and 'under which 1)' breaks when the 1) is on a newline like a bullet ",
			id:      "Community-Spec-1.0",
			wantErr: false,
		},
		{
			reasons: "copyleft-next-0.3.0 (probably 0.3.1 same) ** blocks ** (fixed) and then a (ii) on nl",
			id:      "copyleft-next-0.3.0",
			wantErr: false,
		},
		{
			reasons: "D-FSL-1.0 escaped > in <<regex>> breaks us: match=\"(\\)\\>|\\))?\">> ",
			id:      "D-FSL-1.0",
			wantErr: false,
		},
		{
			reasons: "EPL-1.0 space-comma problem (workaround conflicts with NCSA somehow)",
			id:      "EPL-1.0",
			wantErr: false,
		},
		{
			reasons: "ErlPL-1.1 inconsistent space after comma (workaround breaking Python and PSF",
			id:      "ErlPL-1.1",
			wantErr: false,
		},
		{
			reasons: "IBM-pibs testdata has NBSP chars",
			id:      "IBM-pibs",
			wantErr: false,
		},
		{
			reasons: "LAL-1.3 inconsistent whitespace around : (adding : to whitepace chars would fix)",
			id:      "LAL-1.3",
			wantErr: false,
		},
		{
			reasons: "LPL-1.0 link placeholder",
			id:      "LPL-1.0",
			wantErr: false,
		},
		{
			reasons: "NCSA did't like some colon and comma work-arounds",
			id:      "NCSA",
			wantErr: false,
		},
		{
			reasons: "OGL-UK-1.0 fixed add   \u2028 to whitespace chars",
			id:      "OGL-UK-1.0",
			wantErr: false,
		},
		{
			reasons: "PSF-2.0 had issues with other fixes",
			id:      "PSF-2.0",
			wantErr: false,
		},
		{
			reasons: "PolyForm-Small-Business-1.0.0 has ** in middle and end **",
			id:      "PolyForm-Small-Business-1.0.0",
			wantErr: false,
		},
		{
			reasons: "Python-2.0.1 ([0-9]{4},\\s) doesn't work with the , workaround",
			id:      "Python-2.0.1",
			wantErr: false,
		},
	}
	testData := "../testdata/validator"
	for _, tt := range tests {
		tt := tt
		t.Run(tt.reasons, func(t *testing.T) {
			t.Parallel()
			id := tt.id
			templateFile := path.Join(testData, id+".template.txt")
			templateBytes, err := os.ReadFile(templateFile)
			if err != nil {
				t.Errorf("ID: %v Read template file error: %v", id, err)
				return
			}
			textFile := path.Join(testData, id+".txt")
			textBytes, err := os.ReadFile(textFile)
			if err != nil {
				t.Errorf("ID: %v Read text file error: %v", id, err)
				return
			}
			if _, err := validate(id, templateBytes, textBytes, templateFile); err != nil {
				if tt.wantErr == true {
					t.Skipf("validate() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
