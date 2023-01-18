// SPDX-License-Identifier: Apache-2.0

//go:build unit

package importer

import (
	"os"
	"path"
	"testing"

	"github.com/mrutkows/sbom-utility/log"
)

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
