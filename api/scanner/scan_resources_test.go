// SPDX-License-Identifier: Apache-2.0

//go:build unit

package scanner_test

import (
	"testing"

	"github.com/IBM/license-scanner/api/scanner"
	"github.com/IBM/license-scanner/configurer"

	"golang.org/x/exp/slices"
)

func TestScanner_Resources(t *testing.T) {
	const doNotSet = "DO-NOT-SET" // use config file instead of setting a flag

	tests := []struct {
		name          string
		text          string
		licID         string
		licName       string
		spdxMatches   []string
		customMatches []string
	}{
		{
			name: "nada",
			text: "unrecognizable garbage",
		},
		{
			name:          "custom only test1",
			text:          "test1 matches",
			licName:       "Test 1.0 (T1-Family)",
			customMatches: []string{doNotSet},
		},
		{
			name:          "custom test2",
			text:          "test2 matches",
			licName:       "Test 2.0 (T2-Family)",
			customMatches: []string{"customTest2"},
		},
		{
			name:          "spdx only aal",
			text:          "Attribution Assurance License\n\nCopyright (c) 2002 by AUTHOR PROFESSIONAL IDENTIFICATION * URL \"PROMOTIONAL SLOGAN FOR AUTHOR\u0027S PROFESSIONAL PRACTICE\"\n\nAll Rights Reserved\n\nATTRIBUTION ASSURANCE LICENSE (adapted from the original BSD license)\n\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that the conditions below are met. These conditions require a modest attribution to \u003cAUTHOR\u003e (the \"Author\"), who hopes that its promotional value may help justify the thousands of dollars in otherwise billable time invested in writing this and other freely available, open-source software.\n\n1. Redistributions of source code, in whole or part and with or without modification (the \"Code\"), must prominently display this GPG-signed text in verifiable form.\n\n2. Redistributions of the Code in binary form must be accompanied by this GPG-signed text in any documentation and, each time the resulting executable program or a program dependent thereon is launched, a prominent display (e.g., splash screen or banner text) of the Author\u0027s attribution information, which includes:\n\n     (a) Name (\"AUTHOR\"),\n     (b) Professional identification (\"PROFESSIONAL IDENTIFICATION\"), and\n     (c) URL (\"URL\").\n\n3. Neither the name nor any trademark of the Author may be used to endorse or promote products derived from this software without specific prior written permission.\n\n4. Users are entirely responsible, to the exclusion of the Author and any other persons, for compliance with (1) regulations set by owners or administrators of employed equipment, (2) licensing terms of any other software, and (3) local regulations regarding use, including those regarding import, export, and use of encryption software.\n\nTHIS FREE SOFTWARE IS PROVIDED BY THE AUTHOR \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR ANY CONTRIBUTOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, EFFECTS OF UNAUTHORIZED OR MALICIOUS NETWORK ACCESS; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n",
			licID:         "AAL",
			spdxMatches:   []string{doNotSet, "0.1234"}, // config is using 0.1234
			customMatches: []string{},
		},
		{
			name:          "both 0BSD",
			text:          "Copyright (C) YEAR by AUTHOR EMAIL\n\nPermission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n",
			licID:         "0BSD",
			licName:       "BSD Zero Clause License (BSD)",
			spdxMatches:   []string{doNotSet, "0.1234"}, // config is using 0.1234
			customMatches: []string{doNotSet},
		},
	}

	// read license texts from files
	for _, tt := range tests {
		tt := tt

		// test matrix spdx * custom
		spdxs := []string{doNotSet, "", ".", "0.1234"}
		customs := []string{doNotSet, "customTest2"}

		for s := range spdxs {
			spdx := spdxs[s]
			for _, custom := range customs {
				name := tt.name + " with SPDX=" + spdx + " Custom=" + custom
				t.Run(name, func(t *testing.T) {
					flagSet := configurer.NewDefaultFlags()
					_ = flagSet.Set("configPath", "../../testdata/resources")
					if spdx != doNotSet {
						_ = flagSet.Set(configurer.SpdxFlag, spdx)
					}
					if custom != doNotSet {
						_ = flagSet.Set(configurer.CustomFlag, custom)
					}

					specs := &scanner.ScanSpecs{}
					spec := scanner.ScanSpec{LicenseText: tt.text}
					specs.Specs = append(specs.Specs, spec)
					scanResults, err := specs.WithFlags(flagSet).ScanLicenseText()
					if err != nil {
						t.Logf("scan error: %v", err)
					}

					if len(scanResults) != 1 {
						t.Errorf("expected 1 scan result got: %v", len(scanResults))
					} else if len(scanResults[0].CycloneDXLicenses) != 1 {
						t.Errorf("expected 1 license got: %v", len(scanResults))
					} else {
						lic := scanResults[0].CycloneDXLicenses[0].License
						if slices.Contains(tt.spdxMatches, spdx) && lic.ID != tt.licID {
							t.Errorf("did not find expected spdx id: want %v got %v", tt.licID, lic.ID)
						}
						if slices.Contains(tt.customMatches, custom) && lic.Name != tt.licName {
							t.Errorf("did not find expected custom name: want %v got %v", tt.licName, lic.Name)
						}
						if !slices.Contains(tt.spdxMatches, spdx) && !slices.Contains(tt.customMatches, custom) && lic.Name != scanner.NOASSERTION_SPDX_NAME {
							t.Errorf("did not find expected name: want %v got %v", scanner.NOASSERTION_SPDX_NAME, lic.Name)
						}
					}
				})
			}
		}
	}
}
