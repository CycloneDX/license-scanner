// SPDX-License-Identifier: Apache-2.0

//go:build unit

package licenses

import (
	"fmt"
	"regexp"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/IBM/license-scanner/configurer"
)

const (
	expectedLicenseCount    = 540
	expectedPrecheckCount   = 556
	acceptablePatternsCount = 0
)

func TestCreateLicense(t *testing.T) {
	re := regexp.MustCompile(`permission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>>`)
	tests := []struct {
		name    string
		id      string
		want    License
		wantErr bool
	}{
		{
			name:    "expect fail with no_such_file",
			id:      "no_such_file",
			want:    License{},
			wantErr: true,
		},
		{
			name: "MIT",
			id:   "MIT",
			want: License{
				SPDXLicenseID: "MIT",
				LicenseInfo: LicenseInfo{
					Name:            "MIT License",
					Family:          "MIT",
					SPDXStandard:    true,
					SPDXException:   false,
					OSIApproved:     true,
					IgnoreIDMatch:   true,
					IgnoreNameMatch: false,
					URLs:            []string{"http://www.opensource.org/licenses/mit-license.php", "https://opensource.org/licenses/MIT"},
				},
				PrimaryPatterns: []*PrimaryPatterns{
					{
						Text:     "\n\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>>",
						re:       re,
						FileName: "license_MIT.txt",
					},
				},
				PrimaryPatternsSources: []PrimaryPatternsSources{
					{
						SourceText: "\n\n\nPermission is hereby granted, free of charge, " +
							"to any person obtaining a copy of <<match=this|the>" +
							"> <<match=.*>> <<beginOptional>>software <<match=and/?o?r?>> ass" +
							"ociated documentation<<endOptional>> <<beginOptional>>SOFTWARE<<" +
							`endOptional>> <<beginOptional>><<match=files?>> (the <<match="?S` +
							`oftware"?|"?Materials"?>>),<<endOptional>> to deal in the <<matc` +
							"h=Software|Code|Materials>> without restriction, including witho" +
							"ut <<match=limitation,?>> <<beginOptional>>on<<endOptional>> the " +
							"<<beginOptional>>irrevocable, perpetual, worldwide, and royalty" +
							"-free<<endOptional>> rights to use, copy, modify, merge, publish" +
							", distribute, <<beginOptional>>sublicense,<<endOptional>> <<begi" +
							"nOptional>>distribute with modifications,<<endOptional>> <<begin" +
							"Optional>><<match=sub ?license,?>><<endOptional>> <<beginOptiona" +
							`l>>display, perform, create derivative works from<<endOptional>> ` +
							"<<match=and ?/ ?or>> sell copies of the <<match=Software|code|M" +
							"aterials>>, <<beginOptional>> both in source<<endOptional>> and " +
							"<<beginOptional>>object code form, and<<endOptional>> to permit " +
							"persons to whom the <<match=Software|code|materials>> <<match=is" +
							"|are>> furnished to do so, subject to the following <<match=cond" +
							"itions|disclaimer>>:\n\n<<beginOptional>>\nThe above copyright noti" +
							"ce<<match= and|,>> this permission notice <<beginOptional>>and t" +
							"he disclaimer statement<<endOptional>> <<beginOptional>>(includi" +
							"ng the next\nparagraph)<<endOptional>> <<match=shall|must>> be in" +
							"cluded in all copies or substantial portions of the <<match=Soft" +
							"ware|code|materials>>.\n<<endOptional>>\n",
						Filename: "license_MIT.txt",
					},
				},
				AssociatedPatterns:        nil,
				AssociatedPatternsSources: nil,
				Text: LicenseText{
					ContentType: "",
					Encoding:    "",
					Content:     "",
				},
			},
			wantErr: false,
		},
		{
			name: "Apache-2.0 needs retry to map URL to URLs",
			id:   "Apache-2.0",
			want: License{
				SPDXLicenseID: "Apache-2.0",
				LicenseInfo: LicenseInfo{
					Name:            "Apache License 2.0",
					Family:          "Apache",
					SPDXStandard:    true,
					SPDXException:   false,
					OSIApproved:     true,
					IgnoreIDMatch:   false,
					IgnoreNameMatch: false,
					Aliases:         []string{"Apache License, Version 2.0", "Apache License v. 2.0", "Apache License Version 2.0", "Apache Software License v2.0"},
					URLs:            []string{"http://www.apache.org/licenses/LICENSE-2.0"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ll, err := NewLicenseLibrary(nil)
			if err != nil {
				t.Errorf("NewLicenseLibrary() error = %v", err)
			}
			err = AddLicense(tt.id, ll)
			if err != nil {
				if tt.wantErr == false {
					t.Fatalf("AddLicense() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					Logger.Infof("AddLicense() wantErr %v, error = %v", tt.wantErr, err)
				}
			} else {
				if d := cmp.Diff(tt.want.LicenseInfo, ll.LicenseMap[tt.id].LicenseInfo); d != "" {
					t.Errorf("Didn't get expected License: (-want, +got): %v", d)
				}
			}
		})
	}
}

func TestLicenses_AddLicenses(t *testing.T) {
	tests := []struct {
		name     string
		expected int
		wantErr  bool
	}{
		{
			name:     "add and count licenses",
			expected: expectedLicenseCount,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ll, err := NewLicenseLibrary(nil)
			if err != nil {
				t.Fatalf("NewLicenseLibrary() error = %v", err)
			}
			if err := ll.AddAll(); (err != nil) != tt.wantErr {
				t.Errorf("AddAll() error = %v, wantErr %v", err, tt.wantErr)
			}
			numGot := len(ll.LicenseMap)
			if numGot != tt.expected {
				t.Errorf("AddAll() length check wanted = %v, got %v", tt.expected, numGot)
			}
		})
	}
}

// TestLicenses_PrintLicenses is for handy listing or our inventory. Not really for testing.
func TestLicenses_PrintLicenses(t *testing.T) {
	tests := []struct {
		name     string
		expected int
		wantErr  bool
	}{
		{
			name:     "license listing",
			expected: expectedLicenseCount,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ll, err := NewLicenseLibrary(nil)
			if err != nil {
				t.Fatalf("NewLicenseLibrary() error = %v", err)
			}
			if err := ll.AddLicenses(); (err != nil) != tt.wantErr {
				t.Errorf("AddLicenses() error = %v, wantErr %v", err, tt.wantErr)
			}
			var osiApproved []License
			var notApproved []License
			for _, lic := range ll.LicenseMap {
				if lic.LicenseInfo.OSIApproved {
					osiApproved = append(osiApproved, lic)
				} else {
					notApproved = append(notApproved, lic)
				}
			}
			sort.Slice(osiApproved, func(i, j int) bool {
				return osiApproved[i].GetID() < osiApproved[j].GetID()
			})
			sort.Slice(notApproved, func(i, j int) bool {
				return notApproved[i].GetID() < notApproved[j].GetID()
			})
			fmt.Println("OSI APPROVED LICENSES:")
			fmt.Println("======================")
			for _, lic := range osiApproved {
				fmt.Printf("SPDXID: %v, Name: %v, Alias: %v, SPDXStandard: %v, SPDXException: %v, OSIApproved: %v URLS: %v\n", lic.SPDXLicenseID, lic.LicenseInfo.Name, lic.LicenseInfo.Aliases, lic.LicenseInfo.SPDXStandard, lic.LicenseInfo.SPDXException, lic.LicenseInfo.OSIApproved, lic.LicenseInfo.URLs)
			}
			fmt.Println("")
			fmt.Println("NOT APPROVED LICENSES:")
			fmt.Println("======================")
			for _, lic := range notApproved {
				fmt.Printf("SPDXID: %v, Name: %v, Alias: %v, SPDXStandard: %v, SPDXException: %v, OSIApproved: %v URLS: %v\n", lic.SPDXLicenseID, lic.LicenseInfo.Name, lic.LicenseInfo.Aliases, lic.LicenseInfo.SPDXStandard, lic.LicenseInfo.SPDXException, lic.LicenseInfo.OSIApproved, lic.LicenseInfo.URLs)
			}
		})
	}
}

// TestLicenseLibrary_AddAll makes sure that the loading of license maps works as expected
// The hard-coded sizes here might make this test only of temporary usefulness (could count files?).
func TestLicenseLibrary_AddAll(t *testing.T) {
	config, err := configurer.InitConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	resourcesFlag := configurer.NewDefaultFlags()
	err = resourcesFlag.Set(configurer.ConfigPathFlag, "../testdata/config/")
	if err != nil {
		t.Fatal(err)
	}
	configWithResources, err := configurer.InitConfig(resourcesFlag)
	if err != nil {
		t.Fatal(err)
	}

	defaultLL, err := NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary(nil) error = %v", err)
	}

	configLL, err := NewLicenseLibrary(config)
	if err != nil {
		t.Fatalf("NewLicenseLibrary(config) error = %v", err)
	}

	configWithResourcesLL, err := NewLicenseLibrary(configWithResources)
	if err != nil {
		t.Fatalf("NewLicenseLibrary(configWithResources) error = %v", err)
	}

	tests := []struct {
		name          string
		ll            *LicenseLibrary
		expectedSizes map[string]int
	}{
		{
			name: "default license library",
			ll:   defaultLL,
			expectedSizes: map[string]int{
				"LicenseMap":                expectedLicenseCount,
				"PrimaryPatternPreCheckMap": expectedPrecheckCount,
				"AcceptablePatternsMap":     acceptablePatternsCount,
			},
		},
		{
			name: "config license library",
			ll:   configLL,
			expectedSizes: map[string]int{
				"LicenseMap":                expectedLicenseCount,
				"PrimaryPatternPreCheckMap": expectedPrecheckCount,
				"AcceptablePatternsMap":     acceptablePatternsCount,
			},
		},
		{
			name: "config resources path",
			ll:   configWithResourcesLL,
			expectedSizes: map[string]int{
				"LicenseMap":                1,
				"PrimaryPatternPreCheckMap": 0,
				"AcceptablePatternsMap":     1,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()

			if err := tt.ll.AddAll(); err != nil {
				t.Fatalf("AddAll() error = %v", err)
			}
			actual := map[string]int{
				"LicenseMap":                len(tt.ll.LicenseMap),
				"PrimaryPatternPreCheckMap": len(tt.ll.PrimaryPatternPreCheckMap),
				"AcceptablePatternsMap":     len(tt.ll.AcceptablePatternsMap),
			}

			if d := cmp.Diff(tt.expectedSizes, actual); d != "" {
				t.Errorf("Didn't get expected LicenseLibrary map sizes: (-want, +got): %v", d)
			}
		})
	}
}

func TestLicenseLibrary_PreChecks(t *testing.T) {
	tests := []struct {
		name          string
		configPath    string
		expectedSizes map[string]int
	}{
		{
			name:       "no_prechecks",
			configPath: "../testdata/prechecks/no_prechecks",
			expectedSizes: map[string]int{
				"LicenseMapLen":             1,
				"PrimaryPatternPreCheckMap": 0,
			},
		},
		{
			name:       "static_prechecks",
			configPath: "../testdata/prechecks/static_prechecks",
			expectedSizes: map[string]int{
				"LicenseMapLen":             1,
				"PrimaryPatternPreCheckMap": 1,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flagSet := configurer.NewDefaultFlags()
			if err := flagSet.Set(configurer.ConfigPathFlag, tt.configPath); err != nil {
				t.Fatal(err)
			}
			config, err := configurer.InitConfig(flagSet)
			if err != nil {
				t.Fatal(err)
			}

			ll, err := NewLicenseLibrary(config)
			if err != nil {
				t.Fatalf("NewLicenseLibrary(config) error = %v", err)
			}

			if err := ll.AddAll(); err != nil {
				t.Fatalf("AddAll() error = %v", err)
			}
			actual := map[string]int{
				"LicenseMapLen":             len(ll.LicenseMap),
				"PrimaryPatternPreCheckMap": len(ll.PrimaryPatternPreCheckMap),
			}

			if d := cmp.Diff(tt.expectedSizes, actual); d != "" {
				t.Errorf("Didn't get expected LicenseLibrary map sizes: (-want, +got): %v", d)
			}
		})
	}
}

// Test to make sure the bools are not defaulting to false and the strings are getting wrapped as slices where needed
func TestLicenseUnmarshal(t *testing.T) {
	fileContents := []byte(`
{
  "name": "test",
  "family": "test",
  "spdx_standard": true,
  "spdx_exception": true,
  "osi_approved": true,
  "ignore_id_match": true,
  "ignore_name_match": true,
  "aliases": "test",
  "urls": "test",
  "eligible_licenses": "test",
  "is_mutator": true
}
`)

	li, err := readLicenseInfoJSON(fileContents)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure the bools all read true after reading (defaulted fields are false)
	if !li.SPDXStandard || !li.SPDXException || !li.OSIApproved || !li.IgnoreIDMatch || !li.IgnoreNameMatch || !li.IsMutator {
		t.Fatal("readLicenseInfoJson failed to read a bool as true")
	}
	if li.Name != "test" || li.Family != "test" {
		t.Logf("%+v", li)
		t.Fatal("readLicenseInfoJson failed to read a string (that is supposed to be a string)")
	}
	expectedSlice := []string{"test"}
	gotSlices := [][]string{li.Aliases, li.URLs, li.EligibleLicenses}

	for _, got := range gotSlices {
		if d := cmp.Diff(expectedSlice, got); d != "" {
			t.Logf("%+v", li)
			t.Errorf("Didn't get expected slice: (-want, +got): %v", d)
		}
	}
}
