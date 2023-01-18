// SPDX-License-Identifier: Apache-2.0

//go:build unit

package identifier

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/IBM/license-scanner/configurer"
	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

func Test_generateTextBlocks(t *testing.T) {
	match1 := []int{10, 15}
	type args struct {
		originalText string
		matches      []licenseMatch
	}
	tests := []struct {
		name     string
		args     args
		expected []Block
		wantErr  bool
		skip     bool
	}{
		{
			name: "no Matches no Blocks",
			args: args{
				originalText: "original Text",
				matches:      []licenseMatch{},
			},
			expected: []Block{{Text: "original Text"}},
			wantErr:  false,
		},
		{
			name: "one match one license",
			args: args{
				originalText: "This is a simple test.",
				matches: []licenseMatch{
					{LicenseId: "Simple", Match: Match{Begins: match1[0], Ends: match1[1]}},
				},
			},
			expected: []Block{
				{Text: "This is a "},
				{Text: "simple", Matches: []string{"Simple"}},
				{Text: " test."},
			},
			wantErr: false,
		},
		{
			name: "multiple Matches one license",
			args: args{
				originalText: "This is a simple test of a simple license.",
				matches: []licenseMatch{
					{LicenseId: "Simple", Match: Match{Begins: 10, Ends: 15}},
					{LicenseId: "Simple", Match: Match{Begins: 27, Ends: 32}},
				},
			},
			expected: []Block{
				{Text: "This is a "},
				{Text: "simple", Matches: []string{"Simple"}},
				{Text: " test of a "},
				{Text: "simple", Matches: []string{"Simple"}},
				{Text: " license."},
			},
			wantErr: false,
		},
		{
			name: "multiple overlapping patterns one license (and append no-alphanums)",
			args: args{
				originalText: "This license has multiple overlapping patterns.",
				matches: []licenseMatch{
					{LicenseId: "Simple", Match: Match{Begins: 17, Ends: 45}},
					{LicenseId: "Simple", Match: Match{Begins: 26, Ends: 36}},
				},
			},
			expected: []Block{
				{Text: "This license has "},
				{Text: "multiple overlapping patterns.", Matches: []string{"Simple"}},
			},
			wantErr: false,
		},
		{
			name: "multiple licenses",
			args: args{
				originalText: "This is a simple and easy test.",
				matches: []licenseMatch{
					{LicenseId: "Simple", Match: Match{Begins: 10, Ends: 15}},
					{LicenseId: "Easy", Match: Match{Begins: 21, Ends: 24}},
				},
			},
			expected: []Block{
				{Text: "This is a "},
				{Text: "simple", Matches: []string{"Simple"}},
				{Text: " and "},
				{Text: "easy", Matches: []string{"Easy"}},
				{Text: " test."},
			},
			wantErr: false,
		},
		{
			name: "multiple licenses with overlapping Matches",
			args: args{
				originalText: "This is a simple and easy test.",
				matches: []licenseMatch{
					{LicenseId: "Simple", Match: Match{Begins: 10, Ends: 15}},
					{LicenseId: "Easy", Match: Match{Begins: 21, Ends: 24}},
					{LicenseId: "SimpleAndEasy", Match: Match{Begins: 10, Ends: 24}},
				},
			},
			expected: []Block{
				{Text: "This is a "},
				{Text: "simple", Matches: []string{"Simple", "SimpleAndEasy"}},
				{Text: " and ", Matches: []string{"SimpleAndEasy"}},
				{Text: "easy", Matches: []string{"Easy", "SimpleAndEasy"}},
				{Text: " test."},
			},
			wantErr: false,
			skip:    true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			blocks, err := generateTextBlocks(tt.args.originalText, tt.args.matches)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateTextBlocks() error = %v, wantErr %v", err, tt.wantErr)
			} else if d := cmp.Diff(tt.expected, blocks); d != "" {
				if tt.skip {
					// Want to keep running this test, but it does not work yet
					t.Skipf("Didn't get expected result: (-want, +got): %v", d)
				} else {
					t.Errorf("Didn't get expected result: (-want, +got): %v", d)
				}
			}
		})
	}
}

func defaultOptions() Options {
	options := Options{
		ForceResult: false,
		Enhancements: Enhancements{
			AddNotes:       "",
			AddTextBlocks:  true,
			FlagAcceptable: false,
			FlagCopyrights: true,
			FlagKeywords:   false,
		},
	}
	return options
}

func Test_identifyLicensesInFile(t *testing.T) {
	cfg, err := configurer.InitConfig(nil)
	if err != nil {
		t.Fatalf("error from configurer.InitConfig(): %v", err)
	}

	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name: "no such file /not_a_real_path/this_is_not_an_existing_file_we_hope",
			args: args{
				filePath: "/not_a_real_path/this_is_not_an_existing_file_we_hope",
			},
			want:    map[string]string{},
			wantErr: true,
		},
	}
	options := defaultOptions()
	licenseLibrary, err := licenses.NewLicenseLibrary(cfg)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentifyLicensesInFile(tt.args.filePath, options, licenseLibrary)
			if tt.wantErr {
				if err == nil {
					t.Errorf("IdentifyLicensesInFile() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					t.Logf("IdentifyLicensesInFile() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IdentifyLicensesInFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}

//go:embed testfiles/aml.txt
var aml string

//go:embed testfiles/wcwidth.txt
var wcwidth string

func Test_identifyLicensesInString(t *testing.T) {
	licenseLibrary, err := licenses.NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}
	if err := licenseLibrary.AddAll(); err != nil {
		t.Errorf("AddAll() error = %v", err)
	}

	type args struct {
		input string
	}
	tests := []struct {
		name    string
		args    args
		want    IdentifierResults
		wantErr bool
	}{
		{
			name: "should be correct if no license is found",
			args: args{input: "This does not contain a license pattern."},
			want: IdentifierResults{
				Matches: map[string][]Match{},
				Blocks: []Block{
					{Text: "This does not contain a license pattern."},
				},
				Hash: normalizer.Digest{
					Md5:    "197a64f01031cf1fc53edcc2b736f13e",
					Sha256: "53b3136e2da71e3fa4058ddf365d26dc069405ef74283841e5b792cc1cc8a072",
					Sha512: "a58d7ea8a02b188545c594103dc18856bdebd065e7bc2b6c652fe247bd690906cda5a77bba90e141dfc5ae91200247de9862f394559c604fa7843b6bc5dd5a92",
				},
			},
		},
		{
			name: "should be correct for one match against aml license",
			args: args{input: aml},
			want: IdentifierResults{
				Matches: map[string][]Match{"AML": {{Begins: 0, Ends: len(aml) - 1}}},
				Blocks: []Block{
					{
						Text:    aml,
						Matches: []string{"AML"},
					},
				},
				Hash: normalizer.Digest{
					Md5:    "cb93252f9459e842cba62b7ccd96706c",
					Sha256: "c902be701d61c3275c35a63c5b42ec5caa04c2048a6b8614f2537b97b08bdcf9",
					Sha512: "9641cd64c01e886ae64063b94598fac3446636de61030377cff27931d541ff526ed4f8722a06d3177dfbb167551f4394411abf53e2d07a455cb2ab45ca45638d",
				},
				CopyRightStatements: nil,
			},
		},
		{
			name: "should be correct for one match against wcwidth license",
			args: args{input: wcwidth},
			want: IdentifierResults{
				Matches: map[string][]Match{"MIT": {{Begins: 311, Ends: 871}}},
				Blocks: []Block{
					{
						Text: wcwidth[0:145],
					},
					{
						Text:    "Copyright (C) 2012 by Jun Woong.",
						Matches: []string{"COPYRIGHT"},
					},
					{
						Text: wcwidth[177:311],
					},
					{
						Text:    wcwidth[311:872],
						Matches: []string{"MIT"},
					},
					{
						Text: wcwidth[872:],
					},
				},
				Hash: normalizer.Digest{
					Md5:    "0b36908f02d0d6ac4364a525ea51e2ea",
					Sha256: "85e7115e14f4af6f555d7316ef90529bd4cc6bc0bcbd86542412d05d2b8e5b9f",
					Sha512: "35c95d1d349ca4e2cf2df030b87b7d5b79739af2466fc6bf71d11ddddd11cef5603e0735a7c4d16de505f182174c9a3ab5ffea981149b048685a0cd42317c636",
				},
				CopyRightStatements: []PatternMatch{{Text: "Copyright (C) 2012 by Jun Woong.", Begins: 145, Ends: 176}},
			},
		},
		{
			name: "should be correct for one match against one license",
			args: args{input: "Copyright <YEAR> <COPYRIGHT HOLDER>\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"MIT": {
						{Ends: 1058},
						{Begins: 37, Ends: 597},
						{Begins: 599, Ends: 1058},
					},
				},
				Blocks: []Block{
					{
						Text: "Copyright <YEAR> <COPYRIGHT HOLDER>\n\n" +
							`Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:` +
							"\n\n" +
							`The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.` +
							"\n\n" +
							`THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`,
						Matches: []string{"MIT"},
					},
				},
				Hash: normalizer.Digest{
					Md5:    "1a9f30cb0553e0cc841fbf8188c6035f",
					Sha256: "93e2a8851d7151a715f8f09d1d79f96697a18c75b15f4174b54d60d7e595a088",
					Sha512: "6d4193b4bebbb74dda684306867bdfbb95328b2773acc60abddd6ec8edfad3039ef46bdbc2c01b72660ba4dd6319e5d9730ad43a98b6e723b6b6266c508c7300",
				},
			},
		},
		{
			name: "should be no match when alias prefix has no word boundary",
			args: args{input: "aPaChE lIcEnSe vErSiOn 2.0This prefix does not have a word boundary."},
			want: IdentifierResults{
				Matches: map[string][]Match{},
				Blocks: []Block{
					{Text: "aPaChE lIcEnSe vErSiOn 2.0This prefix does not have a word boundary."},
				},
				Hash: normalizer.Digest{
					Md5:    "8d13ad17778489feed6f6e75b54f19f1",
					Sha256: "6d2da113679ea8ebbc04cf8f43968c23d8fb33dce08261018893e601928b2c3d",
					Sha512: "47203495d723b6d2ca8b1b7a04c0f00c1491dcf323a1200e584286df2adf9c5599a51797f135a4c6e28796aa4fde0297685b368ee11d31395b242db5a3d1f66b",
				},
			},
		},
		{
			name: "should be correct when alias matches prefix",
			args: args{input: "aPaChE lIcEnSe vErSiOn 2.0 This does not contain a license pattern."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 0, Ends: 26},
					},
				},
				Blocks: []Block{
					{
						Text:    "aPaChE lIcEnSe vErSiOn 2.0 ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "This does not contain a license pattern."},
				},
				Hash: normalizer.Digest{
					Md5:    "f9c220c72b1a7e3b6b7741590bf0b25a",
					Sha256: "9ef34f7e4935b76c22d29f28ea37ad64266fb0764bd0c93c36aa510034c03363",
					Sha512: "5e8807e1b55c04fe586365c4366b545beeab3140f357b1ffdb0dce397ccec05956d87318ca48fee44c6a75a6c24b806b3272113e3cbe58ca238b30795f5b6cb5",
				},
			},
		},
		{
			name: "should be correct when alias matches suffix",
			args: args{input: "This does not contain a license pattern aPaChE lIcEnSe vErSiOn 2.0"},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 39, Ends: 65},
					},
				},
				Blocks: []Block{
					{Text: "This does not contain a license pattern"},
					{
						Text:    " aPaChE lIcEnSe vErSiOn 2.0",
						Matches: []string{"Apache-2.0"},
					},
				},
				Hash: normalizer.Digest{
					Md5:    "6b7ebb3e66a277d166bfad4ce167f414",
					Sha256: "d2e995edc4d4c64c93f598a82005b57e2b287ff7e2c5ce6a91138ce91ac9a716",
					Sha512: "2c103f97ba91b691dd8f36a8d74349cc7b394958cae85452cd2360771059f5caa1dc6e9905251b299df712c03f107a56ee4fa6f61209b5dceedd5bdbe305321c",
				},
			},
		},
		{
			name: "should be correct when alias is in middle",
			args: args{input: "Yada yada aPaChE lIcEnSe vErSiOn 2.0 and so on..."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 9, Ends: 36},
					},
				},
				Blocks: []Block{
					{Text: "Yada yada"},
					{
						Text:    " aPaChE lIcEnSe vErSiOn 2.0 ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "and so on..."},
				},
				Hash: normalizer.Digest{
					Md5:    "973c67458632165e33afadd87f4d360d",
					Sha256: "f866bfe3c0f0f0f9207db105486c333a20129ce708edf77d3562340dce3a7966",
					Sha512: "43545191c83bc8f758a322991299416e5de35d6161afe21d62d4efe50309a4a318c8e181c13501acdb4f6b557df4534523c950e6cc5665ed40037f4ef27bd4f9",
				},
			},
		},
		{
			name: "should be correct for name match in the middle",
			args: args{input: "Yada yada aPaChE lIcEnSe 2.0 and so on..."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 9, Ends: 28},
					},
				},
				Blocks: []Block{
					{Text: "Yada yada"},
					{
						Text:    " aPaChE lIcEnSe 2.0 ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "and so on..."},
				},
				Hash: normalizer.Digest{
					Md5:    "cb14e5af98581e2fb982385f746e27f8",
					Sha256: "a351891c1dd7f03187a51b26786eb061ceba4fa6198c8c670a8c00f7ff5aef7d",
					Sha512: "6ef6bd201238507a65f1565e6fa7ffb5c69dedcbec218d37d2ea14889f90e0f994e94485809d1aa8ba0a23356a91891df460497d1217254c4fe66f1d667d583b",
				},
			},
		},
		{
			name: "should be correct for ID match in the middle",
			args: args{input: "Yada yada aPaChE-2.0 and so on..."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 9, Ends: 20},
					},
				},
				Blocks: []Block{
					{Text: "Yada yada"},
					{
						Text:    " aPaChE-2.0 ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "and so on..."},
				},
				Hash: normalizer.Digest{
					Md5:    "049faf27dd1bf6186f7f40f22c13626b",
					Sha256: "138ebafdec2227ac8b8359ee57c87ddc04dd676786e6e8b4b10cbf32d15a9c65",
					Sha512: "1b7a9f8cc1dc4606efef18aaab70d53ce9eeeddf519dd113746bd1bc4fc456df02466ee11bde9b34e02da8ad2b95c3dd389b8744acec57837cd3ba4e03fb0d89",
				},
			},
		},
		{
			name: "should be correct for parenthesized ID match in the middle",
			args: args{input: "Yada yada (aPaChE-2.0) and so on..."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 9, Ends: 22},
					},
				},
				Blocks: []Block{
					{Text: "Yada yada"},
					{
						Text:    " (aPaChE-2.0) ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "and so on..."},
				},
				Hash: normalizer.Digest{
					Md5:    "4773f569ce06a6fadae3eceaccd7a360",
					Sha256: "d15acbb83bb4fada467541ce4255c3d53afa87ae9fc5ed6d8fd1c7156374cf28",
					Sha512: "c8734eabb67d52888b4f7bbd54ed64639846a570d58d19c701377ee1f69a0de1eb218c9d70a3fafc3f66e160a779337b9929006fa29af8e279f6ef165a69fdc0",
				},
			},
		},
		{
			name: "should be correct for URL match (with additional fragment) in the middle",
			args: args{input: "Yada yada http://www.apache.org/licenses/LICENSE-2.0/etc... and so on..."},
			want: IdentifierResults{
				Matches: map[string][]Match{
					"Apache-2.0": {
						{Begins: 9, Ends: 59},
					},
				},
				Blocks: []Block{
					{Text: "Yada yada"},
					{
						Text:    " http://www.apache.org/licenses/LICENSE-2.0/etc... ",
						Matches: []string{"Apache-2.0"},
					},
					{Text: "and so on..."},
				},
				Hash: normalizer.Digest{
					Md5:    "df45de0253f3a3467dcb4e0241186ff6",
					Sha256: "bdb3cf04bf5582f319c21cae31a95a37f6a0052a2210372a8d0d7b4943244a0d",
					Sha512: "a7f4eccb3de2e1ab7dd1c3d5257c6b3c5a5adc15dc66645d179f3ad38e6f67bc3fe182d153c3e0dbff896436082b44edf05c6448b38967ff96eb604da9677c7b",
				},
			},
		},
	}
	options := defaultOptions()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := IdentifyLicensesInString(tt.args.input, options, licenseLibrary)
			if (err != nil) != tt.wantErr {
				t.Errorf("identifyLicensesInString() error = %v, wantErr %v", err, tt.wantErr)
			} else if d := cmp.Diff(tt.want.Matches, got.Matches, cmp.AllowUnexported(Match{})); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			} else if d := cmp.Diff(tt.want.CopyRightStatements, got.CopyRightStatements); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			} else if d := cmp.Diff(tt.want.Blocks, got.Blocks); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			} else if d := cmp.Diff(tt.want.Hash, got.Hash); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			}
		})
	}
}

func Test_identifyLicensesInStringPreChecks(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		input      string
		want       IdentifierResults
	}{
		{
			name:       "duplicate matches",
			configPath: "../testdata/duplicates/",
			input:      "whatever noprechecktext whatever passes",
			want: IdentifierResults{
				Matches: map[string][]Match{"DuplicateMatchTest": {{Begins: 9, Ends: 22}}},
				Blocks: []Block{
					{Text: "whatever "},
					{Text: "noprechecktext", Matches: []string{"DuplicateMatchTest"}},
					{Text: " whatever passes"},
				},
			},
		},
		{
			name:       "no prechecks matches template",
			configPath: "../testdata/prechecks/no_prechecks/",
			input:      "whatever noprechecktext whatever passes",
			want: IdentifierResults{
				Matches: map[string][]Match{"NoPreCheckTest": {{Begins: 9, Ends: 22}}},
				Blocks: []Block{
					{Text: "whatever "},
					{Text: "noprechecktext", Matches: []string{"NoPreCheckTest"}},
					{Text: " whatever passes"},
				},
			},
		},
		{
			name:       "match template and pass static precheck",
			configPath: "../testdata/prechecks/static_prechecks",
			input:      "this matches template and it also passes the static body checks",
			want: IdentifierResults{
				Matches: map[string][]Match{"Template": {{Begins: 13, Ends: 20}}},
				Blocks: []Block{
					{Text: "this matches "},
					{Text: "template", Matches: []string{"Template"}},
					{Text: " and it also passes the static body checks"},
				},
			},
		},
		{
			name:       "match template but fail static precheck",
			configPath: "../testdata/prechecks/static_prechecks",
			input:      "this matches template but does NOT pass the static body checks",
			want: IdentifierResults{
				Matches: map[string][]Match{},
				Blocks: []Block{
					{Text: "this matches template but does NOT pass the static body checks"},
				},
			},
		},
	}
	options := defaultOptions()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flagSet := configurer.NewDefaultFlags()
			flagSet.Set(configurer.ConfigPathFlag, tt.configPath)
			config, err := configurer.InitConfig(flagSet)
			if err != nil {
				t.Fatal(err)
			}

			ll, err := licenses.NewLicenseLibrary(config)
			if err != nil {
				t.Fatalf("NewLicenseLibrary(config) error = %v", err)
			}

			if err := ll.AddAll(); err != nil {
				t.Fatalf("AddAll() error = %v", err)
			}
			got, err := IdentifyLicensesInString(tt.input, options, ll)
			if err != nil {
				t.Errorf("identifyLicensesInString() error = %v", err)
			} else if d := cmp.Diff(tt.want.Matches, got.Matches, cmp.AllowUnexported(Match{})); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			} else if d := cmp.Diff(tt.want.Blocks, got.Blocks); d != "" {
				t.Errorf("Didn't get expected result: (-want, +got): %v", d)
			}
		})
	}
}

func Test_mutatorsAreCompatible(t *testing.T) {
	testId1 := "test_id_1"
	testId2 := "test_id_2"
	testId3 := "test_id_3"
	testId4 := "test_id_4"
	testId5 := "test_id_5"
	testId6 := "test_id_6"
	emptyLicense := licenses.License{}
	testLicInfo1 := licenses.LicenseInfo{
		Name: testId1,
	}
	testLicInfo2 := licenses.LicenseInfo{
		Name:             testId2,
		EligibleLicenses: []string{testId1},
	}
	testLicInfo3 := licenses.LicenseInfo{
		Name:             testId3,
		SPDXException:    true,
		EligibleLicenses: []string{testId1},
	}
	testLicInfo4 := licenses.LicenseInfo{
		Name:             testId4,
		EligibleLicenses: []string{testId1},
	}
	testLicInfo5 := licenses.LicenseInfo{
		Name:             testId5,
		SPDXException:    true,
		EligibleLicenses: []string{testId2},
	}
	testLicInfo6 := licenses.LicenseInfo{
		Name:             testId6,
		SPDXException:    true,
		EligibleLicenses: []string{}, // no eligible licenses
	}
	testLic1 := licenses.License{
		LicenseInfo: testLicInfo1,
	}
	testLic2 := licenses.License{
		LicenseInfo: testLicInfo2,
	}
	testLic3 := licenses.License{
		LicenseInfo: testLicInfo3,
		Text:        licenses.LicenseText{},
	}
	testLic4 := licenses.License{
		LicenseInfo: testLicInfo4,
		Text:        licenses.LicenseText{},
	}
	testLic5 := licenses.License{
		LicenseInfo: testLicInfo5,
	}
	testLic6 := licenses.License{
		LicenseInfo: testLicInfo6,
	}

	type args struct {
		ls       []licenses.License
		mutators []licenses.License
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "zero mutators",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{},
			},
			want: true,
		},
		{
			name: "zero licenses, one mutator",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{emptyLicense},
			},
			want: true,
		},
		{
			name: "one license, one mutator without eligibility",
			args: args{
				ls:       []licenses.License{emptyLicense},
				mutators: []licenses.License{emptyLicense},
			},
			want: false,
		},
		{
			name: "one license, one mutator that is eligible",
			args: args{
				ls:       []licenses.License{testLic1},
				mutators: []licenses.License{testLic2},
			},
			want: true,
		},
		{
			name: "one license, two mutators with one spdxexeption and compatible",
			args: args{
				ls:       []licenses.License{testLic1},
				mutators: []licenses.License{testLic2, testLic3},
			},
			want: true,
		},
		{
			name: "one license, two mutators with no spdxexeption and compatible",
			args: args{
				ls:       []licenses.License{testLic1},
				mutators: []licenses.License{testLic2, testLic4},
			},
			want: false,
		},
		{
			name: "one license, two mutators with one spdxexeption and not compatible",
			args: args{
				ls:       []licenses.License{testLic1},
				mutators: []licenses.License{testLic2, testLic5},
			},
			want: false,
		},
		{
			name: "zero licenses, two mutators with one spdxexeption with no eligiblity",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{testLic2, testLic6},
			},
			want: false,
		},
		{
			name: "zero licenses, two mutators with one spdxexeption",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{testLic2, testLic3},
			},
			want: true,
		},
		{
			name: "one license, two mutators without spdxexeption",
			args: args{
				ls:       []licenses.License{testLic1},
				mutators: []licenses.License{testLic2, testLic4},
			},
			want: false,
		},
		{
			name: "zero licenses, three mutators without spdxexeption",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{testLic2, testLic4, testLic4},
			},
			want: false,
		},
		{
			name: "zero licenses, two mutators no mutual eligibility",
			args: args{
				ls:       []licenses.License{},
				mutators: []licenses.License{testLic4, testLic5},
			},
			want: false,
		},
		{
			name: "more than one license",
			args: args{
				ls:       []licenses.License{emptyLicense, emptyLicense},
				mutators: []licenses.License{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mutatorsAreCompatible(tt.args.ls, tt.args.mutators)
			if got != tt.want {
				t.Errorf("mutatorsAreCompatible() got = %v, wanted %v", got, tt.want)
			}
		})
	}
}
