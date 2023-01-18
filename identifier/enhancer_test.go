// SPDX-License-Identifier: Apache-2.0

//go:build unit

package identifier

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/IBM/license-scanner/licenses"
)

type test struct {
	name    string
	args    args
	want    *IdentifierResults
	wantErr bool
}

type args struct {
	licenseResults *IdentifierResults
	enhancements   Enhancements
	licenseLibrary *licenses.LicenseLibrary
}

func TestFromOptions(t *testing.T) {
	ll, err := licenses.NewLicenseLibrary(nil)
	if err != nil {
		t.Fatalf("NewLicenseLibrary() error = %v", err)
	}

	tests := []test{
		{
			name:    "nils test with no enhancements does not crash (no-op)",
			args:    args{},
			want:    nil,
			wantErr: false,
		},
		{
			name: "nil licenseResults with enhancements does not crash (no-op)",
			args: args{
				enhancements: Enhancements{
					AddNotes:       "Test",
					AddTextBlocks:  true,
					FlagAcceptable: true,
					FlagCopyrights: true,
					FlagKeywords:   true,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "should modify the given IdentifierResults object with Options.Enhancements.AddNotes",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{Text: "This is a xxxlicensxxx test"}},
				},
				enhancements: Enhancements{
					AddNotes: "Test",
				},
				licenseLibrary: ll,
			},
			want: &IdentifierResults{
				Blocks: []Block{{Text: "This is a xxxlicensxxx test"}},
				Notes:  "Test",
			},
			wantErr: false,
		},
		{
			name: "should be able to apply the FlagKeywords enhancement",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{Text: "This is a xxxlicensxxx test"}},
				},
				enhancements: Enhancements{
					FlagKeywords: true,
				},
				licenseLibrary: ll,
			},
			want: &IdentifierResults{
				Blocks:         []Block{{Text: "This is a "}, {Text: "xxxlicensxxx", Matches: []string{"KEYWORD"}}, {Text: " test"}},
				KeywordMatches: []PatternMatch{{Text: "xxxlicensxxx", Begins: 10, Ends: 21}},
			},
			wantErr: false,
		},
		{
			name: "should be able to flag multiple enhancements",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{Text: "This is a xxxlicensxxx test"}},
				},
				enhancements: Enhancements{
					AddNotes:     "A different test note",
					FlagKeywords: true,
				},
				licenseLibrary: ll,
			},
			want: &IdentifierResults{
				Blocks:         []Block{{Text: "This is a "}, {Text: "xxxlicensxxx", Matches: []string{"KEYWORD"}}, {Text: " test"}},
				KeywordMatches: []PatternMatch{{Text: "xxxlicensxxx", Begins: 10, Ends: 21}},
				Notes:          "A different test note",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt

			if err := FromOptions(tt.args.licenseResults, tt.args.enhancements, tt.args.licenseLibrary); (err != nil) != tt.wantErr {
				t.Errorf("FromOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want == nil {
				if tt.args.licenseResults != nil {
					t.Errorf("Wanted nil but didn't not have expected nil args.licenseResults")
				}
			} else if diff := cmp.Diff(*tt.want, *tt.args.licenseResults); diff != "" {
				t.Errorf("Didn't get expected licenseResults (-want, +got): %+v", diff)
			}
		})
	}
}

func Test_flagCopyrights(t *testing.T) {
	tests := []test{
		{
			name: "should find multiple different copyright statements",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "Copyright (c) 2017 James Tanner\nCopyright (c) 2017 IBM",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: "Copyright (c) 2017 James Tanner", Matches: []string{"COPYRIGHT"}},
					{Text: "\n"},
					{Text: "Copyright (c) 2017 IBM", Matches: []string{"COPYRIGHT"}},
				},
				CopyRightStatements: []PatternMatch{
					{Text: "Copyright (c) 2017 James Tanner", Begins: 0, Ends: 30},
					{Text: "Copyright (c) 2017 IBM", Begins: 32, Ends: 53},
				},
			},
		},
		{
			name: `should flag copyright statements that DO NOT include "All Rights Reserved"`,
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "Copyright (c) 2017 James Tanner",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: "Copyright (c) 2017 James Tanner", Matches: []string{"COPYRIGHT"}},
				},
				CopyRightStatements: []PatternMatch{
					{Text: "Copyright (c) 2017 James Tanner", Begins: 0, Ends: 30},
				},
			},
		},
		{
			name: `should flag copyright statements that include "All Rights Reserved"`,
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "Copyright (c) 2017 James Tanner\nAll Rights Reserved.",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: "Copyright (c) 2017 James Tanner\nAll Rights Reserved.", Matches: []string{"COPYRIGHT"}},
				},
				CopyRightStatements: []PatternMatch{
					{Text: "Copyright (c) 2017 James Tanner\nAll Rights Reserved.", Begins: 0, Ends: 51},
				},
			},
		},
		{
			name: "should flag copyright statements when no license matches were found",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "Copyright (c) 2017 James Tanner\n\nNo license here.",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: "Copyright (c) 2017 James Tanner", Matches: []string{"COPYRIGHT"}},
					{Text: "\n\nNo license here."},
				},
				CopyRightStatements: []PatternMatch{
					{Text: "Copyright (c) 2017 James Tanner", Begins: 0, Ends: 30},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flagCopyrights(tt.args.licenseResults)
			if diff := cmp.Diff(*tt.want, *tt.args.licenseResults); diff != "" {
				t.Errorf("Didn't get expected matches (-want, +got): %+v", diff)
			}
		})
	}
}

func Test_flagEmptyBlocks(t *testing.T) {
	tests := []test{
		{
			name: "should mark non-alphanumeric blocks as acceptable",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{
						{Text: `\n\n`},
						{Text: `<>?:"{}[]\\|!@#$%^&*()-_+="  `},
						{Text: "  "},
						{Text: "keyword", Matches: []string{"KEYWORD"}},
						{Text: "."},
					},
					KeywordMatches: []PatternMatch{
						{Text: "keyword", Begins: 32, Ends: 38},
					},
					Notes: "Test",
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: `\n\n`},
					{Text: `<>?:"{}[]\\|!@#$%^&*()-_+="  `},
					{Text: "  "},
					{Text: "keyword", Matches: []string{"KEYWORD"}},
					{Text: "."},
				},
				KeywordMatches: []PatternMatch{
					{Text: "keyword", Begins: 32, Ends: 38},
				},
				Notes: "Test",
				AcceptablePatternMatches: []PatternMatch{
					{Text: `\n\n`, Ends: 3},
					{Text: `<>?:"{}[]\\|!@#$%^&*()-_+="  `, Begins: 4, Ends: 32},
					{Text: "  ", Begins: 33, Ends: 34},
					{Text: ".", Begins: 42, Ends: 42},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flagEmptyBlocks(tt.args.licenseResults)
			if tt.want == nil {
				if tt.args.licenseResults != nil {
					t.Errorf("Wanted nil but didn't not have expected nil args.licenseResults")
				}
			} else if diff := cmp.Diff(*tt.want, *tt.args.licenseResults); diff != "" {
				t.Errorf("Didn't get expected matches (-want, +got): %+v", diff)
			}
		})
	}
}

func Test_flagKeywords(t *testing.T) {
	tests := []test{
		{
			name: "nil test",
			args: args{
				licenseResults: nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "test flag keywords with no keywords",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "Nothing to flag here",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{{Text: "Nothing to flag here"}},
			},
			wantErr: false,
		},
		{
			name: "should be able to flag keywords",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "This is a xxxlicensxxx test",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks:         []Block{{Text: "This is a "}, {Text: "xxxlicensxxx", Matches: []string{"KEYWORD"}}, {Text: " test"}},
				KeywordMatches: []PatternMatch{{Text: "xxxlicensxxx", Begins: 10, Ends: 21}},
			},
			wantErr: false,
		},
		{
			name: "should be able to identify default public domain keywords",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{
						Text: "There is a public domain license in this sentence.",
					}},
				},
			},
			want: &IdentifierResults{
				Blocks: []Block{
					{Text: "There is a "},
					{Text: "public domain", Matches: []string{"KEYWORD"}},
					{Text: " "},
					{Text: "license", Matches: []string{"KEYWORD"}},
					{Text: " in this sentence."},
				},
				KeywordMatches: []PatternMatch{
					{Text: "public domain", Begins: 11, Ends: 23},
					{Text: "license", Begins: 25, Ends: 31},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if err := flagKeywords(tt.args.licenseResults); (err != nil) != tt.wantErr {
				t.Errorf("flagKeywords() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want == nil {
				if tt.args.licenseResults != nil {
					t.Errorf("Wanted nil but didn't not have expected nil args.licenseResults")
				}
			} else if diff := cmp.Diff(*tt.want, *tt.args.licenseResults); diff != "" {
				t.Errorf("Didn't get expected matches (-want, +got): %+v", diff)
			}
		})
	}
}

func Test_identifyPatternInBlocks(t *testing.T) {
	type args struct {
		licenseResults *IdentifierResults
		pattern        *regexp.Regexp
		label          string
	}
	tests := []struct {
		name  string
		args  args
		want  []PatternMatch
		want2 IdentifierResults
	}{
		{
			name: "should be able to identify patterns in blocks",
			args: args{
				licenseResults: &IdentifierResults{
					Blocks: []Block{{Text: "This is a xxxlicensxxx test"}},
				},
				pattern: regexp.MustCompile(`[x]+`),
				label:   "TEST_LABEL",
			},
			want: []PatternMatch{{Text: "xxx", Begins: 10, Ends: 12}, {Text: "xxx", Begins: 19, Ends: 21}},
			want2: IdentifierResults{
				Blocks: []Block{
					{Text: "This is a "},
					{Text: "xxx", Matches: []string{"TEST_LABEL"}},
					{Text: "licens"},
					{Text: "xxx", Matches: []string{"TEST_LABEL"}},
					{Text: " test"},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := identifyPatternInBlocks(tt.args.licenseResults, tt.args.pattern, tt.args.label)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Didn't get expected matches (-want, +got): %+v", diff)
			}
			if diff := cmp.Diff(tt.want2.Blocks[1], tt.args.licenseResults.Blocks[1]); diff != "" {
				t.Errorf("Didn't get expected label (-want, +got): %+v", diff)
			}
			if diff := cmp.Diff(tt.want2, *tt.args.licenseResults); diff != "" {
				t.Errorf("Didn't get expected licenseResults (-want, +got): %+v", diff)
			}
		})
	}
}
