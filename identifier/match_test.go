// SPDX-License-Identifier: Apache-2.0

//go:build unit

package identifier

import (
	"testing"

	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

func Test_generateRegexFromNormalizedText(t *testing.T) {
	type args struct {
		originalPattern string
	}
	tests := []struct {
		name      string
		args      args
		matches   string
		wantMatch bool
	}{
		{
			name: "quoted match using optional quotes",
			args: args{
				originalPattern: `THIS IS <<match=""?AS IS,?"?">> LIMITATION`,
			},
			matches:   `this is 'as is' limitation`,
			wantMatch: true,
		},
		{
			name: "quoted match without using optional quotes",
			args: args{
				originalPattern: `THIS IS <<match=""?AS IS,?"?">> LIMITATION`,
			},
			matches:   "this is as is limitation",
			wantMatch: true,
		},
		{
			name: "quoted match with single quotes and optional comma",
			args: args{
				originalPattern: `THIS IS <<match="'AS IS,?'">> LIMITATION`,
			},
			matches:   "this is 'as is,' limitation",
			wantMatch: true,
		},
		{
			name: "unquoted match using optional quotes",
			args: args{
				originalPattern: `THIS IS <<match="?AS IS,?"?>> LIMITATION`,
			},
			matches:   "this is 'as is' limitation",
			wantMatch: true,
		},
		{
			name: "unquoted match without using optional quotes",
			args: args{
				originalPattern: `THIS IS <<match="?AS IS,?"?>> LIMITATION`,
			},
			matches:   "this is as is limitation",
			wantMatch: true,
		},
		{
			name: "regex with match",
			args: args{
				originalPattern: "including without <<match=limitation,?>>",
			},
			matches:   "the Software without restriction, including without limitation the rights to\n",
			wantMatch: true,
		},
		{
			name: "regex with match no space separation still matches",
			args: args{
				originalPattern: "including without <<match=limitation,?>>",
			},
			matches:   "the Software without restriction, including withoutlimitation the rights to\n",
			wantMatch: true,
		},
		{
			name: "regex with match extra space separation does match (originally did not)",
			args: args{
				originalPattern: "including without <<match=limitation,?>>",
			},
			matches:   "the Software without restriction, including without  limitation the rights to\n",
			wantMatch: true,
		},
		{
			name: "match 5000 needs to be split into 1000 or less",
			args: args{
				originalPattern: `<<beginOptional>><<var;name="title";original="BSD Zero Clause License";match="(BSD Zero[ -]Clause|Zero[ -]Clause BSD)( License)?( \(0BSD\))?">>

<<endOptional>> <<var;name="copyright";original="Copyright (C) YEAR by AUTHOR EMAIL  ";match=".{0,5000}">>

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.`,
			},
			matches:   ` bsd zero-clause license(0bsd) ...allows anything here... permission to use,copy,modify,and/or distribute this software for any purpose with or without fee is hereby granted.`,
			wantMatch: true,
		},
		{
			name: "pointy brackets in double pointy brackets",
			args: args{
				originalPattern: `<<beginOptional>><<<endOptional>> abc<<beginOptional>> ><<endOptional>>`,
			},
			matches:   `< abc> `,
			wantMatch: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizer.NewNormalizationData(tt.args.originalPattern, true)
			err := normalized.NormalizeText()
			if err != nil {
				t.Errorf("NormalizeText() error = %v", err)
			}

			got, err := licenses.GenerateRegexFromNormalizedText(normalized.NormalizedText)
			if err != nil {
				t.Fatalf("generateRegexFromNormalizedText() error = %v", err)
			}
			result := got.FindAllStringIndex(tt.matches, -1)
			if tt.wantMatch {
				if len(result) == 0 {
					t.Errorf("generateRegexFromNormalizedText() got = %v, want match with %v", got, tt.matches)
				} else {
					t.Logf("generateRegexFromNormalizedText() matches: %v", tt.matches[result[0][0]:result[0][1]])
				}
			} else {
				if len(result) == 0 {
					t.Logf("generateRegexFromNormalizedText() got = %v, no match as expected", got)
				} else {
					t.Errorf("Did not want match but generateRegexFromNormalizedText() matches: %v", tt.matches[result[0][0]:result[0][1]])
				}
			}
		})
	}
}
