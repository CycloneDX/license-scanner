// SPDX-License-Identifier: Apache-2.0

//go:build unit

package normalizer

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNormalizationData_NormalizeText(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{
		{
			n: &NormalizationData{
				OriginalText: "\n" +
					"\n" +
					"\n" +
					"Permission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>> <<match=.*>> <<beginOptional>>software <<match=and/?o?r?>> associated documentation<<endOptional>>" +
					" <<beginOptional>>SOFTWARE<<endOptional>> <<beginOptional>><<match=files?>> (the <<match=\"?Software\"?|\"?Materials\"?>>),<<endOptional>> to deal in the <<match=Software|Code|Materials>> without restriction," +
					" including without <<match=limitation,?>> <<beginOptional>>on<<endOptional>> the <<beginOptional>>irrevocable, perpetual, worldwide, and royalty-free<<endOptional>> rights to use, copy, modify, merge, publish, distribute," +
					" <<beginOptional>>sublicense,<<endOptional>> <<beginOptional>>distribute with modifications,<<endOptional>> <<beginOptional>><<match=sub ?license,?>><<endOptional>> <<beginOptional>>display, perform, create derivative works from<<endOptional>>" +
					" <<match=and ?/ ?or>> sell copies of the <<match=Software|code|Materials>>, <<beginOptional>> both in source<<endOptional>> and <<beginOptional>>object code form, and<<endOptional>> to permit persons to whom" +
					" the <<match=Software|code|materials>> <<match=is|are>> furnished to do so, subject to the following <<match=conditions|disclaimer>>:\n" +
					"\n" +
					"<<beginOptional>>\n" +
					"The above copyright notice<<match= and|,>> this permission notice <<beginOptional>>and the disclaimer statement<<endOptional>> <<beginOptional>>(including the next\n" +
					"paragraph)<<endOptional>> <<match=shall|must>> be included in all copies or substantial portions of the <<match=Software|code|materials>>.\n" +
					"<<endOptional>>\n",
			},
			e: &NormalizationData{
				NormalizedText: "permission is hereby granted,free of charge,to any person obtaining a copy of <<this|the>> <<.{0,144}>> <<omitable>>software <<and/?o?r?>> associated documentation<</omitable>>" +
					" <<omitable>>software<</omitable>> <<omitable>><<files?>> (the <<'?software'?|'?materials'?>>),<</omitable>> to deal in the <<software|code|materials>> without restriction," +
					"including without <<limitation,?>> <<omitable>>on<</omitable>> the <<omitable>>irrevocable,perpetual,worldwide,and royalty-free<</omitable>> rights to use,copy,modify,merge,publish,distribute," +
					"<<omitable>>sublicense,<</omitable>> <<omitable>>distribute with modifications,<</omitable>> <<omitable>><<sub ?license,?>><</omitable>> <<omitable>>display,perform,create derivative works from<</omitable>>" +
					" <<and ?/ ?or>> sell copies of the <<software|code|materials>>,<<omitable>> both in source<</omitable>> and <<omitable>>object code form,and<</omitable>> to permit persons to whom" +
					" the <<software|code|materials>> <<is|are>> furnished to do so,subject to the following <<conditions|disclaimer>>:" +
					"<<omitable>> " +
					"the above copyright notice<< and|,>> this permission notice <<omitable>>and the disclaimer statement<</omitable>> <<omitable>>(including the next " +
					"paragraph)<</omitable>> <<shall|must>> be included in all copies or substantial portions of the <<software|code|materials>>. " +
					"<</omitable>>",
			},
		},
		{
			name: "quoted match any 100",
			n: &NormalizationData{
				OriginalText: `quoted match test: <<var;name="test";original="Test  ";match=".{0,100}">> any100`,
			},
			e: &NormalizationData{
				NormalizedText: "quoted match test:<<.{0,100}?>> any100",
			},
		},
		{
			name: "quoted match any 5000",
			n: &NormalizationData{
				OriginalText: `quoted match test: <<var;name="test";original="Test  ";match=".{0,5000}">> any5000`,
			},
			e: &NormalizationData{
				NormalizedText: "quoted match test:<<.{0,1000}?>> any5000",
			},
		},
		{
			name: "html tags without runes",
			n: &NormalizationData{
				OriginalText: `runes in Commissariat a l'energie atomique then htmltag <<beginOptional>>X<#why>Z<<endOptional>> .`,
			},
			e: &NormalizationData{
				NormalizedText: `runes in commissariat a l'energie atomique then htmltag <<omitable>>x♢z<</omitable>> .`,
			},
		},
		{
			name: "runes causing match position errors now fixed",
			n: &NormalizationData{
				OriginalText: `runes in Commissariat à l'énergie atomique then htmltag <<beginOptional>>X<#why>Z<<endOptional>> .`,
			},
			e: &NormalizationData{
				NormalizedText: "runes in commissariat à l'énergie atomique then htmltag <<omitable>>x♢z<</omitable>> .",
			},
		},
		{
			name: "Character that changes length should not cause out-of-bounds with indexMap",
			n: &NormalizationData{
				OriginalText: "\n\xfe\nx\n",
			},
			e: &NormalizationData{
				NormalizedText: "x",
			},
		},
		{
			name: "Character that changes length should not cause out-of-bounds with indexMap (char 0)",
			n: &NormalizationData{
				OriginalText: "\xfe\nx\n",
			},
			e: &NormalizationData{
				NormalizedText: "x",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.n.NormalizeText()
			if err != nil {
				t.Errorf("NormalizeText() error: %v", err)
			}
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_removeNoteTag(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: "Something to note about <<note: Please be careful with this license>>",
		},
		e: &NormalizationData{
			NormalizedText: "something to note about  ",
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.removeNoteTags()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_WildcardMatching(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: "replaceable: <<match=.+>> goes here",
		},
		// TODO: must capture the group
		// group_number: 1,
		// matches: '.{1,144}'
		e: &NormalizationData{
			NormalizedText: "replaceable: <<.{1,144}>> goes here",
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.limitWildcardMatching()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_OptionalWildcardMatching(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: "replaceable: <<match=.*>> goes here",
		},
		e: &NormalizationData{
			NormalizedText: "replaceable: <<.{0,144}>> goes here",
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.limitOptionalWildcardMatching()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_CaptureReplaceableTextSections(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: "replaceable: <<var;name=replaceableSection;original=some text;match=.+>> goes here",
		},
		e: &NormalizationData{
			CaptureGroups: []*CaptureGroup{{
				GroupNumber: 1,
				Name:        "replaceablesection",
				Original:    "some text",
				Matches:     ".+?",
			}},
			NormalizedText: "replaceable: <<.+?>> goes here",
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.captureReplaceableTextSections()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
			if d := cmp.Diff(tc.e.CaptureGroups, tc.n.CaptureGroups); d != "" {
				t.Errorf("Didn't get expected Capture Groups: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_StandardizeOmitableTags(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: "omitable: <<beginOptional;name=optionalSection>> optional text <<endOptional>> goes here",
		},
		e: &NormalizationData{
			NormalizedText: "omitable: <<omitable>> optional text <</omitable>> goes here",
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.standardizeOmitableTags()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_removeCodeCommentIndicators(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{
		{
			name: "should satisfy SPDX matching guideline 6.1.1 (Code Comment Indicators)",
			n: &NormalizationData{
				OriginalText: "/* \n * wide block\n */\n/* dense block */\n// comment\n<!-- HTML comment -->\n# python",
			},
			e: &NormalizationData{
				NormalizedText: "wide block dense block comment html comment python",
				IndexMap:       []int{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 43, 44, 45, 46, 47, 48, 49, 50, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 75, 76, 77, 78, 79, 80},
			},
		},
		{
			name: "comments",
			n: &NormalizationData{
				OriginalText: "/* \n * comment\n */\n/* comment */\n// comment\n<!-- comment -->",
			},
			e: &NormalizationData{
				NormalizedText: "comment comment comment comment",
				IndexMap:       []int{7, 8, 9, 10, 11, 12, 13, 14, 22, 23, 24, 25, 26, 27, 28, 29, 36, 37, 38, 39, 40, 41, 42, 43, 49, 50, 51, 52, 53, 54, 55},
			},
		},
		{
			name: "comments abcdefg",
			n: &NormalizationData{
				OriginalText: "/* a */\n/*\n * b\n */\n//c\n//d\n<!--e-->\n<!--f-->\n# g",
			},
			e: &NormalizationData{
				NormalizedText: "a b c d e f g",
				IndexMap:       []int{3, 4, 14, 15, 22, 23, 26, 27, 32, 33, 41, 42, 48},
			},
		},
		{
			name: "line comment",
			n: &NormalizationData{
				OriginalText: "  // line comment // test \n// test2 // test3",
			},
			e: &NormalizationData{
				NormalizedText: "line comment // test test2 // test3",
				IndexMap:       []int{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43},
			},
		},
		{
			name: "block comment",
			n: &NormalizationData{
				OriginalText: "   /* this is a block comment */   ", // start/end comment tags are caught
			},
			e: &NormalizationData{
				NormalizedText: "this is a block comment",
				IndexMap:       []int{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28},
			},
		},
		{
			name: "not block comment",
			n: &NormalizationData{
				OriginalText: "  this is /* not */ recognized (start or end)      ", // extra non-whitespace outer chars
			},
			e: &NormalizationData{
				NormalizedText: "this is /* not */ recognized (start or end)",
				IndexMap:       []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44}, // etc truncated
			},
		},
		{
			name: "inside block comment",
			n: &NormalizationData{
				OriginalText: " * part of a comment",
			},
			e: &NormalizationData{
				NormalizedText: "part of a comment",
				IndexMap:       []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
			},
		},
		{
			name: "inside block comment end",
			n: &NormalizationData{
				OriginalText: "not sure why but remove this*",
			},
			e: &NormalizationData{
				NormalizedText: "not sure why but remove this",
				IndexMap:       []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}, // etc truncated
			},
		},
		{
			name: "inside block comment hash",
			n: &NormalizationData{
				OriginalText: " # part of a comment",
			},
			e: &NormalizationData{
				NormalizedText: "part of a comment",
				IndexMap:       []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
			},
		},
		{
			name: "inside block comment hash end",
			n: &NormalizationData{
				OriginalText: "but not removing this one#",
			},
			e: &NormalizationData{
				NormalizedText: "but not removing this one#",
				IndexMap:       []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.n.NormalizeText()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
			if d := cmp.Diff(tc.e.IndexMap, tc.n.IndexMap); d != "" {
				t.Errorf("Didn't get expected IndexMap: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_removeHTMLTags(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{
		{
			name: "negative lookahead to keep http links replace other tokens with placeholder symbol",
			n: &NormalizationData{
				OriginalText: "<http>\n<head>This is a head</head>",
			},
			e: &NormalizationData{
				NormalizedText: "<http> ♢this is a head♢",
			},
		},
		{
			name: "negative lookahead with http at end of string",
			n: &NormalizationData{
				OriginalText: "<http>",
			},
			e: &NormalizationData{
				NormalizedText: "<http>",
			},
		},
		{
			name: "negative lookahead with string too short",
			n: &NormalizationData{
				OriginalText: "<http",
			},
			e: &NormalizationData{
				NormalizedText: "<http",
			},
		},
		{
			name: "tag with tag inside we skip",
			n: &NormalizationData{
				OriginalText: "<link < test >",
			},
			e: &NormalizationData{
				NormalizedText: "<link < test >",
			},
		},
		{
			name: "template markers not to be messed with",
			n: &NormalizationData{
				OriginalText: "<<link>> <test>",
			},
			e: &NormalizationData{
				NormalizedText: "<<link>> ♢",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.n.NormalizeText()
			if err != nil {
				t.Fatalf("Normalize error: %v", err)
			}
			tc.n.removeHTMLTags()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceDashLikeCharacters(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("equal: -\u002D\u2010\u2011\u2013\u2014\u2015\u2212\uFE58\uFE63\uFE0D"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("equal: -----------"),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.replaceDashLikeCharacters()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceQuoteLikeCharacters(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("equal: '' ' \u0022 \u0027 \u0060 \u00B4 \u2018 \u2019 \u201C \u201D"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("equal: ' ' ' ' ' ' ' ' ' '"),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.replaceQuoteLikeCharacters()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_standardizeToHTTP(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("https://thesecurereference.com"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("http://thesecurereference.com"),
		},
	}, {
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("http://theunsecurereference.com"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("http://theunsecurereference.com"),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.standardizeToHTTP()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceBulletsAndNumbering(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{
		{
			name: "IsTemplate=false",
			n: &NormalizationData{
				OriginalText: "a) letter-paren \nb. letter-dot \n1. number \n* star \n- dash",
			},
			e: &NormalizationData{
				NormalizedText: "a) letter-paren \nb. letter-dot \n1. number \nstar \ndash",
			},
		},
		{
			name: "IsTemplate=true",
			n: &NormalizationData{
				OriginalText: "a) letter-paren \nb. letter-dot \n1. number \n* star \n- dash",
				IsTemplate:   true,
			},
			e: &NormalizationData{
				NormalizedText: "<<.{0,20}?>>letter-paren <<.{0,20}?>>letter-dot <<.{0,20}?>>number \n<<.{0,20}?>>star \n<<.{0,20}?>>dash",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.n.replaceBulletsAndNumbering()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceSplitWords(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("split-\nword"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("splitword"),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.reconnectSplitWords()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_removeHorizontalRulePattern(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("dashes\n-----\nequals\n=====\nstars\n******"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("dashes\n \nequals\n \nstars\n "),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.removeHorizontalRules()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceCopyrightSymbols(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("equal: © (c) (C) copyright"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("equal: copyright copyright copyright copyright"),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.replaceCopyrightSymbols()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_removeOddCharacters(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("Trademark \u0099  Not sign ¬"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("trademark    not sign  "),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.removeOddCharacters()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_replaceWhitespace(t *testing.T) {
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{{
		n: &NormalizationData{
			OriginalText: fmt.Sprintf("\nThis text   has \tsome \nwhitespace.\n"),
		},
		e: &NormalizationData{
			NormalizedText: fmt.Sprintf("this text has some whitespace."),
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc.n.replaceWhitespace()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}

func TestNormalizationData_NormalizeText_Replacement_Words(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name string
		n    *NormalizationData
		e    *NormalizationData
	}{
		{
			n: &NormalizationData{
				OriginalText: "This licence license organisation organisation to redistributions redistribution",
			},
			e: &NormalizationData{
				NormalizedText: "this license license organization organization to redistribution redistribution",
			},
		},
		{
			n: &NormalizationData{
				OriginalText: "This license organisation to redistribution",
			},
			e: &NormalizationData{
				NormalizedText: "this license organization to redistribution",
			},
		},
		{
			n: &NormalizationData{
				OriginalText: "This licence organization to redistributions ",
			},
			e: &NormalizationData{
				NormalizedText: "this license organization to redistribution ",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.n.replaceVarietalWordSpellings()
			if d := cmp.Diff(tc.e.NormalizedText, tc.n.NormalizedText); d != "" {
				t.Errorf("Didn't get expected Normalized text: %s", fmt.Sprintf("(-want, +got): %s", d))
			}
		})
	}
}
