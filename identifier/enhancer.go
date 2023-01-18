// SPDX-License-Identifier: Apache-2.0

package identifier

import (
	"regexp"
	"strings"

	"github.com/IBM/license-scanner/licenses"
)

type Enhancements struct {
	AddNotes       string
	AddTextBlocks  bool
	FlagAcceptable bool
	FlagCopyrights bool
	FlagKeywords   bool
	// FlagKeywords   []string  // TODO: JavaScript used this as a bool and later as a list
}

const AlphaNumericPattern = `/[a-zA-Z0-9]+/`

// CopyrightPattern recognizes a block to be flagged as COPYRIGHT
// const COPYRIGHT_PATTERN = /^[^a-z0-9\n]*(?:All rights reserved\.?\s*)?(?:[ \t]*(?:Copyright|Copr\.?|\(c\)|[\xA9]))+\s+[^\n\r]+(?:[^a-z0-9]*All rights reserved\.?)?/gmi;
// The legacy pattern required one-or-more white-spaces AND one-or-more non-carriage-return chars after Copyright. Here we are minimally requiring just the one white-space (or more...).
const CopyrightPattern = `(?i)[^a-z0-9\n]*(?:All rights reserved\.?\s*)?(?:[ \t]*(?:Copyright|Copr\.?|\(c\)|[\xA9]))+\s+[^\n\r]*(?:[^a-z0-9]*All rights reserved\.?)?`

var (
	CopyrightRegexp    = regexp.MustCompile(CopyrightPattern)
	AlphaNumericRegexp = regexp.MustCompile(AlphaNumericPattern)
)

var DefaultKeywordList = []string{
	`public domain`,
	`Affero`,
	`[a-z]*gpl`,
	`[a-z-]*commercial[a-z]*`,
	`[a-z-]*licen[cs][a-z]*`,
}

// FromOptions adds enabled enhancements (in order)
func FromOptions(licenseResults *IdentifierResults, enhancements Enhancements, licenseLibrary *licenses.LicenseLibrary) error {
	if licenseResults == nil {
		return nil // no-op, no crash
	}

	if enhancements.FlagCopyrights {
		flagCopyrights(licenseResults)
	}
	if enhancements.FlagAcceptable {
		flagAcceptable(licenseResults, licenseLibrary)
	}
	if enhancements.FlagKeywords {
		if err := flagKeywords(licenseResults); err != nil {
			return err
		}
	}
	if len(enhancements.AddNotes) > 0 {
		licenseResults.Notes = enhancements.AddNotes
	}
	if enhancements.FlagAcceptable {
		flagEmptyBlocks(licenseResults)
	}

	return nil
}

func flagCopyrights(licenseResults *IdentifierResults) {
	if licenseResults == nil {
		return
	}
	licenseResults.CopyRightStatements = identifyPatternInBlocks(licenseResults, CopyrightRegexp, "COPYRIGHT")
}

func flagAcceptable(licenseResults *IdentifierResults, licenseLibrary *licenses.LicenseLibrary) {
	// Don't look for acceptable text if no licenses were found.
	if licenseResults == nil || len(licenseResults.Matches) == 0 {
		return
	}

	for _, pattern := range licenseLibrary.AcceptablePatternsMap {
		_ = identifyPatternInBlocks(licenseResults, pattern, "ACCEPTABLE")
	}
}

func flagKeywords(licenseResults *IdentifierResults) error {
	if licenseResults == nil {
		return nil
	}
	keywords := DefaultKeywordList

	re, err := regexp.Compile(`(?i)\b` + strings.Join(keywords, "|"+`\b`))
	if err != nil {
		return err
	}
	licenseResults.KeywordMatches = identifyPatternInBlocks(licenseResults, re, "KEYWORD")

	return nil
}

func flagEmptyBlocks(licenseResults *IdentifierResults) {
	if licenseResults == nil || len(licenseResults.Blocks) == 0 {
		return
	}

	offsetToBlock := 0
	for _, block := range licenseResults.Blocks {
		if len(block.Matches) > 0 {
			offsetToBlock += len(block.Text)
			continue
		}

		if !AlphaNumericRegexp.MatchString(block.Text) {
			block.Matches = []string{"ACCEPTABLE"}
			licenseResults.AcceptablePatternMatches = append(licenseResults.AcceptablePatternMatches, PatternMatch{
				Text: block.Text, Begins: offsetToBlock, Ends: offsetToBlock + len(block.Text) - 1,
			})
		}
		offsetToBlock += len(block.Text)
	}
}

func identifyPatternInBlocks(licenseResults *IdentifierResults, pattern *regexp.Regexp, label string) []PatternMatch {
	if licenseResults == nil {
		return nil
	}
	var patternMatches []PatternMatch

	// Iterate over all the blocks.
	var newBlocks []Block
	offsetToBlock := 0
	for _, block := range licenseResults.Blocks {

		text := block.Text

		// If the block matches anything, move on without searching it.
		if len(block.Matches) > 0 {
			offsetToBlock += len(text)
			newBlocks = append(newBlocks, block) // build new array including old blocks
			continue
		}

		matches := pattern.FindAllStringIndex(text, -1)

		// If there were no matches, move on.
		if len(matches) == 0 {
			offsetToBlock += len(text)
			newBlocks = append(newBlocks, block)
			continue
		}
		// Otherwise, create new blocks out of the matching and remaining text.
		prev := 0
		for _, newBlockMatch := range matches {

			start := newBlockMatch[0]
			end := newBlockMatch[1]

			// If there are pre-match characters, create a block.
			if start > prev {
				newBlocks = append(newBlocks, Block{Text: text[prev:start]})
			}
			// append a block for the match
			match := text[start:end]
			prev = end
			newBlocks = append(newBlocks, Block{Text: match, Matches: []string{label}})
			// create a new pattern match object.
			patternMatches = append(patternMatches, PatternMatch{
				Text: match, Begins: offsetToBlock + start, Ends: offsetToBlock + end - 1,
			})
		}
		if prev < len(text) {
			newBlocks = append(newBlocks, Block{Text: text[prev:]})
		}
		// Increment the offset.
		offsetToBlock += len(text)
	}
	licenseResults.Blocks = newBlocks
	return patternMatches
}
