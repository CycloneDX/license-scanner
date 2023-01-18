// SPDX-License-Identifier: Apache-2.0

package identifier

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/mrutkows/sbom-utility/log"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

var (
	Logger     = log.NewLogger(log.INFO)
	nonAlphaRE = regexp.MustCompile(`^[^A-Za-z0-9]*$`)
)

type Options struct {
	ForceResult  bool
	OmitBlocks   bool
	Enhancements Enhancements
}

type licenseMatch struct {
	LicenseId string
	Match     Match
}

type Match struct {
	Begins int
	Ends   int
}

type PatternMatch struct {
	Text   string
	Begins int
	Ends   int
}

type IdentifierResults struct {
	Matches                  map[string][]Match
	Blocks                   []Block
	File                     string
	OriginalText             string
	NormalizedText           string
	Hash                     normalizer.Digest
	Notes                    string
	AcceptablePatternMatches []PatternMatch
	KeywordMatches           []PatternMatch
	CopyRightStatements      []PatternMatch
}

type Block struct {
	Text    string
	Matches []string
}

func Identify(options Options, licenseLibrary *licenses.LicenseLibrary, normalizedData normalizer.NormalizationData) (IdentifierResults, error) {
	// find the licenses in the normalized text and return a list of SPDX IDs
	// in case of an error, return as much as we have along with an error
	licenseResults, err := findAllLicensesInNormalizedData(licenseLibrary, normalizedData)
	if err != nil {
		return IdentifierResults{}, err
	}

	if err := FromOptions(&licenseResults, options.Enhancements, licenseLibrary); err != nil {
		return IdentifierResults{}, err
	}

	if err := applyMutatorLicenses(licenseLibrary.LicenseMap, &licenseResults); err != nil {
		return IdentifierResults{}, err
	}

	if options.OmitBlocks {
		licenseResults.Blocks = []Block{}
	}

	return licenseResults, err
}

func IdentifyLicensesInString(input string, options Options, licenseLibrary *licenses.LicenseLibrary) (IdentifierResults, error) {
	// instantiate normalizedData with the input license text
	normalizedData := normalizer.NormalizationData{
		OriginalText: input,
	}

	// normalize the input license text
	if err := normalizedData.NormalizeText(); err != nil {
		return IdentifierResults{}, err
	}

	return Identify(options, licenseLibrary, normalizedData)
}

func IdentifyLicensesInFile(filePath string, options Options, licenseLibrary *licenses.LicenseLibrary) (IdentifierResults, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return IdentifierResults{}, err
	}
	if fi.Size() > 1000000 {
		return IdentifierResults{}, fmt.Errorf("file too large (%v > 1000000)", fi.Size())
	}

	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return IdentifierResults{}, err
	}
	input := string(b)

	result, err := IdentifyLicensesInString(input, options, licenseLibrary)
	result.File = filePath
	return result, err
}

func IdentifyLicensesInDirectory(dirPath string, options Options, licenseLibrary *licenses.LicenseLibrary) (ret []IdentifierResults, err error) {
	var lfs []string

	if err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
			return err
		}
		if !d.IsDir() {
			info, _ := d.Info()
			if info.Size() > 0 {
				lfs = append(lfs, path)
			}
		}
		return nil
	}); err != nil {
		fmt.Printf("error walking the path %v: %v\n", dirPath, err)
		return nil, err
	}

	// errGroup to do the work in parallel until error
	workers := errgroup.Group{}
	workers.SetLimit(10)
	ch := make(chan IdentifierResults, 10)

	// WaitGroup to know when we have all the results
	waitForResults := sync.WaitGroup{}
	waitForResults.Add(1)

	// Start receiving the results until channel closes
	go func() {
		for ir := range ch {
			ret = append(ret, ir)
		}
		waitForResults.Done()
	}()

	// Loop using a worker to send results to a channel
	for _, lf := range lfs {
		lf := lf
		workers.Go(func() error {
			ir, err := IdentifyLicensesInFile(lf, options, licenseLibrary)
			if err == nil {
				ch <- ir
			}
			return err
		})
	}

	// Close the channel when done or error
	go func() {
		err = workers.Wait()
		close(ch)
	}()

	// Make sure we got all the results
	waitForResults.Wait()
	return ret, err
}

func findAllLicensesInNormalizedData(licenseLibrary *licenses.LicenseLibrary, normalizedData normalizer.NormalizationData) (IdentifierResults, error) {
	// initialize the result with original license text, normalized license text, and hash (md5, sha256, and sha512)
	ret := IdentifierResults{
		OriginalText:   normalizedData.OriginalText,
		NormalizedText: normalizedData.NormalizedText,
		Hash:           normalizedData.Hash,
	}

	// LicenseID-to-matches map to return
	ret.Matches = make(map[string][]Match)
	// List with LicenseID and indexes for generating text blocks
	var licensesMatched []licenseMatch

	for id, lic := range licenseLibrary.LicenseMap {
		matches, err := findLicenseInNormalizedData(lic, normalizedData, licenseLibrary)
		if err != nil {
			return ret, err
		}

		// Sort the matches slice by start and end index.
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Begins != matches[j].Begins {
				return matches[i].Begins < matches[j].Begins
			} else {
				return matches[i].Ends < matches[j].Ends
			}
		})

		for i := range matches {
			if i > 0 && matches[i] == matches[i-1] {
				continue // remove duplicates
			}
			licensesMatched = append(licensesMatched, licenseMatch{LicenseId: id, Match: matches[i]})
			ret.Matches[id] = append(ret.Matches[id], matches[i])
		}
	}

	// Generate Blocks.
	blocks, err := generateTextBlocks(normalizedData.OriginalText, licensesMatched)
	if err != nil {
		return ret, err
	}
	ret.Blocks = blocks

	return ret, nil
}

func findLicenseInNormalizedData(lic licenses.License, normalizedData normalizer.NormalizationData, ll *licenses.LicenseLibrary) (licenseMatches []Match, err error) {
	// TODO: If we are not using the match blocks, etc, then do the faster alias checks first.
	// Get the license pattern matches.
	licenseMatches, err = findPatterns(lic.PrimaryPatterns, normalizedData, licenseMatches, ll)
	if err != nil {
		return licenseMatches, err
	}

	// If we don't already have a more interesting match, then see if there is an alias hit
	if len(licenseMatches) == 0 {
		licenseMatches = findAnyAlias(lic.Aliases, normalizedData, licenseMatches)
	}

	// If we don't already have a more interesting match, then see if there is a URL hit
	if len(licenseMatches) == 0 {
		licenseMatches = findAnyURL(lic.URLs, normalizedData, licenseMatches)
	}

	// If there were no results, return null.
	if len(licenseMatches) == 0 {
		return nil, nil
	}

	// If there are associated patterns, check those.
	return findPatterns(lic.AssociatedPatterns, normalizedData, licenseMatches, ll)
}

// findAny finds one matching string which meets word boundary conditions (and url conditions)
func findAny(ss []string, normalized normalizer.NormalizationData, isURL bool, licenseMatches []Match) []Match {
	for _, s := range ss {
		next := 0
		for i := strings.Index(normalized.NormalizedText, s); i > -1; i = strings.Index(normalized.NormalizedText[next:], s) {
			i = next + i // position in the full normalized text string
			next = i + 1 // if we continue to loop, start one char after the last hit

			begin, end, found := findBoundaries(i, s, normalized, isURL)
			if found {
				return appendIndexMappedMatch(begin, end, normalized, licenseMatches)
			}
		}
	}
	return licenseMatches
}

func findBoundaries(start int, s string, nd normalizer.NormalizationData, isURL bool) (begin int, end int, ok bool) {
	begin, ok = findBeginBoundary(start, nd, isURL)
	if !ok {
		return -1, -1, false
	}

	end, ok = findEndBoundary(start, s, nd, isURL)
	if !ok {
		return -1, -1, false
	}

	return begin, end, true
}

func findBeginBoundary(start int, nd normalizer.NormalizationData, isURL bool) (begin int, ok bool) {
	// Starting at position zero is always an ok boundary
	if start == 0 {
		return 0, true
	}
	begin = start

	// First scan to include URL prefixes https?://(www.)?
	if isURL {
		begin = includeURLPrefix(begin, nd)
		if begin == 0 {
			return 0, true // position 0 boundary
		}
	}

	begin -= 1
	if begin == 0 {
		return 0, true
	}

	c := nd.NormalizedText[begin]
	if c == '(' {
		begin -= 1
		if begin == 0 {
			return 0, true
		}
		c = nd.NormalizedText[begin]
	}

	switch { // Allows anything except a-z0-9
	case c >= 'a' && c <= 'z':
		return -1, false
	case c >= '0' && c <= '9':
		return -1, false
	}

	return begin, true // Space-paren word boundary
}

func findEndBoundary(start int, s string, nd normalizer.NormalizationData, isURL bool) (end int, ok bool) {
	end = start + len(s)
	max := len(nd.NormalizedText)

	if end >= max {
		return end, true // end of string is ok boundary
	}

	// if isURL then take additional suffix fragments like URL/alphas/digits/dots/dashes-under_scores/ as part of the URL
	if isURL {
		for ; end < max; end++ {
			c := nd.NormalizedText[end]
			switch {
			case c >= 'a' && c <= 'z':
				continue
			case c >= '0' && c <= '9':
				continue
			}
			switch c {
			case '.', '-', '_', '/':
				continue
			}
			break // break loop when we stop finding a-z0-9_-./
		}
	}

	if end < max && nd.NormalizedText[end] == ')' {
		end += 1 // include the end parens
	}

	// Need word boundary if not the very end of the normalized text
	if end < max {
		c := nd.NormalizedText[end]
		switch { // Allows anything except a-z0-9
		case c >= 'a' && c <= 'z':
			return -1, false
		case c >= '0' && c <= '9':
			return -1, false
		}
	}

	return end, true // found an ok boundary
}

func includeURLPrefix(begin int, nd normalizer.NormalizationData) int {
	wwwDot := "www."
	length := len(wwwDot)
	if begin >= length && wwwDot == nd.NormalizedText[begin-length:begin] {
		// Add the optional www. prefix to the match
		begin = begin - length
	}

	httpSlashSlash := "http://" // normalizer drops the 's', URLs are cut at ://
	length = len(httpSlashSlash)
	if begin >= length && httpSlashSlash == nd.NormalizedText[begin-length:begin] {
		// Add the optional http:// prefix to the match
		begin = begin - length
	}
	return begin
}

func appendIndexMappedMatch(begin int, end int, normalizedData normalizer.NormalizationData, licenseMatches []Match) []Match {
	indexMapLen := len(normalizedData.IndexMap)
	if end < indexMapLen {
		return append(licenseMatches, Match{Begins: normalizedData.IndexMap[begin], Ends: normalizedData.IndexMap[end]})
	} else {
		// End of map is out of range, so use the last index in the map
		return append(licenseMatches, Match{Begins: normalizedData.IndexMap[begin], Ends: normalizedData.IndexMap[indexMapLen-1]})
	}
}

func findAnyAlias(urls []string, normalized normalizer.NormalizationData, licenseMatches []Match) []Match {
	return findAny(urls, normalized, false, licenseMatches)
}

func findAnyURL(urls []string, normalized normalizer.NormalizationData, licenseMatches []Match) []Match {
	return findAny(urls, normalized, true, licenseMatches)
}

func findPatterns(patterns []*licenses.PrimaryPatterns, normalizedData normalizer.NormalizationData, licenseMatches []Match, ll *licenses.LicenseLibrary) ([]Match, error) {
	// errGroup to do the work in parallel until error
	workers := errgroup.Group{}
	workers.SetLimit(10)
	ch := make(chan []Match, 10)

	// WaitGroup to know when we have all the results
	waitForResults := sync.WaitGroup{}
	waitForResults.Add(1)

	// Start receiving the results until channel closes
	go func() {
		for patternMatches := range ch {
			if len(patternMatches) > 0 {
				licenseMatches = append(licenseMatches, patternMatches...)
			}
		}
		waitForResults.Done()
	}()

	// Loop with the slow part using a worker to send results to a channel
	for _, pattern := range patterns {
		ppk := licenses.LicensePatternKey{
			FilePath: pattern.FileName,
		}
		preChecksRequired := ll.PrimaryPatternPreCheckMap[ppk]
		if preChecksRequired != nil && !PassedStaticBlocksChecks(preChecksRequired.StaticBlocks, normalizedData) {
			continue
		}
		p := pattern
		nD := normalizedData
		workers.Go(func() error {
			patternMatches, err := FindMatchingPatternInNormalizedData(p, nD)
			if err == nil {
				ch <- patternMatches
			}
			return err
		})
	}

	// Close the channel when done or error
	var err error
	go func() {
		err = workers.Wait()
		close(ch)
	}()

	// Make sure we got all the results
	waitForResults.Wait()
	return licenseMatches, err
}

func FindMatchingPatternInNormalizedData(matchingPattern *licenses.PrimaryPatterns, normalized normalizer.NormalizationData) (results []Match, err error) {
	re, err := licenses.GenerateMatchingPatternFromSourceText(matchingPattern)
	if err != nil || re == nil {
		return results, err
	}

	matches := re.FindAllStringIndex(normalized.NormalizedText, -1)
	for _, match := range matches {
		// Create the result object, with the start and end points in the original text.
		if match[1] < len(normalized.IndexMap) {
			results = append(results, Match{Begins: normalized.IndexMap[match[0]], Ends: normalized.IndexMap[match[1]-1]})
		} else {
			// End of map is out of range, so use the last index in the map
			results = append(results, Match{Begins: normalized.IndexMap[match[0]], Ends: normalized.IndexMap[len(normalized.IndexMap)-1]})
		}
	}

	return results, err
}

// PassedStaticBlocksChecks verifies static blocks are present, if any
func PassedStaticBlocksChecks(staticBlocks []string, nd normalizer.NormalizationData) bool {
	for i := range staticBlocks {
		// If the input does not contain a static block, stop immediately and return false.
		if !strings.Contains(nd.NormalizedText, staticBlocks[i]) {
			return false
		}
	}
	return true
}

func generateTextBlocks(originalText string, matches []licenseMatch) ([]Block, error) {
	// If there were no license results or licenses found, return with a single block.
	if len(matches) == 0 {
		return []Block{{Text: originalText}}, nil
	}

	var blocks []Block
	lastEnd := 0
	for _, nextMatch := range matches {

		// Create the block for everything leading up to the new match.
		if lastEnd < nextMatch.Match.Begins {
			blocks = appendNewBlock(blocks, originalText[lastEnd:nextMatch.Match.Begins], "")
			lastEnd = nextMatch.Match.Begins
		}

		begin := nextMatch.Match.Begins
		if begin < lastEnd {
			begin = lastEnd
		}

		nextEnd := nextMatch.Match.Ends + 1
		if nextEnd > lastEnd {
			if nextEnd > len(originalText) {
				blocks = appendNewBlock(blocks, originalText[begin:], nextMatch.LicenseId)
			} else {
				blocks = appendNewBlock(blocks, originalText[begin:nextEnd], nextMatch.LicenseId)
			}
			lastEnd = nextEnd
		}
	}
	if lastEnd < len(originalText) {
		blocks = appendNewBlock(blocks, originalText[lastEnd:], "")
	}

	return blocks, nil
}

func appendNewBlock(blocks []Block, newBlockText string, licenseId string) []Block {
	numBlocks := len(blocks)
	if numBlocks > 0 {
		prevBlock := &blocks[numBlocks-1]
		if len(prevBlock.Matches) == 1 && prevBlock.Matches[0] == licenseId {
			// Blocks which are functionally identical to the previous block should also be appended.
			prevBlock.Text += newBlockText
			return blocks
		} else if licenseId == "" && nonAlphaRE.MatchString(newBlockText) {
			// Unmatched blocks containing no alphanumeric text, should be appended to the previous block.
			prevBlock.Text += newBlockText
			return blocks
		}
	}

	var newBlock Block
	newBlock.Text = newBlockText
	if licenseId != "" {
		newBlock.Matches = []string{licenseId}
	}
	blocks = append(blocks, newBlock)

	return blocks
}

func applyMutatorLicenses(allLicenses licenses.LicenseMap, licenseResults *IdentifierResults) error {
	var previousLicenses []licenses.License
	var previousMutators []licenses.License
	var affectedBlocks []Block
	appliedMutation := false

	// Iterate over all blocks.
	for _, b := range licenseResults.Blocks {

		// Previous state information:
		currentLicenses := previousLicenses
		currentMutators := previousMutators
		var newLicenses []licenses.License
		var newMutators []licenses.License

		// TODO: // Ignore any Blocks which are not relevant to licenses.
		// TODO: check for a bunch of things to ignore
		if len(b.Matches) == 0 {
			// Apply mutators to previous state.

			// TODO: This invalid state should be refactored away
			if len(previousLicenses) > 1 {
				return fmt.Errorf("Invalid state. Should be only one previous license.")
			}

			if len(previousLicenses) > 0 {
				appliedMutation = appliedMutation || applyMutatorsInAffectedBlocks(affectedBlocks, previousLicenses[0], previousMutators)
			}

			// Set up new state.
			previousLicenses, previousMutators, affectedBlocks = nil, nil, nil
			continue
		}

		// Collate all the matches into licenses and mutators.
		for _, m := range b.Matches {
			lic := allLicenses[m]
			if lic.LicenseInfo.IsMutator {
				// If the match is a mutator, add it to the mutators.
				if !containsLicID(currentMutators, m) {
					currentMutators = append(currentMutators, lic)
				}
				if !containsLicID(newMutators, m) {
					newMutators = append(newMutators, lic)
				}
			} else {
				// Otherwise, add it to the base licenses.
				if !containsLicID(currentLicenses, m) {
					currentLicenses = append(currentLicenses, lic)
				}
				if !containsLicID(newLicenses, m) {
					newLicenses = append(newLicenses, lic)
				}
			}
		}

		// If the current block contains more than one base license...
		if len(newLicenses) > 1 {
			// Apply mutators to previous state.

			// TODO: This invalid state should be refactored away
			if len(previousLicenses) > 1 {
				return fmt.Errorf("Invalid state. Should be only one previous license.")
			}

			if len(previousLicenses) > 0 {
				appliedMutation = appliedMutation || applyMutatorsInAffectedBlocks(affectedBlocks, previousLicenses[0], previousMutators)
			}

			previousLicenses, previousMutators, affectedBlocks = nil, nil, nil
		} else if mutatorsAreCompatible(currentLicenses, currentMutators) {
			// Don't apply yet...
			// Update the previous state and continue.
			previousLicenses = currentLicenses
			previousMutators = currentMutators
			affectedBlocks = []Block{b}
		} else {
			// Otherwise, the current state is invalid and we need to apply mutators on the previous state.

			// TODO: This invalid state should be refactored away
			if len(previousLicenses) > 1 {
				return fmt.Errorf("Invalid state. Should be only one previous license.")
			}

			if len(previousLicenses) > 0 {
				appliedMutation = appliedMutation || applyMutatorsInAffectedBlocks(affectedBlocks, previousLicenses[0], previousMutators)
			}

			previousLicenses = newLicenses
			previousMutators = newMutators
			affectedBlocks = append(affectedBlocks, b)
		}

	}

	// If there are still any blocks left unprocessed, and it is a valid state...
	if len(affectedBlocks) > 0 && mutatorsAreCompatible(previousLicenses, previousMutators) {
		// ... apply mutators to this final state.

		// TODO: This invalid state should be refactored away
		if len(previousLicenses) > 1 {
			return fmt.Errorf("Invalid state. Should be only one previous license.")
		}

		if len(previousLicenses) > 0 {
			appliedMutation = appliedMutation || applyMutatorsInAffectedBlocks(affectedBlocks, previousLicenses[0], previousMutators)
		}
	}

	// If any mutations were applied, we need to recalculate the licenses_found and license_matches results.
	if appliedMutation {
		licenseResults.Matches = recalculateMatchesFromBlocks(*licenseResults)
	}
	return nil
}

// mutatorsAreCompatible checks for incompatibility.
// If any mutator is not compatible with the base license (or, if there is no
// base license, each other) then this function will return false.
// Otherwise, this function will return true.
func mutatorsAreCompatible(baseLicenses []licenses.License, mutators []licenses.License) bool {
	numLicenses := len(baseLicenses)
	if numLicenses > 1 {
		return false
	}
	if len(mutators) == 0 {
		return true
	}

	if numLicenses == 1 {
		// If there is a base license...
		replacementMutatorsCount := 0
		l := baseLicenses[0]
		for _, mutator := range mutators {
			if !mutator.LicenseInfo.SPDXException {
				if replacementMutatorsCount++; replacementMutatorsCount > 1 {
					return false
				}
			}
			if !slices.Contains(mutator.LicenseInfo.EligibleLicenses, l.GetID()) {
				return false
			}
		}
	} else if len(mutators) > 1 {
		// Otherwise, if there are multiple mutators...
		var mutualLicenses []string
		replacementMutatorsCount := 0
		for i, mutator := range mutators {
			if i == 0 {
				// Start with the first eligible licenses.
				mutualLicenses = mutator.LicenseInfo.EligibleLicenses
			} else {
				// ... they must all be mutually compatible.
				if len(mutator.LicenseInfo.EligibleLicenses) < 1 {
					return false
				}
				if !mutator.LicenseInfo.SPDXException {
					if replacementMutatorsCount++; replacementMutatorsCount > 1 {
						return false
					}
				}
				var filteredMutualLicenses []string
				for _, id := range mutualLicenses {
					if slices.Contains(mutator.LicenseInfo.EligibleLicenses, id) {
						filteredMutualLicenses = append(filteredMutualLicenses, id)
					}
				}
				mutualLicenses = filteredMutualLicenses
			}
			if len(mutualLicenses) < 1 {
				return false
			}
		}
	}

	// Otherwise, there is no base license and fewer than two mutators, so no incompatibility is possible.
	return true
}

func applyMutatorsInAffectedBlocks(affectedBlocks []Block, base licenses.License, mutators []licenses.License) bool {
	if len(mutators) < 1 || len(affectedBlocks) < 1 {
		return false
	}

	// Separate the exception mutators from the replacement mutator, if any.
	var replacementMutator *licenses.License
	var exceptionMutators []licenses.License
	for _, mutator := range mutators {
		if mutator.LicenseInfo.SPDXException {
			exceptionMutators = append(exceptionMutators, mutator)
		} else {
			replacementMutator = &mutator // TODO: what if this is not the one and only??? Invalid state? Refactor?
		}
	}

	// Initialize the new, mutated license.
	mutatedLicense := licenses.License{
		SPDXLicenseID: base.SPDXLicenseID,
		LicenseInfo: licenses.LicenseInfo{
			Name:         base.LicenseInfo.Name,
			SPDXStandard: base.LicenseInfo.SPDXStandard,
			OSIApproved:  base.LicenseInfo.OSIApproved,
		},
	}

	// If there is a replacement mutator, apply it first.
	if replacementMutator != nil {
		mutatedLicense.SPDXLicenseID = replacementMutator.SPDXLicenseID
		mutatedLicense.LicenseInfo.Name = replacementMutator.LicenseInfo.Name
		mutatedLicense.LicenseInfo.SPDXStandard = replacementMutator.LicenseInfo.SPDXStandard
	}

	// If there are exception mutators, apply them.
	for _, e := range exceptionMutators {
		mutatedLicense.SPDXLicenseID = mutatedLicense.SPDXLicenseID + " WITH " + e.SPDXLicenseID
		mutatedLicense.LicenseInfo.Name = mutatedLicense.LicenseInfo.Name + " with " + e.LicenseInfo.Name
		mutatedLicense.LicenseInfo.SPDXStandard = e.LicenseInfo.SPDXStandard && mutatedLicense.LicenseInfo.SPDXStandard
	}

	// TODO: Save the mutated license, if necessary, to the license matches.

	// Set the Matches field on all affected Blocks.
	// TODO: legacy was setting one ID here (not append). Test/refactor.
	for i := range affectedBlocks {
		affectedBlocks[i].Matches = append(affectedBlocks[i].Matches, mutatedLicense.GetID())
	}

	return true
}

// TODO: See if this has ANY IMPACT ON ANYTHING
func recalculateMatchesFromBlocks(licenseResults IdentifierResults) map[string][]Match {
	newMatches := make(map[string][]Match)

	// Iterate over blocks to rebuild matches in license matches.
	offset := 0
	for _, block := range licenseResults.Blocks {
		blockMatches := block.Matches
		begins := offset
		ends := offset + len(block.Text) - 1
		offset = ends + 1

		for _, licenseId := range blockMatches {
			// If matches are null, copyright, keyword, or acceptable skip them.
			switch licenseId {
			case "", "COPYRIGHT", "KEYWORD", "ACCEPTABLE":
				continue
			default:
				newMatches[licenseId] = append(newMatches[licenseId], Match{Begins: begins, Ends: ends})
			}
		}
	}
	return newMatches
}

func containsLicID(lics []licenses.License, id string) bool {
	if id == "" {
		return false
	}
	for i := range lics {
		if id == lics[i].GetID() {
			return true
		}
	}
	return false
}
