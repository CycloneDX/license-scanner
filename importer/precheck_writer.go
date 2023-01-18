// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/IBM/license-scanner/normalizer"

	"github.com/IBM/license-scanner/licenses"
)

var replaceRE = regexp.MustCompile(`(<<.*?>>)`)

func WritePreChecksFile(staticBlocks []string, f string) error {
	preChecks := licenses.LicensePreChecks{
		StaticBlocks: staticBlocks,
	}

	b, err := json.MarshalIndent(preChecks, "", "  ")
	if err != nil {
		return fmt.Errorf("error on MarshalIndent for %v: %w", f, err)
	}

	err = os.WriteFile(f, b, 0o666)
	if err != nil {
		return fmt.Errorf("error writing %v: %w", f, err)
	}
	return nil
}

// GetStaticBlocks filters out the regex sections and returns the static text blocks
func GetStaticBlocks(normalizedPatternData *normalizer.NormalizationData) []string {
	var staticBlocks []string
	omitableDepth := 0
	pos := 0
	for _, ii := range replaceRE.FindAllStringIndex(normalizedPatternData.NormalizedText, -1) {
		if pos < ii[0] {
			block := normalizedPatternData.NormalizedText[pos:ii[0]]
			if block == "<<omitable>>" {
				omitableDepth++
			} else if block == "<</omitable>>" {
				omitableDepth--
			} else if !strings.Contains(block, "<<") && omitableDepth == 0 && strings.TrimSpace(block) != "" {
				staticBlocks = append(staticBlocks, block)
			}
		}
		block := normalizedPatternData.NormalizedText[ii[0]:ii[1]]
		if block == "<<omitable>>" {
			omitableDepth++
		} else if block == "<</omitable>>" {
			omitableDepth--
		} else if !strings.Contains(block, "<<") && omitableDepth == 0 && block != "" {
			staticBlocks = append(staticBlocks, block)
		}
		pos = ii[1]
	}
	if pos < len(normalizedPatternData.NormalizedText) {
		staticBlocks = append(staticBlocks, normalizedPatternData.NormalizedText[pos:])
	}

	var trimmedStaticBlocks []string
	for i := range staticBlocks {
		trimmed := strings.TrimSpace(staticBlocks[i])
		if len(trimmed) > 1 { // SKIP the single chars
			trimmedStaticBlocks = append(trimmedStaticBlocks, trimmed)
		}
	}

	return trimmedStaticBlocks
}
