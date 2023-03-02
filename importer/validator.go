// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"fmt"

	"github.com/mrutkows/sbom-utility/log"

	"github.com/CycloneDX/license-scanner/debugger"
	"github.com/CycloneDX/license-scanner/identifier"
	"github.com/CycloneDX/license-scanner/licenses"
	"github.com/CycloneDX/license-scanner/normalizer"
)

func validate(id string, templateBytes []byte, textBytes []byte, templateFile string) (staticBlocks []string, err error) {

	l := &licenses.License{}
	if err = licenses.AddPrimaryPatternAndSource(string(templateBytes), templateFile, l); err != nil {
		return
	}

	if _, err = licenses.GenerateMatchingPatternFromSourceText(l.PrimaryPatterns[0]); err != nil {
		return
	}

	normalizedTestData := normalizer.NormalizationData{
		OriginalText: string(textBytes),
	}
	if err = normalizedTestData.NormalizeText(); err != nil {
		return
	}

	matches, err := identifier.FindMatchingPatternInNormalizedData(l.PrimaryPatterns[0], normalizedTestData)
	if err != nil {
		return
	}

	// There should be exactly ONE match when matching a template against its example license text
	if len(matches) != 1 {
		err = Logger.Errorf("expected 1 match for %v got: %v", id, matches)
		if Logger.GetLevel() >= log.DEBUG {
			failure, _ := debugger.DebugLicenseMatchFailure(*l, normalizedTestData.NormalizedText)
			Logger.Debug(fmt.Errorf("Debugging invalid template for %v...\n", id))
			Logger.Debug(failure)
			Logger.Debug("\n")
		}
		return
	}

	normalizedTemplate := normalizer.NewNormalizationData(string(templateBytes), true)
	if err = normalizedTemplate.NormalizeText(); err != nil {
		return
	}

	staticBlocks = GetStaticBlocks(normalizedTemplate)
	passed := identifier.PassedStaticBlocksChecks(staticBlocks, normalizedTestData)
	if !passed {
		err = Logger.Errorf("%v failed testing against static blocks", id)
		return
	}
	return
}
