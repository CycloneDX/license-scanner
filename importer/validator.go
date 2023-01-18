// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"fmt"
	"os"
	"path"

	"github.com/mrutkows/sbom-utility/log"

	"github.com/IBM/license-scanner/debugger"
	"github.com/IBM/license-scanner/identifier"
	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

func ValidateSPDXTemplateWithLicenseText(id, templateFile, textFile, templateDestDir, preCheckDestDir, textDestDir string) (err error) {
	var templateBytes []byte
	var textBytes []byte
	var staticBlocks []string

	// on error, save template/text/precheck files (if available) under testdata/invalid
	defer func() {
		if err != nil {
			invalid := path.Join(textDestDir, "invalid") // on error save files in testdata/invalid
			_ = os.Mkdir(invalid, 0o700)
			_ = write(id, invalid, templateBytes, invalid, textBytes, invalid, staticBlocks)
		}
	}()

	textBytes, err = os.ReadFile(textFile)
	if err != nil {
		return
	}
	templateBytes, err = os.ReadFile(templateFile)
	if err != nil {
		return
	}

	staticBlocks, err = validate(id, templateBytes, textBytes, templateFile)
	if err != nil {
		return err
	}

	if err = write(id, templateDestDir, templateBytes, textDestDir, textBytes, preCheckDestDir, staticBlocks); err != nil {
		return
	}
	return
}

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

func write(id string, templateDestDir string, templateBytes []byte, textDestDir string, textBytes []byte, preCheckDestDir string, staticBlocks []string) error {

	if err := os.WriteFile(path.Join(templateDestDir, id+".template.txt"), templateBytes, 0o600); err != nil {
		return Logger.Errorf("error writing template for %v: %w", id, err)
	}

	if err := os.WriteFile(path.Join(textDestDir, id+".txt"), textBytes, 0o600); err != nil {
		return Logger.Errorf("error writing testdata for %v: %w", id, err)
	}

	if err := WritePreChecksFile(staticBlocks, path.Join(preCheckDestDir, id+".json")); err != nil {
		return Logger.Errorf("error writing precheck file for %v: %w", id, err)
	}
	return nil
}
