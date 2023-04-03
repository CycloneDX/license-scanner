// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/CycloneDX/license-scanner/configurer"
	"github.com/CycloneDX/license-scanner/licenses"
	"github.com/CycloneDX/license-scanner/normalizer"
	"github.com/CycloneDX/license-scanner/resources"

	"github.com/CycloneDX/sbom-utility/log"

	"github.com/spf13/viper"
)

var Logger = log.NewLogger(log.INFO)

// Import validates, preprocesses, and copies templates into resources (or into external paths)
// This implements --addAll (which probably be changed to license-scanner import ...)
// The --addAll <string> value is the input dir. Output is determined by spdxPath/spdx/customPath/custom flags.
func Import(cfg *viper.Viper) error {
	input := cfg.GetString(configurer.AddAllFlag)
	if input == "" {
		return nil // nothing to import
	}

	// Get a destination from the config args and handle usage errs
	doSPDX, doCustom, err := checkArgs(cfg)
	r := resources.NewResources(cfg)
	if doSPDX {
		err = importSPDX(r, input)
	}
	if doCustom {
		err = importCustom(r, input)
	}
	return err
}

// Update validates, preprocesses, and updates preprocessed prechecks in resources (or into external paths)
// This implements --updateAll (which probably be changed to license-scanner update ...)
// The args spdxPath/spdx/customPath/custom are used to determine which resources (or external dir) are updated in-place.
func Update(cfg *viper.Viper) error {
	doUpdate := cfg.GetBool(configurer.UpdateAllFlag)
	if !doUpdate {
		return nil // nothing to do
	}

	doSPDX, doCustom, err := checkArgs(cfg)
	r := resources.NewResources(cfg)
	if doSPDX {
		err = updateSPDX(r)
	}
	if doCustom {
		err = updateCustom(r)
	}
	return err
}

// checkArgs gets flags to determine whether to do custom or SPDX import/update.
// If args suggest doing both or neither an error is returned.
func checkArgs(cfg *viper.Viper) (bool, bool, error) {
	doSPDX := cfg.GetString(configurer.SpdxPathFlag) != "" || cfg.GetString(configurer.SpdxFlag) != configurer.DefaultResource
	doCustom := cfg.GetString(configurer.CustomPathFlag) != "" || cfg.GetString(configurer.CustomFlag) != configurer.DefaultResource
	if !doCustom && !doSPDX {
		return false, false, fmt.Errorf("a non-default destination for custom or SPDX templates is required")
	} else if doCustom && doSPDX {
		return false, false, fmt.Errorf("one non-default SPDX or custom destination is required -- found both")
	}
	return doSPDX, doCustom, nil
}

// importSPDX validates, preprocesses, and copies templates, etc. from inputDir, into resources (or into external paths).
// The output destination is determined by spdxPath or spdx flags.
func importSPDX(r *resources.Resources, inputDir string) error {
	// Create an input resource reader using the input dir as --spdxPath to leverage resource reading functions
	inputConfig, err := configurer.InitConfig(nil)
	if err != nil {
		return err
	}
	inputConfig.Set(configurer.SpdxPathFlag, inputDir)
	inputResources := resources.NewResources(inputConfig)

	SPDXLicenseListBytes, SPDXExceptionsListBytes, err := inputResources.ReadSPDXJSONFiles()
	if err != nil {
		return err
	}
	licenseList, err := licenses.ReadSPDXLicenseListJSON(SPDXLicenseListBytes)
	if err != nil {
		return err
	}
	exceptionsList, err := licenses.ReadSPDXLicenseListJSON(SPDXExceptionsListBytes)
	if err != nil {
		return err
	}
	if licenseList.LicenseListVersion != exceptionsList.LicenseListVersion {
		return fmt.Errorf("license list version '%v' does not match exception list version '%v'", licenseList.LicenseListVersion, exceptionsList.LicenseListVersion)
	}
	if err := r.MkdirAllSPDX(); err != nil {
		return err
	}
	if err := r.WriteSPDXFile(SPDXLicenseListBytes, "json", "licenses.json"); err != nil {
		return err
	}
	if err := r.WriteSPDXFile(SPDXExceptionsListBytes, "json", "exceptions.json"); err != nil {
		return err
	}

	errorCount := 0
	for _, sl := range licenseList.Licenses {
		id := sl.LicenseID
		isDeprecated := sl.IsDeprecatedLicenseID
		if err := importSPDXResource(inputResources, r, id, isDeprecated); err != nil {
			errorCount++
		}
	}

	for _, se := range exceptionsList.Exceptions {
		id := se.LicenseExceptionID
		isDeprecated := se.IsDeprecatedLicenseID
		if err := importSPDXResource(inputResources, r, id, isDeprecated); err != nil {
			errorCount++
		}
	}

	if errorCount > 0 {
		return fmt.Errorf("%v templates could not be validated", errorCount)
	}
	return nil
}

func writeSPDXFiles(r *resources.Resources, id string, templateBytes []byte, textBytes []byte, staticBlocks []string) error {
	if err := r.WriteSPDXFile(templateBytes, "template", id+".template.txt"); err != nil {
		return err
	}
	if err := r.WriteSPDXFile(textBytes, "testdata", id+".txt"); err != nil {
		return err
	}
	if err := writeSPDXPreCheckFile(r, staticBlocks, id+".json"); err != nil {
		return err
	}
	return nil
}

func writeSPDXPreCheckFile(r *resources.Resources, staticBlocks []string, precheckName string) error {
	precheckBytes, err := getPreChecksBytes(staticBlocks)
	if err != nil {
		return Logger.Errorf("error getting precheck bytes for %v: %w", precheckName, err)
	}
	if err := r.WriteSPDXFile(precheckBytes, "precheck", precheckName); err != nil {
		return Logger.Errorf("error writing precheck file for %v: %w", precheckName, err)
	}
	return nil
}

// writeInvalidSPDXFiles stashes the template and text under testdata/invalid for further (manual) examination
func writeInvalidSPDXFiles(r *resources.Resources, id string, templateBytes []byte, textBytes []byte) {
	if err := r.WriteSPDXFile(templateBytes, "testdata", "invalid", id+".template.txt"); err != nil {
		_ = Logger.Errorf("error writing template for %v: %w", id+".template.txt", err)
	}
	if err := r.WriteSPDXFile(textBytes, "testdata", "invalid", id+".txt"); err != nil {
		_ = Logger.Errorf("error writing testdata for %v: %w", id+".txt", err)
	}
}

// importCustom validates, preprocesses, and copies templates, etc. from inputDir, into outputResources (or into external paths).
// The output destination is determined by customPath or custom flags.
func importCustom(outputResources *resources.Resources, inputDir string) error {

	// Create an input resource reader using the input dir as --customPath to leverage resource reading functions
	inputConfig, err := configurer.InitConfig(nil)
	if err != nil {
		return err
	}
	inputConfig.Set(configurer.CustomPathFlag, inputDir)
	inputResources := resources.NewResources(inputConfig)

	licenseIds, err := inputResources.ReadCustomLicensePatternIds()
	if err != nil {
		return err
	}

	for _, id := range licenseIds {
		des, idPath, err := inputResources.ReadCustomLicensePatternsDir(id)
		if err != nil {
			return err
		}

		if err := outputResources.MkdirAllCustom(id); err != nil {
			return err
		}

		for _, de := range des {
			if de.IsDir() {
				continue
			}
			fileName := de.Name()
			base := path.Base(fileName)
			filePath := path.Join(idPath, fileName)
			lowerFileName := strings.ToLower(fileName)
			switch {
			// the JSON payload is always stored in license_info.txt
			case lowerFileName == licenses.LicenseInfoJSON:
				bytes, err := inputResources.ReadCustomFile(filePath)
				if err != nil {
					return err
				}
				// Verify that unmarshal doesn't fail
				if _, err := licenses.ReadLicenseInfoJSON(bytes); err != nil {
					return Logger.Errorf("Unmarshal LicenseInfo from %v using LicenseReader error: %v", filePath, err)
				}
				if err := outputResources.WriteCustomFile(bytes, "license_patterns", id, fileName); err != nil {
					return err
				}
			// all other files starting with "license_" are primary license patterns. Validate and copy primary and associated patterns.
			case strings.HasPrefix(lowerFileName, licenses.PrimaryPattern), strings.HasPrefix(lowerFileName, licenses.AssociatedPattern), strings.HasPrefix(lowerFileName, licenses.OptionalPattern):
				bytes, err := inputResources.ReadCustomFile(filePath)
				if err != nil {
					return err
				}
				normalizedData, err := normalizeAndRegex(string(bytes))
				if err != nil {
					return err
				}

				if err := outputResources.WriteCustomFile(bytes, "license_patterns", id, fileName); err != nil {
					return err
				}

				if err := writeCustomPrecheck(outputResources, normalizedData, base, id, fileName); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func updateSPDX(r *resources.Resources) error {
	licenseList, exceptionsList, err := licenses.ReadSPDXLicenseLists(r)
	if err != nil {
		return err
	}

	if licenseList.LicenseListVersion != exceptionsList.LicenseListVersion {
		return fmt.Errorf("license list version '%v' does not match exception list version '%v'", licenseList.LicenseListVersion, exceptionsList.LicenseListVersion)
	}

	// Make sure we have a precheck dir
	_ = r.MkdirPreCheckSPDX()

	for _, sl := range licenseList.Licenses {
		id := sl.LicenseID
		isDeprecated := sl.IsDeprecatedLicenseID
		if err := updateSPDXResource(r, id, isDeprecated); err != nil {
			return err
		}
	}

	for _, se := range exceptionsList.Exceptions {
		id := se.LicenseExceptionID
		isDeprecated := se.IsDeprecatedLicenseID
		if err := updateSPDXResource(r, id, isDeprecated); err != nil {
			return err
		}
	}
	return nil
}

func importSPDXResource(input *resources.Resources, output *resources.Resources, id string, isDeprecated bool) error {

	// In earlier versions we attempted to use deprecated templates.
	// In 3.20 the deprecated licenses are not compatible with the newer versions.
	if isDeprecated {
		return nil
	}

	templateBytes, templateFile, err := input.ReadSPDXTemplateFile(id, isDeprecated)
	if err != nil {
		return err
	}
	textBytes, err := input.ReadSPDXTextFile(id, isDeprecated)
	if err != nil {
		return err
	}
	staticBlocks, err := validate(id, templateBytes, textBytes, templateFile)
	if err != nil {
		_ = Logger.Errorf("template ID %v is not valid", id)
		writeInvalidSPDXFiles(output, id, templateBytes, textBytes)
		return err
	}

	return writeSPDXFiles(output, id, templateBytes, textBytes, staticBlocks)
}

func updateSPDXResource(r *resources.Resources, id string, isDeprecated bool) error {
	tBytes, f, err := r.ReadSPDXTemplateFile(id, isDeprecated)
	if err != nil {
		if os.IsNotExist(err) {
			Logger.Debugf("Skipping missing template file '%v'", f)
			return nil
		}
		return err
	}
	normalizedTemplate, err := normalizeAndRegex(string(tBytes))
	if err != nil {
		return err
	}
	staticBlocks := GetStaticBlocks(normalizedTemplate)
	if err := writeSPDXPreCheckFile(r, staticBlocks, id+".json"); err != nil {
		return err
	}
	return nil
}

func updateCustom(r *resources.Resources) error {
	licenseIds, err := r.ReadCustomLicensePatternIds()
	if err != nil {
		return err
	}

	for _, id := range licenseIds {
		des, idPath, err := r.ReadCustomLicensePatternsDir(id)
		if err != nil {
			return err
		}

		for _, de := range des {
			if de.IsDir() {
				continue
			}

			fileName := de.Name()
			base := path.Base(fileName)
			filePath := path.Join(idPath, fileName)
			lowerFileName := strings.ToLower(fileName)

			if lowerFileName != licenses.LicenseInfoJSON {
				if strings.HasPrefix(lowerFileName, licenses.PrimaryPattern) || strings.HasPrefix(lowerFileName, licenses.AssociatedPattern) || strings.HasPrefix(lowerFileName, licenses.OptionalPattern) {
					bytes, err := r.ReadCustomFile(filePath)
					if err != nil {
						return err
					}
					normalizedData, err := normalizeAndRegex(string(bytes))
					if err != nil {
						return err
					}

					if err := writeCustomPrecheck(r, normalizedData, base, id, fileName); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// normalizeAndRegex verifies that we can normalize the template text and create a regex and returns useful stuff
func normalizeAndRegex(s string) (*normalizer.NormalizationData, error) {
	normalizedData := normalizer.NewNormalizationData(s, true)
	if err := normalizedData.NormalizeText(); err != nil {
		return nil, fmt.Errorf("cannot normalize text: %w", err)
	}
	// Generate regex just to make sure there isn't a regex compile error with this input
	_, err := licenses.GenerateRegexFromNormalizedText(normalizedData.NormalizedText)
	if err != nil {
		return nil, fmt.Errorf("cannot generate re: %w", err)
	}
	return normalizedData, nil
}

func writeCustomPrecheck(r *resources.Resources, normalizedData *normalizer.NormalizationData, base string, id string, fileName string) error {
	staticBlocks := GetStaticBlocks(normalizedData)
	precheckBytes, err := getPreChecksBytes(staticBlocks)
	if err != nil {
		return Logger.Errorf("error getting precheck bytes for %v: %w", base, err)
	}
	f := "prechecks_" + base // Add prefix
	ext := path.Ext(f)
	f = f[0:len(f)-len(ext)] + ".json" // Replace .txt with .json
	if err := r.WriteCustomFile(precheckBytes, "license_patterns", id, f); err != nil {
		return Logger.Errorf("error writing precheck file for %v: %w", fileName, err)
	}
	return nil
}
