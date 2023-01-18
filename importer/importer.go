// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mrutkows/sbom-utility/log"

	"github.com/spf13/viper"

	"github.com/IBM/license-scanner/licenses"
)

var (
	Logger            = log.NewLogger(log.INFO)
	_, thisFile, _, _ = runtime.Caller(0) // Dirs/files are relative to this file
	thisDir           = filepath.Dir(thisFile)
)

func AddAllSPDXTemplates(cfg *viper.Viper) error {
	// input dir is relative to root (if not an absolute path)
	addAllDir := cfg.GetString("addAll")

	if !path.IsAbs(addAllDir) {
		addAllDir = path.Join(thisDir, "..", addAllDir)
	}

	// sources
	licensesJSON := path.Join(addAllDir, "json", "licenses.json")
	exceptionsJSON := path.Join(addAllDir, "json", "exceptions.json")
	templateSrcDir := path.Join(addAllDir, "template")
	textSrcDir := path.Join(addAllDir, "text")

	SPDXLicenseListBytes, err := os.ReadFile(licensesJSON)
	if err != nil {
		return fmt.Errorf("read SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}
	licenseList, err := licenses.ReadSPDXLicenseListJSON(SPDXLicenseListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}
	licenseListVersion := licenseList.LicenseListVersion

	SPDXExceptionsListBytes, err := os.ReadFile(exceptionsJSON)
	if err != nil {
		return fmt.Errorf("read exceptions JSON from %v error: %w", exceptionsJSON, err)
	}
	exceptionsList, err := licenses.ReadSPDXLicenseListJSON(SPDXExceptionsListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", exceptionsJSON, err)
	}
	exceptionsListVersion := exceptionsList.LicenseListVersion

	if licenseListVersion != exceptionsListVersion {
		return fmt.Errorf("license list version '%v' does not match exception list version '%v'", licenseListVersion, exceptionsListVersion)
	}

	templateDEs, err := os.ReadDir(templateSrcDir)
	if err != nil {
		return err
	}
	if len(templateDEs) < 1 {
		return fmt.Errorf("template source dir %v is empty", templateSrcDir)
	}

	// destinations
	rd := cfg.GetString(licenses.Resources)

	templateDestDir := getDestPath(rd, licenseListVersion, "template")
	preCheckDestDir := getDestPath(rd, licenseListVersion, "precheck")
	textDestDir := getDestPath(rd, licenseListVersion, "testdata")
	jsonDestDir := getDestPath(rd, licenseListVersion, "json")

	if err := createEmptyLicenseListDataResourceDirs(templateDestDir, preCheckDestDir, textDestDir, jsonDestDir); err != nil {
		return err
	}

	if err := os.WriteFile(path.Join(jsonDestDir, "licenses.json"), SPDXLicenseListBytes, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(path.Join(jsonDestDir, "exceptions.json"), SPDXExceptionsListBytes, 0o600); err != nil {
		return err
	}

	errorCount := 0
	for _, de := range templateDEs {
		templateName := de.Name()
		id := strings.TrimSuffix(templateName, ".template.txt")
		templateFile := path.Join(templateSrcDir, templateName)
		textFile := path.Join(textSrcDir, id+".txt")

		if err := ValidateSPDXTemplateWithLicenseText(id, templateFile, textFile, templateDestDir, preCheckDestDir, textDestDir); err != nil {
			deprecatedPrefix := "deprecated_"
			if strings.HasPrefix(id, deprecatedPrefix) {
				altTextFile := path.Join(textSrcDir, strings.TrimPrefix(id+".txt", deprecatedPrefix))
				Logger.Infof("template ID %v is not valid retrying w/o testdata prefix", id)
				err = ValidateSPDXTemplateWithLicenseText(id, templateFile, altTextFile, templateDestDir, preCheckDestDir, textDestDir)
			}
			if err != nil {
				_ = Logger.Errorf("template ID %v is not valid", id)
				errorCount++
			}
		}
	}
	if errorCount > 0 {
		return fmt.Errorf("%v templates could not be validated", errorCount)
	}
	return nil
}

func createEmptyLicenseListDataResourceDirs(dirs ...string) error {
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("cannot create destination dir %v error: %w", dir, err)
		}
		des, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("cannot read destination dir %v error: %w", dir, err)
		}
		if len(des) > 0 {
			return fmt.Errorf("destination dir %v is not empty", dir)
		}
	}
	return nil
}

func getDestPath(rd string, spdxVersionDir string, dir string) string {
	destPath := path.Join(rd, "spdx", spdxVersionDir, dir)
	return destPath
}
