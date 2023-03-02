// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/CycloneDX/license-scanner/configurer"

	"github.com/spf13/viper"
)

const (
	LicensePatternsDir = "license_patterns"
	JSONDir            = "json"
)

type Resources struct {
	config          *viper.Viper
	spdxReader      resourceReader
	spdxPath        string
	customReader    resourceReader
	customPath      string
	customWritePath string
	spdxWritePath   string
}

func NewResources(cfg *viper.Viper) *Resources {
	spdxReader, spdxPath := getSPDXReader(cfg)
	customReader, customReadPath := getCustomReader(cfg)
	customWritePath := getResourcesWritePath(cfg, configurer.CustomPathFlag, configurer.CustomFlag)
	spdxWritePath := getResourcesWritePath(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag)
	return &Resources{
		cfg,
		spdxReader,
		spdxPath,
		customReader,
		customReadPath,
		customWritePath,
		spdxWritePath,
	}
}

type resourceReader interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
}

type osReader struct{}

var (
	//go:embed spdx/*/template spdx/*/precheck spdx/*/json custom/*/license_patterns
	embeddedFS        embed.FS
	_, thisFile, _, _                = runtime.Caller(0) // Dirs/files are relative to this file
	thisDir                          = filepath.Dir(thisFile)
	_                 resourceReader = osReader{} // static check for implements interface
)

func (osr osReader) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (osr osReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// getResourcesWritePath determines path to resources including <thisDir> prefix for embedded resources.
// Note: embedded FS is read-only, so this provides additional pathing to allow os.WriteFile etc to write to the source
// of the embedded FS (which would be read into the embedded FS only upon restart).
func getResourcesWritePath(cfg *viper.Viper, pathFlag string, embeddedFlag string) string {
	pathValue := cfg.GetString(pathFlag)
	if pathValue == "" {
		pathValue = path.Join(thisDir, embeddedFlag, cfg.GetString(embeddedFlag))
		return pathValue
	}
	return pathValue
}

// getFileReader returns a resourceReader for embedded-or-not resources and the path
func getFileReader(cfg *viper.Viper, pathFlag string, embeddedFlag string) (resourceReader, string) {
	pathValue := cfg.GetString(pathFlag)
	if pathValue == "" {
		pathValue = path.Join(embeddedFlag, cfg.GetString(embeddedFlag))
		return embeddedFS, pathValue
	}
	return osReader{}, pathValue
}

// getSPDXReader returns a resourceReader for embedded-or-not SPDX resources and the path
func getSPDXReader(cfg *viper.Viper) (resourceReader, string) {
	return getFileReader(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag)
}

// getCustomReader returns a resourceReader for embedded-or-not SPDX resources and the path
func getCustomReader(cfg *viper.Viper) (resourceReader, string) {
	return getFileReader(cfg, configurer.CustomPathFlag, configurer.CustomFlag)
}

func getSPDXTemplateFilePath(id string, isDeprecated bool, templatePath string) string {
	f := id + ".template.txt"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(templatePath, f)
	return f
}

func getSPDXTextFilePath(id string, isDeprecated bool, textPath string) string {
	f := id + ".txt"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(textPath, f)
	return f
}

func getSPDXPreCheckFilePath(id string, isDeprecated bool, preCheckPath string) string {
	f := id + ".json"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(preCheckPath, f)
	return f
}

func (r *Resources) ReadSPDXTemplateFile(id string, isDeprecated bool) ([]byte, string, error) {
	templatePath := path.Join(r.spdxPath, "template")
	f := getSPDXTemplateFilePath(id, isDeprecated, templatePath)
	tBytes, err := r.spdxReader.ReadFile(f)
	return tBytes, f, err
}

func (r *Resources) ReadSPDXTextFile(id string, isDeprecated bool) ([]byte, error) {
	textPath := path.Join(r.spdxPath, "text")
	f := getSPDXTextFilePath(id, isDeprecated, textPath)
	tBytes, err := r.spdxReader.ReadFile(f)
	if err != nil {
		// retry without the deprecated_ prefix (fixes one SPDX 3.18 inconsistency)
		f := getSPDXTextFilePath(id, false, textPath)
		tBytes, err = r.spdxReader.ReadFile(f)
	}
	return tBytes, err
}

func (r *Resources) ReadSPDXPreCheckFile(id string, isDeprecated bool) ([]byte, error) {
	preCheckPath := path.Join(r.spdxPath, "precheck")
	f := getSPDXPreCheckFilePath(id, isDeprecated, preCheckPath)
	tBytes, err := r.spdxReader.ReadFile(f)
	return tBytes, err
}

func (r *Resources) ReadSPDXJSONFiles() (licenseListBytes []byte, exceptionsBytes []byte, err error) {
	licensesJSON := path.Join(r.spdxPath, JSONDir, "licenses.json")
	exceptionsJSON := path.Join(r.spdxPath, JSONDir, "exceptions.json")
	licenseListBytes, err = r.spdxReader.ReadFile(licensesJSON)
	if err != nil {
		return
	}
	exceptionsBytes, err = r.spdxReader.ReadFile(exceptionsJSON)
	return
}

func (r *Resources) ReadCustomLicensePatternIds() (ids []string, err error) {
	patternPath := path.Join(r.customPath, LicensePatternsDir)
	des, err := r.customReader.ReadDir(patternPath)
	if err != nil {
		return
	}
	for _, de := range des {
		ids = append(ids, de.Name())
	}
	return
}

func (r *Resources) ReadCustomLicensePatternsDir(id string) ([]fs.DirEntry, string, error) {
	idPath := path.Join(r.customPath, LicensePatternsDir, id)
	des, err := r.customReader.ReadDir(idPath)
	return des, idPath, err
}

func (r *Resources) ReadCustomDir(dir string) ([]fs.DirEntry, string, error) {
	dirPath := path.Join(r.customPath, dir)
	des, err := r.customReader.ReadDir(dirPath)
	return des, dirPath, err
}

func (r *Resources) ReadCustomFile(filePath string) ([]byte, error) {
	b, err := r.customReader.ReadFile(filePath)
	return b, err
}

func (r *Resources) WriteCustomFile(bytes []byte, ff ...string) error {
	f := path.Join(r.customWritePath, path.Join(ff...))
	return os.WriteFile(f, bytes, 0o600)
}

func mkdirAll(cfg *viper.Viper, pathFlag string, embeddedFlag string, dirs ...string) error {
	destPath := getResourcesWritePath(cfg, pathFlag, embeddedFlag)
	for _, dir := range dirs {
		destSubDir := path.Join(destPath, dir)
		if err := os.MkdirAll(destSubDir, os.ModePerm); err != nil {
			return fmt.Errorf("cannot create destination dir %v error: %w", destSubDir, err)
		}
		des, err := os.ReadDir(destSubDir)
		if err != nil {
			return fmt.Errorf("cannot read destination dir %v error: %w", destSubDir, err)
		}
		if len(des) > 0 {
			return fmt.Errorf("destination dir %v is not empty", destSubDir)
		}
	}
	return nil
}

func (r *Resources) MkdirAllSPDX() error {
	dirs := []string{"template", "precheck", "json", "testdata", "testdata/invalid"}
	return mkdirAll(r.config, configurer.SpdxPathFlag, configurer.SpdxFlag, dirs...)
}

func (r *Resources) MkdirPreCheckSPDX() error {
	return mkdirAll(r.config, configurer.SpdxPathFlag, configurer.SpdxFlag, "precheck")
}

func (r *Resources) MkdirAllCustom(id string) error {
	dirs := []string{"license_patterns/" + id}
	return mkdirAll(r.config, configurer.CustomPathFlag, configurer.CustomFlag, dirs...)
}

func (r *Resources) WriteSPDXFile(bytes []byte, ff ...string) error {
	f := path.Join(r.spdxWritePath, path.Join(ff...))
	return os.WriteFile(f, bytes, 0o600)
}
