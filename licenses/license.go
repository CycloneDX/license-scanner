// SPDX-License-Identifier: Apache-2.0

package licenses

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/IBM/license-scanner/configurer"

	"github.com/spf13/viper"

	"github.com/mrutkows/sbom-utility/log"

	"github.com/IBM/license-scanner/normalizer"
)

const (
	Resources          = "resources"
	SPDX               = "spdx"
	customDir          = "custom"
	template           = "template"
	precheck           = "precheck"
	jsonDir            = "json"
	LicenseInfoJSON    = "license_info.json"
	PreChecksPattern   = "prechecks_"
	PrimaryPattern     = "license_"
	AssociatedPattern  = "associated_"
	OptionalPattern    = "optional_"
	LicensePatterns    = "license_patterns"
	AcceptablePatterns = "acceptable_patterns"
)

var (
	Logger                 = log.NewLogger(log.INFO)
	pointyBracketSegmentRE = regexp.MustCompile(` *<<(.*?)>> *`)
	RegexUnsafePattern     = regexp.MustCompile(`([\\.*+?^${}()|[\]])`)
	spaceTagReplacer       = strings.NewReplacer(
		" <<", "<<",
		">> ", ">>",
	)
	tagReplacer = strings.NewReplacer(
		"<<omitable>>", "BEGIN_OMITABLE",
		"<</omitable>>", "END_OMITABLE",
		"<<copyright>>", "COPYRIGHT",
	)
	tokenReplacer = strings.NewReplacer(
		"BEGIN_OMITABLE", " *(?:",
		"END_OMITABLE", " *)?",
		"COPYRIGHT", ".*",
	)
)

type LicenseLibrary struct {
	SPDXVersion               string
	LicenseMap                LicenseMap
	PrimaryPatternPreCheckMap PrimaryPatternPreCheckMap
	AcceptablePatternsMap     PatternsMap
	Config                    *viper.Viper
}

type LicensePreChecks struct {
	StaticBlocks []string
}

type LicensePatternKey struct {
	FilePath string // Each ID may have multiple license_*.txt primary patterns
}

type PrimaryPatternPreCheckMap map[LicensePatternKey]*LicensePreChecks

type Detail struct {
	ID            string
	Name          string
	Family        string
	NumTemplates  int
	IsOSIApproved bool
	IsFSFLibre    bool
}

type Exception struct {
	ID           string
	Name         string
	Family       string
	NumTemplates int
}

func NewLicenseLibrary(config *viper.Viper) (*LicenseLibrary, error) {
	if config == nil {
		cfg, err := configurer.InitConfig(nil)
		if err != nil {
			return nil, err
		}
		config = cfg
	}

	ll := LicenseLibrary{
		LicenseMap:                make(LicenseMap),
		PrimaryPatternPreCheckMap: make(PrimaryPatternPreCheckMap),
		AcceptablePatternsMap:     make(PatternsMap),
		Config:                    config,
	}

	return &ll, nil
}

type LicenseMap map[string]License

// License holds the specification of each license
type License struct {
	// SPDX License ID if applicable, for example, "Apache-2.0"
	SPDXLicenseID             string
	LicenseInfo               LicenseInfo
	PrimaryPatterns           []*PrimaryPatterns
	PrimaryPatternsSources    []PrimaryPatternsSources
	AssociatedPatterns        []*PrimaryPatterns
	AssociatedPatternsSources []PrimaryPatternsSources
	// Aliases (and names and IDs) can be used like primary patterns (unless disabled), but are simple strings not regex. They also require word boundaries.
	Aliases []string
	// URLs can be used like primary patterns (unless disabled), but are simple strings not regex with URL matching.
	URLs []string
	// license text or an expression
	Text LicenseText
}

type PatternsMap map[string]*regexp.Regexp

type PrimaryPatterns struct {
	Text          string
	doOnce        sync.Once
	re            *regexp.Regexp
	CaptureGroups []*normalizer.CaptureGroup
	FileName      string
}

type PrimaryPatternsSources struct {
	SourceText string
	Filename   string
}

// LicenseText contains the content type along with the content
type LicenseText struct {
	// content type of the license, for example, "text/plain"
	ContentType string
	// any encoding if the license text is encoded in any particular format, for example, "base64"
	Encoding string
	// license text encoded in the format specified
	Content string
}

type SPDXLicenceInfo struct {
	Name                  string `json:"name"`
	LicenseID             string `json:"licenseId"`
	IsOSIApproved         bool   `json:"isOsiApproved"`
	IsFSFLibre            bool   `json:"isFsfLibre"`
	IsDeprecatedLicenseID bool   `json:"isDeprecatedLicenseId"`
}

type SPDXExceptionInfo struct {
	Name                  string `json:"name"`
	LicenseExceptionID    string `json:"licenseExceptionId"`
	IsDeprecatedLicenseID bool   `json:"isDeprecatedLicenseId"`
}

type SPDXLicenceList struct {
	LicenseListVersion string              `json:"licenseListVersion"`
	Licenses           []SPDXLicenceInfo   `json:"licenses"`
	Exceptions         []SPDXExceptionInfo `json:"exceptions"`
}

type LicenseInfo struct {
	Name             string         `json:"name"`
	Family           string         `json:"family"`
	SPDXStandard     bool           `json:"spdx_standard"`
	SPDXException    bool           `json:"spdx_exception"`
	OSIApproved      bool           `json:"osi_approved"`
	IgnoreIDMatch    bool           `json:"ignore_id_match"`
	IgnoreNameMatch  bool           `json:"ignore_name_match"`
	Aliases          SliceOfStrings `json:"aliases"`
	URLs             SliceOfStrings `json:"urls"`
	EligibleLicenses SliceOfStrings `json:"eligible_licenses"`
	IsMutator        bool           `json:"is_mutator"`
	IsDeprecated     bool           `json:"is_deprecated"`
	IsFSFLibre       bool           `json:"is_fsf_libre"`
}

// SliceOfStrings gives us []string with special UnmarshalJSON
type SliceOfStrings []string

// UnmarshalJSON reads string or array of strings into []string when json.Unmarshal encounters a SliceOfStrings
func (stringArray *SliceOfStrings) UnmarshalJSON(b []byte) error {
	var stringOrStrings interface{}
	err := json.Unmarshal(b, &stringOrStrings)
	if err != nil {
		return err
	}
	*stringArray = toSliceOfStrings(stringOrStrings)
	return nil
}

// toSliceOfStrings takes an interface which can be a string, a slice of strings, or some interface{} version of that, and convert it into a []string
func toSliceOfStrings(got interface{}) []string {
	if got == nil {
		return nil
	}
	switch got.(type) {
	case []interface{}, []string:
		got := got.([]interface{})
		ret := make([]string, 0, len(got))
		for _, s := range got {
			ret = append(ret, s.(string))
		}
		return ret
	case interface{}, string:
		return []string{got.(string)}
	default:
		panic(fmt.Sprintf("NOT A STRING OR STRINGS %v", got))
	}
}

// readLicenseInfoJSON unmarshalls the json bytes into LicenseInfo
func readLicenseInfoJSON(fileContents []byte) (*LicenseInfo, error) {
	var licenseInfo LicenseInfo
	if err := json.Unmarshal(fileContents, &licenseInfo); err != nil {
		return nil, err
	}
	return &licenseInfo, nil
}

// ReadSPDXLicenseListJSON unmarshalls the json bytes into SPDXLicenseList
func ReadSPDXLicenseListJSON(fileContents []byte) (*SPDXLicenceList, error) {
	var ret SPDXLicenceList
	err := json.Unmarshal(fileContents, &ret)
	return &ret, err
}

type addFunc func(string, string) error

func (l License) GetID() string {
	if l.SPDXLicenseID != "" {
		return l.SPDXLicenseID
	} else {
		return l.LicenseInfo.Name
	}
}

func (ll *LicenseLibrary) AddAll() error {
	if err := ll.AddAllSPDX(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// not exist is okay for now. Assuming legacy resources
		return err
	}
	return ll.AddAllLegacy()
}

func (ll *LicenseLibrary) AddAllSPDX() error {
	resourcesPath := ll.Config.GetString(Resources)
	SPDXDir := ll.Config.GetString(SPDX)
	// templateMap := make(map[string]string)
	templatePath := path.Join(resourcesPath, "spdx", SPDXDir, template)
	jsonPath := path.Join(resourcesPath, "spdx", SPDXDir, jsonDir)

	licensesJSON := path.Join(jsonPath, "licenses.json")
	SPDXLicenseListBytes, err := os.ReadFile(licensesJSON)
	if err != nil {
		return fmt.Errorf("read SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}
	licenseList, err := ReadSPDXLicenseListJSON(SPDXLicenseListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}

	ll.SPDXVersion = licenseList.LicenseListVersion

	exceptionsJSON := path.Join(jsonPath, "exceptions.json")
	SPDXExceptionsListBytes, err := os.ReadFile(exceptionsJSON)
	if err != nil {
		return fmt.Errorf("read exceptions JSON from %v error: %w", exceptionsJSON, err)
	}
	exceptionsList, err := ReadSPDXLicenseListJSON(SPDXExceptionsListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", exceptionsJSON, err)
	}

	for _, sl := range licenseList.Licenses {
		id := sl.LicenseID
		f := getTemplateFilePath(id, sl.IsDeprecatedLicenseID, templatePath)
		tBytes, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				Logger.Debugf("Skipping missing template file '%v'", f)
				continue
			}
			return err
		}

		l := ll.LicenseMap[id]
		if err := AddPrimaryPatternAndSource(string(tBytes), f, &l); err != nil {
			return err
		}
		l.SPDXLicenseID = id
		l.LicenseInfo.Name = sl.Name
		l.LicenseInfo.SPDXStandard = true
		l.LicenseInfo.SPDXException = false
		l.LicenseInfo.IsDeprecated = sl.IsDeprecatedLicenseID
		l.LicenseInfo.OSIApproved = sl.IsOSIApproved
		l.LicenseInfo.IsFSFLibre = sl.IsFSFLibre
		ll.LicenseMap[id] = l
	}

	for _, se := range exceptionsList.Exceptions {
		id := se.LicenseExceptionID
		f := getTemplateFilePath(id, se.IsDeprecatedLicenseID, templatePath)
		tBytes, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				Logger.Debugf("Skipping missing template file '%v'", f)
				continue
			}
			return err
		}

		l := ll.LicenseMap[id]
		if err := AddPrimaryPatternAndSource(string(tBytes), f, &l); err != nil {
			return err
		}
		l.SPDXLicenseID = id
		l.LicenseInfo.Name = se.Name
		l.LicenseInfo.SPDXStandard = true
		l.LicenseInfo.SPDXException = true
		l.LicenseInfo.IsDeprecated = se.IsDeprecatedLicenseID
		ll.LicenseMap[id] = l
	}

	preCheckMap := make(map[string]string)
	preCheckPath := path.Join(resourcesPath, "spdx", SPDXDir, precheck)
	if err := filepath.WalkDir(preCheckPath, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if de.IsDir() {
			if de.Name() == precheck {
				return nil // walk the template dir
			}
			return filepath.SkipDir // ignore any other dirs
		}

		if strings.HasSuffix(de.Name(), ".json") {
			preCheckMap[strings.TrimSuffix(de.Name(), ".json")] = path
		}
		return err
	}); err != nil {
		return err
	}

	for id, f := range preCheckMap {

		fileContents, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		isDeprecated := ll.LicenseMap[id].LicenseInfo.IsDeprecated
		templateFilePath := getTemplateFilePath(id, isDeprecated, templatePath)
		if err := addPreChecks(fileContents, templateFilePath, ll); err != nil {
			return err
		}
	}

	return nil
}

func getTemplateFilePath(id string, isDeprecated bool, templatePath string) string {
	f := id + ".template.txt"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(templatePath, f)
	return f
}

func (ll *LicenseLibrary) AddAllLegacy() error {
	if err := ll.addAcceptablePatternsFromBundledLibrary(); err != nil {
		return err
	}
	Logger.Debugf("Loaded %v acceptable patterns", len(ll.AcceptablePatternsMap))

	if err := ll.AddLicenses(); err != nil {
		return err
	}
	Logger.Debugf("Loaded %v licenses", len(ll.LicenseMap))

	return nil
}

func (ll *LicenseLibrary) addAcceptablePattern(patternId string, source string) error {
	if _, ok := ll.AcceptablePatternsMap[patternId]; ok {
		return fmt.Errorf("An acceptable pattern already exists with the ID %v", patternId)
	}
	source = strings.TrimSpace(source)
	re, err := regexp.Compile("(?i)" + source)
	if err != nil {
		return err
	}
	ll.AcceptablePatternsMap[patternId] = re
	return nil
}

func (ll *LicenseLibrary) addAcceptablePatternsFromBundledLibrary() error {
	_, acceptablePatternsPath := getResourcePaths(ll.Config)
	if err := ll.addRegexFromSourceToLibrary(acceptablePatternsPath, ll.addAcceptablePattern); err != nil && !os.IsNotExist(err) {
		// Ignoring IsNotExist to make acceptable patterns optional, but other errs are not ok
		return err
	}
	return nil
}

func (ll *LicenseLibrary) addRegexFromSourceToLibrary(sourceDir string, addFunction addFunc) error {
	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		} else {
			return nil
		}
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileName := file.Name()
		patternId := fileName[:len(fileName)-len(filepath.Ext(fileName))]
		source, err := ioutil.ReadFile(path.Join(sourceDir, fileName))
		if err != nil {
			return err
		}
		if err := addFunction(patternId, string(source)); err != nil {
			_ = Logger.Errorf("invalid regex from %v/%v with error: %v", sourceDir, fileName, err)
			return err
		}
	}
	return nil
}

func getResourcePaths(cfg *viper.Viper) (licensePatternsPath, acceptablePatternsPath string) {
	rd := cfg.GetString(Resources)
	customVersionedDir := cfg.GetString(configurer.CustomFlag)
	licensePatternsPath = path.Join(rd, customDir, customVersionedDir, LicensePatterns)
	acceptablePatternsPath = path.Join(rd, customDir, customVersionedDir, AcceptablePatterns)
	return
}

// AddLicenses initializes the license data set to scan the input license file against
// all the possible licenses available in the resources are read
func (ll *LicenseLibrary) AddLicenses() error {
	licensePatternsPath, _ := getResourcePaths(ll.Config)
	licenseIds, err := ioutil.ReadDir(licensePatternsPath)
	if err != nil {
		return err
	}

	// retrieve each license ID based on the directory name, i.e. resources/license_patterns/licenseID
	// for example, resources/license_patterns/MIT
	for _, id := range licenseIds {
		err := AddLicense(id.Name(), ll)
		if err != nil {
			_ = Logger.Errorf("AddLicense error on %v: %v", id.Name(), err)
			return err
		}
	}
	return nil
}

func AddLicense(id string, ll *LicenseLibrary) error {
	l, existed := ll.LicenseMap[id]

	licensePatternsPath, _ := getResourcePaths(ll.Config)
	// license directory is at the LicensePatternsPath/id
	licenseDirectory := path.Join(licensePatternsPath, id)
	directoryContents, err := ioutil.ReadDir(licenseDirectory)
	if err != nil {
		return err
	}

	// load license data from the license directory
	for _, file := range directoryContents {
		// reading from a directory at this point is not expected
		// the license patterns contains a list of files with primary and associated patterns (license_MIT.txt, associated_full_title.txt, etc)
		if file.IsDir() {
			continue
		}
		// read the file contents, determine the file path by joining licenseDirectory (LicensePatternsPath/id) and file name
		fileContents, err := ioutil.ReadFile(path.Join(licenseDirectory, file.Name()))
		if err != nil {
			return err
		}
		fileName := file.Name()
		filePath := path.Join(licenseDirectory, fileName)
		lowerFileName := strings.ToLower(fileName)

		switch {
		// the JSON payload is always stored in license_info.txt
		case lowerFileName == LicenseInfoJSON:
			payload, err := readLicenseInfoJSON(fileContents)
			if err != nil {
				return Logger.Errorf("Unmarshal LicenseInfo from %v using LicenseReader error: %v", file.Name(), err)
			}

			if l.SPDXLicenseID == "" {
				if payload.SPDXStandard {
					l.SPDXLicenseID = id
				}
			} else if !payload.SPDXStandard {
				return Logger.Errorf("Cannot add non-SPDX custom policies from %v to existing SPDX license %v", id, l.SPDXLicenseID)
			}

			// Instead of trying to do the optional "the " and optional " license", any string wanted should be configured to be used as-is.
			// Word boundaries before and after the strings will be enforced.

			// ToLower the aliases to prepare them to match it against normalized data.
			var aliases []string
			for _, a := range payload.Aliases {
				aliases = append(aliases, strings.ToLower(a))
			}

			if !payload.IgnoreIDMatch {
				aliases = append(aliases, strings.ToLower(id))
			}
			if !payload.IgnoreNameMatch && payload.Name != "" {
				aliases = append(aliases, strings.ToLower(payload.Name))
			}
			l.Aliases = aliases

			// When the legacy one is disabled, use the stringy version of matching.
			// Instead of trying to do the optional http(s), optional www, etc... any string wanted should be configured to be used as-is.

			// ToLower the URLs to prepare them to match it against normalized data.
			var urls []string
			for _, u := range payload.URLs {
				_, after, found := strings.Cut(u, "://")
				if found {
					urls = append(urls, strings.ToLower(after))
				} else {
					urls = append(urls, strings.ToLower(u))
				}
			}
			l.URLs = urls

			if existed { // merge the additional LicenseInfo with the existing SPDX attributes
				if l.LicenseInfo.Name != "" {
					payload.Name = l.LicenseInfo.Name // Use first name we got (from SPDX), if not empty
				}
				// Merge SPDX bools flags. Use true if either existing or payload says true
				payload.SPDXStandard = payload.SPDXStandard || l.LicenseInfo.SPDXStandard
				payload.SPDXException = payload.SPDXException || l.LicenseInfo.SPDXException
				payload.IsDeprecated = payload.IsDeprecated || l.LicenseInfo.IsDeprecated
				payload.OSIApproved = payload.OSIApproved || l.LicenseInfo.OSIApproved
				payload.IsFSFLibre = payload.IsFSFLibre || l.LicenseInfo.IsFSFLibre
			}
			l.LicenseInfo = *payload

		// all other files starting with "license_" are primary license patterns
		case strings.HasPrefix(lowerFileName, PrimaryPattern):
			if err := AddPrimaryPatternAndSource(string(fileContents), filePath, &l); err != nil {
				return err
			}

		// all other files starting with "prechecks_" are prechecks for license patterns
		case strings.HasPrefix(lowerFileName, PreChecksPattern):
			sourceFile := strings.TrimPrefix(fileName, PreChecksPattern)
			ext := path.Ext(sourceFile)
			sourceFile = sourceFile[0:len(sourceFile)-len(ext)] + ".txt" // Replace .json with .txt
			filePath := path.Join(licenseDirectory, sourceFile)
			if err := addPreChecks(fileContents, filePath, ll); err != nil {
				return err
			}

		// All files starting with "associated_" or "optional_" are associated patterns
		case strings.HasPrefix(lowerFileName, AssociatedPattern), strings.HasPrefix(lowerFileName, OptionalPattern):
			p := PrimaryPatternsSources{
				SourceText: string(fileContents),
				Filename:   filePath,
			}
			l.AssociatedPatternsSources = append(l.AssociatedPatternsSources, p)
			associatedPattern := PrimaryPatterns{
				Text:     p.SourceText,
				FileName: p.Filename,
			}
			l.AssociatedPatterns = append(l.AssociatedPatterns, &associatedPattern)
		default:
			Logger.Info(fmt.Sprintf("found an invalid file name %s", filePath))
		}
	}
	ll.LicenseMap[id] = l
	return nil
}

func addPreChecks(fileContents []byte, templatePath string, ll *LicenseLibrary) error {
	readPreChecks := &LicensePreChecks{}
	err := json.Unmarshal(fileContents, readPreChecks)
	if err != nil {
		return fmt.Errorf("error on unmarshal %v: %w", templatePath, err)
	} else {
		licensePatternKey := LicensePatternKey{
			FilePath: templatePath,
		}
		ll.PrimaryPatternPreCheckMap[licensePatternKey] = readPreChecks
	}
	return nil
}

func AddPrimaryPatternAndSource(fileContents string, filePath string, l *License) error {
	p := PrimaryPatternsSources{
		SourceText: fileContents,
		Filename:   filePath,
	}
	l.PrimaryPatternsSources = append(l.PrimaryPatternsSources, p)
	primaryPattern := PrimaryPatterns{
		Text:     p.SourceText,
		FileName: p.Filename,
	}
	l.PrimaryPatterns = append(l.PrimaryPatterns, &primaryPattern)
	return nil
}

// GenerateMatchingPatternFromSourceText normalizes and compiles a pattern once with sync
func GenerateMatchingPatternFromSourceText(pp *PrimaryPatterns) (*regexp.Regexp, error) {
	var err error
	pp.doOnce.Do(func() {
		// Normalize the input text.
		normalizedData := normalizer.NewNormalizationData(pp.Text, true)
		err = normalizedData.NormalizeText()
		if err == nil {
			var re *regexp.Regexp
			re, err = GenerateRegexFromNormalizedText(normalizedData.NormalizedText)
			if err == nil {
				pp.re = re
				pp.CaptureGroups = normalizedData.CaptureGroups
			} else {
				err = fmt.Errorf("cannot generate re: %v", err)
			}
		}
	})
	return pp.re, err
}

func GenerateRegexFromNormalizedText(normalizedText string) (*regexp.Regexp, error) {
	// Eat optional single space before "<<" and after ">>" (just refactoring what was in regex)
	text := spaceTagReplacer.Replace(normalizedText)
	// Replace simple tags with tokens, so we can attack the not-simple tags which might be nested in these
	text = tagReplacer.Replace(text)

	// Replace matched <<segment>> with ` ?(?:(`+segment+`) ?)`
	// Escape regex-unsafe characters outside of tags.
	// Then put the segments back together
	matches := pointyBracketSegmentRE.FindAllStringSubmatchIndex(text, -1)

	var segments []string
	prev := 0
	for _, ii := range matches {

		start := ii[0]
		end := ii[1]

		if start > prev {
			// Handle pre-match characters
			// Escape unsafe characters in the text elements.
			segment := text[prev:start]
			segment = RegexUnsafePattern.ReplaceAllString(segment, `\${1}`)
			segments = append(segments, segment)
		}

		// Handle the sub-matched chars (inside the <<>>)
		submatchStart := ii[2]
		submatchEnd := ii[3]
		segment := text[submatchStart:submatchEnd]

		prev = end
		segments = append(segments, ` *(?:(`+segment+`) *)`)
	}
	if prev < len(text) {
		segment := text[prev:]
		segment = RegexUnsafePattern.ReplaceAllString(segment, `\${1}`)
		segments = append(segments, segment)
	}

	// Rejoin segments, replace tokens, compile, and return (*re, err)
	text = strings.Join(segments, "")
	text = tokenReplacer.Replace(text)
	return regexp.Compile(text)
}

func List(config *viper.Viper) (lics []Detail, deprecatedLics []Detail, exceptions []Exception, deprecatedExceptions []Exception, spdxVersion string, err error) {
	var ll *LicenseLibrary
	ll, err = NewLicenseLibrary(config)
	if err != nil {
		return
	}

	err = ll.AddAll()
	if err != nil {
		return
	}

	spdxVersion = ll.SPDXVersion

	lm := ll.LicenseMap

	// Sort by key
	keys := make([]string, 0, len(lm))
	for key := range lm {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, k := range keys {
		isException := lm[k].LicenseInfo.SPDXException
		isDeprecated := lm[k].LicenseInfo.IsDeprecated

		if isException { //nolint:nestif
			e := Exception{
				ID:           lm[k].SPDXLicenseID,
				Name:         lm[k].LicenseInfo.Name,
				Family:       lm[k].LicenseInfo.Family,
				NumTemplates: len(lm[k].PrimaryPatterns),
			}
			if isDeprecated {
				deprecatedExceptions = append(deprecatedExceptions, e)
			} else {
				exceptions = append(exceptions, e)
			}
		} else {
			l := Detail{
				ID:            lm[k].SPDXLicenseID,
				Name:          lm[k].LicenseInfo.Name,
				Family:        lm[k].LicenseInfo.Family,
				IsOSIApproved: lm[k].LicenseInfo.OSIApproved,
				IsFSFLibre:    lm[k].LicenseInfo.IsFSFLibre,
				NumTemplates:  len(lm[k].PrimaryPatterns),
			}
			if isDeprecated {
				deprecatedLics = append(deprecatedLics, l)
			} else {
				lics = append(lics, l)
			}
		}
	}
	return
}
