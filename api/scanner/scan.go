// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/IBM/license-scanner/configurer"

	"github.com/IBM/license-scanner/identifier"
	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

// NOASSERTION_SPDX_NAME in License SPDX Name signify that the license text passed through the scan without any errors but no match was found
const NOASSERTION_SPDX_NAME = "NOASSERTION"

// ScanSpecs holds the package manager, the programming language, and a list of multiple packages with their specifications
type ScanSpecs struct {
	// package manager to search for
	// This is the standard package manager, for example, pypi for python, npm for nodejs, etc
	PackageManager string
	// programming language to search for
	Language string
	// a list of scan specification
	// for a single package manager or a language, specify a list of packages with their respective specifications
	Specs []ScanSpec
	// config flag set
	flags *pflag.FlagSet
}

// ScanSpec holds the specifications used for scanning the incoming package/file
type ScanSpec struct {
	// file name or package name to search for.
	// This will also be matched against known package URL or known file names. If a match is found, the canonical name will be returned in the ScanResult.
	Name string
	// package version number to search for.
	// If no version is provided, the scanning service defaults to the package manager default which is mostly the latest version.
	Version string
	// location from where the file can be retrieved or a package can be downloaded.
	// If no location is provided, the package source location is retrieved from the package manager.
	// TODO: Resolve - Can we get the file content from the file system or should that be included as part of the specification?
	Location string
	// Package URL to search for.
	// This is the standardized URL used to identify and locate a software package across many programming languages and package managers.
	PURL string
	// file hash or package hash to search for.
	// This will also be matched against known file hashes.
	// TODO: Create a proposal for hashing algorithm of a package.
	Hash *normalizer.Digest
	// license input text to match and identify the license against the data set
	LicenseText string
}

// LicenseChoice is a collection of a License info with expression
// either license or expression must be set, but not both
// CycloneDX defines the LicenseChoice is defined here:
// https://github.com/CycloneDX/cyclonedx-go/blob/7d9a5619d767a252b454e8554d0fc986796ef958/cyclonedx.go#L462-L465
type LicenseChoice struct {
	License    *License
	Expression string
}

// License is a collection of SPDX ID, name, license text, and license URL
// CycloneDX license struct defined here:
// https://github.com/CycloneDX/cyclonedx-go/blob/7d9a5619d767a252b454e8554d0fc986796ef958/cyclonedx.go#L389-L394
type License struct {
	ID   string
	Name string
	Text *AttachedText
	URL  string
}

// AttachedText holds the formatted License Text
// CycloneDX AttachedText is defined here:
// https://github.com/CycloneDX/cyclonedx-go/blob/7d9a5619d767a252b454e8554d0fc986796ef958/cyclonedx.go#L52-L56
type AttachedText struct {
	Content     string
	ContentType string
	Encoding    string
}

type Licenses []LicenseChoice

// ScanResult holds the license identification results for a given package
type ScanResult struct {
	// the specification from the user to perform the scan
	Spec ScanSpec
	// source text which matched against the SPDX License Data
	OriginalText string
	// normalized version of the source text which is compared against the license text
	NormalizedText string
	// file hash or package hash
	// set to the hash if provided or calculate based on the input text (normalized)
	Hash *normalizer.Digest
	// error reported during the scan - includes empty license text or too large license text etc
	Error error
	// a list of LicenseMatch i.e. a list of SPDX license IDs in sequential order, the matches of the input text across the various licenses
	CycloneDXLicenses Licenses
}

// WithConfig sets the config to use for the scan
func (s *ScanSpecs) WithFlags(flags *pflag.FlagSet) *ScanSpecs {
	s.flags = flags
	return s
}

// ScanLicenseText scans the specified license file to retrieve license information
func (s *ScanSpecs) ScanLicenseText() ([]*ScanResult, error) {
	cfg, err := configurer.InitConfig(s.flags)
	if err != nil {
		return nil, err
	}
	licenseLibrary, err := licenses.NewLicenseLibrary(cfg)
	if err != nil {
		return nil, err
	}

	// initialize the license data set to compare against
	if err := licenseLibrary.AddAll(); err != nil {
		return nil, err
	}

	var r []*ScanResult

	// resultsCache is a local cache holding the results of scanned license text
	// this cache is searched before every scan to get the scan results if they exist
	// this cache is updated after every new license match found
	resultsCache := make(map[normalizer.Digest]*ScanResult)

	for _, p := range s.Specs {
		// identify license information for the specified license text
		scanResult := p.ScanLicenseText(licenseLibrary, resultsCache)
		r = append(r, scanResult)
	}
	return r, nil
}

// ScanLicenseText scans the specified license file to retrieve license information
func (s *ScanSpec) ScanLicenseText(licenseLibrary *licenses.LicenseLibrary, resultsCache map[normalizer.Digest]*ScanResult) *ScanResult {
	// create a scanResult with the specifications and licenseText
	r := &ScanResult{
		Spec:              *s,
		OriginalText:      s.LicenseText,
		CycloneDXLicenses: Licenses{},
	}

	// instantiate normalizedData with the input license text
	normalizedData := normalizer.NormalizationData{
		OriginalText: s.LicenseText,
	}

	// normalize the input license text
	if err := normalizedData.NormalizeText(); err != nil {
		r.Error = err
		return r
	}

	// set the normalized text and hashes
	r.NormalizedText = normalizedData.NormalizedText
	r.Hash = &normalizedData.Hash

	// check the cache in memory if we have seen the same license before
	// return the result if it exists in the cache to avoid running identification for it
	if cachedResult, ok := resultsCache[*r.Hash]; ok {
		return cachedResult
	}

	// find the licenses in the normalized text and return a list of SPDX IDs
	// in case of an error, return as much as we have along with an error
	results, err := identifier.Identify(identifier.Options{}, licenseLibrary, normalizedData)
	if err != nil {
		r.Error = err
		return r
	}

	// if the results are empty, add unknown as the SPDX ID
	if len(results.Matches) == 0 {
		// Add NOASSERTION to the LicenseChoice of the SPDX Name for this scan
		r.CycloneDXLicenses = append(r.CycloneDXLicenses, LicenseChoice{
			License: &License{
				Name: NOASSERTION_SPDX_NAME,
			},
		})
	} else {
		// iterate over the list of matches and maintain the unique list of SPDX IDs in the result
		for id := range results.Matches {
			// Add an SPDX ID from the match
			// update the LicenseChoice to include each new match

			// Add suffix of (family) to the name, if we have a family
			family := licenseLibrary.LicenseMap[id].LicenseInfo.Family
			name := licenseLibrary.LicenseMap[id].LicenseInfo.Name
			if family != "" {
				name = fmt.Sprintf("%s (%s)", name, family)
			}
			r.CycloneDXLicenses = append(r.CycloneDXLicenses, LicenseChoice{
				License: &License{
					ID:   id,
					Name: name,
					// TODO: verify whether this is acceptable or just expect a single license here
					URL: strings.Join(licenseLibrary.LicenseMap[id].LicenseInfo.URLs, ","),
					Text: &AttachedText{
						Content:     licenseLibrary.LicenseMap[id].Text.Content,
						ContentType: licenseLibrary.LicenseMap[id].Text.ContentType,
						Encoding:    licenseLibrary.LicenseMap[id].Text.Encoding,
					},
				},
			})

		}
	}

	// populate the results cache to keep the match in memory for next license match
	resultsCache[*r.Hash] = r

	return r
}

// ScanFile looks up a specific file by name to retrieve license data.
// If the license data is not available, scan the specified file,
// persist the scanned result into a datastore, and return the license data.
func (s *ScanSpecs) ScanFile() []*ScanResult {
	var r []*ScanResult
	// identify license information for each specified package
	for _, p := range s.Specs {
		r = append(r, &ScanResult{
			Spec: p,
		})
	}
	return r
}
