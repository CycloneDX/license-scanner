// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"

	"github.com/IBM/license-scanner/configurer"
	"github.com/IBM/license-scanner/debugger"
	"github.com/IBM/license-scanner/identifier"
	"github.com/IBM/license-scanner/importer"
	"github.com/IBM/license-scanner/licenses"
)

const (
	currentVersion = "0.0.0"
	project        = "license-scanner"
)

var (
	ProjectLogger = log.NewLogger(log.DEFAULT_LEVEL)

	// rootCmd represents the base command when called without any subcommands
	rootCmd = NewRootCmd()
)

func logScanTimeMS(startTime int64) {
	ProjectLogger.Debugf("Scan took %v milliseconds.", (time.Now().UnixMicro()-startTime)/1000)
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   project,
		Short: fmt.Sprintf("%v: scan files to detect licenses", project),
		Long: `
LICENSE-SCANNER

Scan files to detect licenses.

Example usage to print copyrights, hash codes, and blocks found in file LICENSE.txt:

    $ license-scanner -c -x -f LICENSE.txt

Example usage to scan LICENSE.txt, but only print the license IDs and positions of license matches:

    $ license-scanner --quiet -f LICENSE.txt

Please give us feedback at: https://github.com/IBM/license-scanner/issues
		`,
		Args:    cobra.NoArgs,
		Version: currentVersion,
		RunE: func(cmd *cobra.Command, args []string) error {
			ProjectLogger.Enter("RunCommand()")
			defer ProjectLogger.Exit("RunCommand()")

			cfg, err := configurer.InitConfig(cmd.Flags())
			if err != nil {
				ProjectLogger.Error(err)
				return err
			}

			if cfg.GetBool(configurer.DebugFlag) {
				ProjectLogger.SetLevel(log.DEBUG)
			}

			ProjectLogger.SetQuietMode(cfg.GetBool(configurer.QuietFlag))

			if ProjectLogger.GetLevel() >= log.TRACE {
				ProjectLogger.Debugf(" * Flags: %+v", cfg.AllSettings())
			}

			f := cfg.GetString(configurer.FileFlag)
			if f != "" {
				return findLicensesInFile(cfg, f)
			} else if cfg.GetString(configurer.DirFlag) != "" {
				return findLicensesInDirectory(cfg)
			} else if cfg.GetBool(configurer.ListFlag) {
				return listLicenses(cfg)
			} else if cfg.GetString(configurer.AddAllFlag) != "" {
				return importer.AddAllSPDXTemplates(cfg)
			} else if cfg.GetString(configurer.AddPatternFlag) != "" {
				// Otherwise, if addPattern was requested, attempt to add that pattern.
				return errors.New("add_pattern_from_spdx() is NOT-IMPLEMENTED")
			} else {
				// Otherwise, terminate with an error.
				return errors.New("you must provide a file path")
			}
		},
	}
	notGlobalInit(cmd)
	return cmd
}

// y returns "Y" for true and " " for false to make readable table cells
func y(isIt bool) string {
	if isIt {
		return "Y"
	} else {
		return " "
	}
}

func listLicenses(cfg *viper.Viper) error {
	lics, deprecatedLics, exceptions, deprecatedExceptions, spdxVersion, err := licenses.List(cfg)
	if err != nil {
		return err
	}

	fmt.Println("## Licenses")
	fmt.Printf("| %v | %v | %v | %v | %v | %v |\n", "ID", "Name", "Family", "Templates", "OSI Approved", "FSF Libre")
	fmt.Println("| :--- | :--- | :--- | ---: | :---: | :---: |")
	for _, l := range lics {
		fmt.Printf("| %v | %v | %v | %v | %v | %v |\n", l.ID, l.Name, l.Family, l.NumTemplates, y(l.IsOSIApproved), y(l.IsFSFLibre))
	}

	fmt.Println("## Exceptions")
	fmt.Printf("| %v | %v | %v | %v |\n", "ID", "Name", "Family", "Templates")
	fmt.Println("| :--- | :--- | :--- | ---: |")
	for _, e := range exceptions {
		fmt.Printf("| %v | %v | %v | %v |\n", e.ID, e.Name, e.Family, e.NumTemplates)
	}

	fmt.Println("## Deprecated Licenses")
	fmt.Printf("| %v | %v | %v | %v | %v | %v |\n", "ID", "Name", "Family", "Templates", "OSI Approved", "FSF Libre")
	fmt.Println("| :--- | :--- | :--- | ---: | :---: | :---: |")
	for _, l := range deprecatedLics {
		fmt.Printf("| %v | %v | %v | %v | %v | %v |\n", l.ID, l.Name, l.Family, l.NumTemplates, y(l.IsOSIApproved), y(l.IsFSFLibre))
	}

	fmt.Println("## Deprecated Exceptions")
	fmt.Printf("| %v | %v | %v | %v |\n", "ID", "Name", "Family", "Templates")
	fmt.Println("| :--- | :--- | :--- | ---: |")
	for _, e := range deprecatedExceptions {
		fmt.Printf("| %v | %v | %v | %v |\n", e.ID, e.Name, e.Family, e.NumTemplates)
	}

	var licenseListVersion string
	if spdxVersion != "" {
		licenseListVersion = fmt.Sprintf("  (SPDX license list %v)", spdxVersion)
	}
	fmt.Println("## Runtime Configuration")
	fmt.Printf("* resources: %v\n", cfg.GetString("resources"))
	fmt.Printf("  * spdx/%v%v\n", cfg.GetString(configurer.SpdxFlag), licenseListVersion)
	fmt.Printf("  * custom/%v\n", cfg.GetString(configurer.CustomFlag))
	fmt.Printf("\n###### Generated on %v\n", time.Now().Format(time.RFC3339))
	return nil
}

func findLicensesInDirectory(cfg *viper.Viper) error {
	d := cfg.GetString(configurer.DirFlag)

	licenseLibrary, err := licenses.NewLicenseLibrary(cfg)
	if err != nil {
		return err
	}
	if err := licenseLibrary.AddAll(); err != nil {
		return err
	}

	options := identifier.Options{
		ForceResult: true,
		Enhancements: identifier.Enhancements{
			AddNotes:       "",
			AddTextBlocks:  true,
			FlagAcceptable: cfg.GetBool(configurer.AcceptableFlag),
			FlagCopyrights: cfg.GetBool(configurer.CopyrightsFlag),
			FlagKeywords:   cfg.GetBool(configurer.KeywordsFlag),
		},
	}

	results, err := identifier.IdentifyLicensesInDirectory(d, options, licenseLibrary)
	if err != nil {
		return err
	}

	for _, result := range results {
		if len(result.Matches) > 0 {

			// Print the matches by license ID in alphabetical order
			fmt.Printf("\nFOUND LICENSE MATCHES: %v\n", result.File)
			var found []string
			for id := range result.Matches {
				found = append(found, id)
			}
			sort.Strings(found)
			for _, id := range found {
				fmt.Printf("\tLicense ID:\t%v", id)
				fmt.Println()
				var prev identifier.Match
				for _, m := range result.Matches[id] {
					// Print if not same as prev
					if m != prev {
						fmt.Printf("\t\tbegins: %5v\tends: %5v\n", m.Begins, m.Ends)
						prev = m
					}
				}
			}
			fmt.Println()

			if ProjectLogger.GetLevel() >= log.INFO {
				for _, block := range result.Blocks {
					ProjectLogger.Infof("%v :: %v", block.Matches, block.Text)
				}
			}
		} else {
			fmt.Printf("\nNo licenses were found: %v\n", result.File)
		}
	}
	return nil
}

func findLicensesInFile(cfg *viper.Viper, f string) error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()
	startTime := time.Now().UnixMicro()
	ProjectLogger.Info("Looking for all licences")

	licenseLibrary, err := licenses.NewLicenseLibrary(cfg)
	if err != nil {
		logScanTimeMS(startTime)
		return err
	}
	if err := licenseLibrary.AddAll(); err != nil {
		logScanTimeMS(startTime)
		return err
	}

	options := identifier.Options{
		ForceResult: true,
		Enhancements: identifier.Enhancements{
			AddNotes:       "",
			AddTextBlocks:  true,
			FlagAcceptable: cfg.GetBool(configurer.AcceptableFlag),
			FlagCopyrights: cfg.GetBool(configurer.CopyrightsFlag),
			FlagKeywords:   cfg.GetBool(configurer.KeywordsFlag),
		},
	}

	results, err := identifier.IdentifyLicensesInFile(f, options, licenseLibrary)
	if err != nil {
		logScanTimeMS(startTime)
		return err
	}

	licenseArg := cfg.GetString(configurer.LicenseFlag)
	if len(results.Matches) > 0 {

		// Print the matches by license ID in alphabetical order
		fmt.Printf("\nFOUND LICENSE MATCHES:\n")
		var found []string
		for id := range results.Matches {
			found = append(found, id)
		}
		sort.Strings(found)
		for _, id := range found {
			fmt.Printf("\tLicense ID:\t%v", id)
			fmt.Println()
			var prev identifier.Match
			for _, m := range results.Matches[id] {
				// Print if not same as prev
				if m != prev {
					fmt.Printf("\t\tbegins: %5v\tends: %5v\n", m.Begins, m.Ends)
					prev = m
				}
			}
		}
		fmt.Println()

		if licenseArg == "" {
			for _, block := range results.Blocks {
				ProjectLogger.Infof("%v :: %v", block.Matches, block.Text)
			}
		}
	} else {
		ProjectLogger.Info("No licenses were found")
	}

	if licenseArg != "" {
		// If a license is also provided, debug against that license.
		ProjectLogger.Info("Looking for a specific license")
		debugResults, err := debugger.DebugLicenseMatchFailure(licenseLibrary.LicenseMap[licenseArg], results.NormalizedText)
		if err != nil {
			return err
		}

		for i, debugResult := range debugResults {
			ProjectLogger.Infof("Matching Pattern %v\n", i)
			ProjectLogger.Info(debugResult)
		}
	}

	if cfg.GetBool(configurer.HashFlag) {
		ProjectLogger.Infof("File Hash: %v", results.Hash.Md5)
	}
	if cfg.GetBool(configurer.NormalizedFlag) {
		ProjectLogger.Info("Normalized Text:")
		ProjectLogger.Info(results.NormalizedText)
	}

	logScanTimeMS(startTime)
	return nil
}

func notGlobalInit(c *cobra.Command) {
	// Add configurer flag definitions, shared with API, added to CLI flags here.
	configurer.AddDefaultFlags(c.Flags())
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if ProjectLogger.GetLevel() >= log.DEBUG {
		_ = doc.GenMarkdownTree(rootCmd, "./cmd/")
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
