// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/CycloneDX/license-scanner/configurer"
	"github.com/CycloneDX/license-scanner/debugger"
	"github.com/CycloneDX/license-scanner/identifier"
	"github.com/CycloneDX/license-scanner/importer"
	"github.com/CycloneDX/license-scanner/licenses"
	"github.com/CycloneDX/sbom-utility/log"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
)

const (
	currentVersion = "0.0.0"
	project        = "license-scanner"
)

var (
	Logger *log.MiniLogger = log.NewLogger(log.DEFAULT_LEVEL)
	// rootCmd represents the base command when called without any subcommands
	rootCmd = NewRootCmd()
)

func logScanTimeMS(startTime int64) {
	Logger.Debugf("Scan took %v milliseconds.", (time.Now().UnixMicro()-startTime)/1000)
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          project,
		SilenceUsage: true,
		Short:        fmt.Sprintf("%v: scan files to detect licenses", project),
		Long: `
LICENSE-SCANNER

Scan files to detect licenses.

Example usage to print copyrights, hash codes, and blocks found in file LICENSE.txt:

    $ license-scanner -c -x -f LICENSE.txt

Example usage to scan LICENSE.txt, but only print the license IDs and positions of license matches:

    $ license-scanner --quiet -f LICENSE.txt

Please give us feedback at: https://github.com/CycloneDX/license-scanner/issues
		`,
		Args:    cobra.NoArgs,
		Version: currentVersion,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := configurer.InitConfig(cmd.Flags())
			if err != nil {
				Logger.Error(err)
				return err
			}

			if cfg.GetBool(configurer.DebugFlag) {
				Logger.SetLevel(log.DEBUG)
			}

			Logger.SetQuietMode(cfg.GetBool(configurer.QuietFlag))
			if Logger.GetLevel() == log.DEBUG {
				mapSettings := cfg.AllSettings()
				formattedSettings, _ := json.MarshalIndent(mapSettings, "", "")
				Logger.Debugf(" * Flags: %+v", string(formattedSettings))
				Logger.DumpArgs()
			}

			f := cfg.GetString(configurer.FileFlag)
			if f != "" {
				return findLicensesInFile(cfg, f)
			} else if cfg.GetString(configurer.DirFlag) != "" {
				return findLicensesInDirectory(cfg)
			} else if cfg.GetBool(configurer.ListFlag) {
				return listLicenses(cfg)
			} else if cfg.GetString(configurer.AddAllFlag) != "" {
				return importer.Import(cfg)
			} else if cfg.GetBool(configurer.UpdateAllFlag) {
				return importer.Update(cfg)
			} else {
				// Otherwise, terminate with an error.
				err = Logger.Errorf("you must provide a command valid flag")
				cmd.Help()
				return err
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
	fmt.Printf("  * spdx/%v%v\n", cfg.GetString(configurer.SpdxFlag), licenseListVersion)
	fmt.Printf("  * custom/%v\n", cfg.GetString(configurer.CustomFlag))
	fmt.Println()
	fmt.Println("## License Library")
	fmt.Printf("| %v | %v |\n", "Type", "Count")
	fmt.Printf("| :--- | ---: |\n")
	fmt.Printf("| Licenses              | %v |\n", len(lics))
	fmt.Printf("| Exceptions            | %v |\n", len(exceptions))
	fmt.Printf("| Deprecated Licenses   | %v |\n", len(deprecatedLics))
	fmt.Printf("| Deprecated Exceptions | %v |\n", len(deprecatedExceptions))
	fmt.Printf("\n###### Generated on %v\n", time.Now().Format(time.RFC3339))
	return nil
}

func getCommandLineOptions(cfg *viper.Viper) (options identifier.Options) {
	options = identifier.Options{
		ForceResult: true,
		Enhancements: identifier.Enhancements{
			AddNotes:       "",
			AddTextBlocks:  true,
			FlagAcceptable: cfg.GetBool(configurer.AcceptableFlag),
			FlagCopyrights: cfg.GetBool(configurer.CopyrightsFlag),
			FlagKeywords:   cfg.GetBool(configurer.KeywordsFlag),
		},
	}
	return
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
	// retrieve command line options from flags
	options := getCommandLineOptions(cfg)

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

			if Logger.GetLevel() >= log.INFO {
				for _, block := range result.Blocks {
					Logger.Infof("%v :: %v", block.Matches, block.Text)
				}
			}
		} else {
			fmt.Printf("\nNo licenses were found: %v\n", result.File)
		}
	}
	return nil
}

func findLicensesInFile(cfg *viper.Viper, f string) error {
	Logger.Enter()
	defer Logger.Exit()
	startTime := time.Now().UnixMicro()
	Logger.Info("Looking for all licenses")

	licenseLibrary, err := licenses.NewLicenseLibrary(cfg)
	if err != nil {
		logScanTimeMS(startTime)
		return err
	}
	if err := licenseLibrary.AddAll(); err != nil {
		logScanTimeMS(startTime)
		return err
	}

	// retrieve command line options from flags
	options := getCommandLineOptions(cfg)

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
				Logger.Infof("%v :: %v", block.Matches, block.Text)
			}
		}
	} else {
		Logger.Info("No licenses were found")
	}

	if licenseArg != "" {
		// If a license is also provided, debug against that license.
		Logger.Info("Looking for a specific license")
		debugResults, err := debugger.DebugLicenseMatchFailure(licenseLibrary.LicenseMap[licenseArg], results.NormalizedText)
		if err != nil {
			return err
		}

		for i, debugResult := range debugResults {
			Logger.Infof("Matching Pattern %v\n", i)
			Logger.Info(debugResult)
		}
	}

	if cfg.GetBool(configurer.HashFlag) {
		Logger.Infof("File Hash: %v", results.Hash.Md5)
	}
	if cfg.GetBool(configurer.NormalizedFlag) {
		Logger.Info("Normalized Text:")
		Logger.Info(results.NormalizedText)
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
	if Logger.GetLevel() >= log.DEBUG {
		_ = doc.GenMarkdownTree(rootCmd, "./cmd/")
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
