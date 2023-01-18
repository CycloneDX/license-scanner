// SPDX-License-Identifier: Apache-2.0

package configurer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/spf13/pflag"

	"github.com/spf13/viper"
)

const (
	AcceptableFlag = "acceptable"
	CopyrightsFlag = "copyrights"
	NormalizedFlag = "normalized"
	HashFlag       = "hash"
	KeywordsFlag   = "keywords"
	ListFlag       = "list"
	AddAllFlag     = "addAll"
	AddPatternFlag = "addPattern"
	DebugFlag      = "debug"
	QuietFlag      = "quiet"
	LicenseFlag    = "license"
	DirFlag        = "dir"
	FileFlag       = "file"
	ConfigPathFlag = "configPath"
	ConfigNameFlag = "configName"
	SpdxFlag       = "spdx"
	CustomFlag     = "custom"
)

var (
	_, thisFile, _, _ = runtime.Caller(0) // Dirs/files are relative to this file
	thisDir           = filepath.Dir(thisFile)
	execDir, _        = os.Executable()
	execPath          = filepath.Dir(execDir)
	projectRoot       = path.Join(thisDir, "..")
)

func InitConfig(flags *pflag.FlagSet) (*viper.Viper, error) {
	newViper := viper.New()
	newViper.AutomaticEnv()

	newViper.SetDefault("resources", path.Join(projectRoot, "resources"))
	newViper.SetDefault("configName", "config")

	if flags != nil {
		if err := newViper.BindPFlags(flags); err != nil {
			return newViper, fmt.Errorf("InitConfig bind flags err: %+v", err)
		}
	} else {
		err := newViper.BindPFlags(NewDefaultFlags())
		if err != nil {
			return nil, err
		}
	}

	configName := newViper.GetString("configName")
	configPath := newViper.GetString("configPath")

	// TODO: Deprecate configFrom in favor of configPath and configName
	configFrom := newViper.GetString("configFrom")
	if configFrom != "" {
		if path.IsAbs(configFrom) {
			newViper.SetConfigFile(configFrom)
		} else {
			configFrom = path.Join(thisDir, "..", configFrom)
			newViper.SetConfigFile(configFrom)
		}
	} else { // configPath (configName defaults to "config.<ext>")
		newViper.SetConfigName(configName)
		if configPath != "" {
			newViper.AddConfigPath(configPath)
		} else {
			newViper.AddConfigPath(execPath)
			newViper.AddConfigPath(projectRoot)
		}
	}

	err := newViper.MergeInConfig()
	if err != nil {
		return nil, fmt.Errorf("MergeInConfig err: %w", err)
	}

	// If we didn't get a resources flag, then relative config file resources need to be relative to the config file
	if flags == nil || flags.Lookup("resources") == nil {
		configFileUsed := newViper.ConfigFileUsed()
		if configFileUsed != "" {
			configDir := filepath.Dir(configFileUsed)

			// Make all relative paths relative to the config file used.
			resources := newViper.GetString("resources")
			if resources != "" && !path.IsAbs(resources) {
				resources = path.Join(configDir, resources)
				newViper.Set("resources", resources) // override
			}
		}
	}

	// TODO: env from a file is W-I-P.
	// Doc and test or just use config.env with above code and remove this.
	envFrom := newViper.GetString("envFrom")
	if envFrom != "" {
		newViper.SetConfigFile(envFrom)
		if err := newViper.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("envFrom file err: %+v", err)
		}
	}
	return newViper, nil
}

func NewDefaultFlags() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("default flagset for configurer", pflag.ContinueOnError)
	AddDefaultFlags(flagSet)
	return flagSet
}

func AddDefaultFlags(flagSet *pflag.FlagSet) {
	flagSet.BoolP(DebugFlag, "d", false, "Enable debug logging")
	flagSet.BoolP(QuietFlag, "q", false, "Set logging to quiet")
	flagSet.String(DirFlag, "", "A directory in which to identify licenses")
	flagSet.StringP(FileFlag, "f", "", "A file in which to identify licenses")
	flagSet.BoolP(AcceptableFlag, "g", false, "Flag acceptable")
	flagSet.BoolP(KeywordsFlag, "k", false, "Flag keywords")
	flagSet.BoolP(CopyrightsFlag, "c", false, "Flag copyrights")
	flagSet.BoolP(NormalizedFlag, "n", false, "Flag normalized")
	flagSet.BoolP(HashFlag, "x", false, "Output file hash")
	flagSet.StringP(LicenseFlag, "l", "", "Display match debugging for the given license")
	flagSet.StringP(AddPatternFlag, "a", "", "Add a new license pattern to the library, from SPDX")
	flagSet.Bool(ListFlag, false, "List the license templates to be used")
	flagSet.String(AddAllFlag, "", "Add the licenses from SPDX unzipped release")
	flagSet.String(ConfigPathFlag, "", "Path to any config files")
	flagSet.String(ConfigNameFlag, "config", "Base name for config file")
	flagSet.String(SpdxFlag, "default", "SPDX templates to use")
	flagSet.String(CustomFlag, "default", "Custom templates to use")
}
