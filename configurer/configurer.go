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
	DefaultResource = "default"
	AcceptableFlag  = "acceptable"
	CopyrightsFlag  = "copyrights"
	NormalizedFlag  = "normalized"
	HashFlag        = "hash"
	KeywordsFlag    = "keywords"
	ListFlag        = "list"
	AddAllFlag      = "addAll"
	UpdateAllFlag   = "updateAll"
	DebugFlag       = "debug"
	QuietFlag       = "quiet"
	LicenseFlag     = "license"
	DirFlag         = "dir"
	FileFlag        = "file"
	ConfigPathFlag  = "configPath"
	ConfigNameFlag  = "configName"
	SpdxFlag        = "spdx"
	SpdxPathFlag    = "spdxPath"
	CustomFlag      = "custom"
	CustomPathFlag  = "customPath"
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

	configNameDefault := "config"
	newViper.SetDefault("configName", configNameDefault)

	if flags != nil {
		if err := newViper.BindPFlags(flags); err != nil {
			return newViper, fmt.Errorf("InitConfig bind flags err: %w", err)
		}
	} else {
		err := newViper.BindPFlags(NewDefaultFlags())
		if err != nil {
			return nil, err
		}
	}

	configName := newViper.GetString("configName")
	configPath := newViper.GetString("configPath")
	newViper.SetConfigName(configName)
	if configPath != "" {
		fileInfo, err := os.Lstat(configPath)
		if err != nil {
			return nil, err
		}
		if !fileInfo.IsDir() {
			return nil, fmt.Errorf("--configPath %s is not a directory", configPath)
		}
		newViper.AddConfigPath(configPath)
	} else {
		newViper.AddConfigPath(execPath)
		newViper.AddConfigPath(projectRoot)
	}

	err := newViper.MergeInConfig()
	if err != nil && configName != configNameDefault {
		return nil, fmt.Errorf("invalid configName specified: %w", err)
	}

	// Make relative paths from config.* relative to the config file
	relativeToConfig(SpdxPathFlag, flags, newViper)
	relativeToConfig(CustomPathFlag, flags, newViper)

	// TODO: env from a file is W-I-P.
	// Doc and test or just use config.env with above code and remove this.
	envFrom := newViper.GetString("envFrom")
	if envFrom != "" {
		newViper.SetConfigFile(envFrom)
		if err := newViper.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("envFrom file err: %w", err)
		}
	}
	return newViper, nil
}

// If we didn't get a flag, then relative config file resources need to be relative to the config file
// Make all relative paths relative to the config file used.
func relativeToConfig(flag string, flags *pflag.FlagSet, newViper *viper.Viper) {
	// Ignore if flags are overriding. This is only for config file settings.
	var p string
	if flags != nil {
		p, _ = flags.GetString(flag)
	}
	if flags == nil || p == "" {
		configFileUsed := newViper.ConfigFileUsed()
		if configFileUsed != "" {
			configDir := filepath.Dir(configFileUsed)
			p := newViper.GetString(flag)
			if p != "" && !path.IsAbs(p) {
				newViper.Set(flag, path.Join(configDir, p)) // override
			}
		}
	}
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
	flagSet.Bool(ListFlag, false, "List the license templates to be used")
	flagSet.String(AddAllFlag, "", "Add licenses")
	flagSet.Bool(UpdateAllFlag, false, "Update existing licenses")
	flagSet.String(ConfigPathFlag, "", "Path to any config files")
	flagSet.String(ConfigNameFlag, "config", "Base name for config file")
	flagSet.String(SpdxFlag, DefaultResource, "Set of embedded SPDX templates to use")
	flagSet.String(SpdxPathFlag, "", "Path to external SPDX templates to use")
	flagSet.String(CustomFlag, DefaultResource, "Custom templates to use")
	flagSet.String(CustomPathFlag, "", "Path to external custom templates to use")
}
