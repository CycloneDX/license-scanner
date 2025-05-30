// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/CycloneDX/sbom-utility/log"

	"github.com/CycloneDX/license-scanner/cmd"
	"github.com/CycloneDX/license-scanner/identifier"
	"github.com/CycloneDX/license-scanner/importer"
	"github.com/CycloneDX/license-scanner/licenses"
	"github.com/CycloneDX/license-scanner/normalizer"
)

var (
	Logger          *log.MiniLogger
	DefaultLogLevel = log.DEFAULT_LEVEL
)

func init() {
	// Create logger at the earliest
	// NOTE: This logger will not apply to `go test` as package "main" will not be loaded
	Logger = log.NewLogger(DefaultLogLevel)
	// Check for log-related flags (anywhere) and apply to logger
	// as early as possible (before customary Cobra flag formalization)
	// NOTE: the last log-level flag found, in order of appearance "wins"
	// Set default log level and turn "quiet mode" off
	Logger.InitLogLevelAndModeFromFlags()
	// Emit log level used from this point forward
	Logger.Tracef(" Logger (%T) created: with Level=`%v`", Logger, Logger.GetLevelName())
	// Provide access to project logger to other modules
	cmd.Logger = Logger
	identifier.Logger = Logger
	importer.Logger = Logger
	normalizer.Logger = Logger
	licenses.Logger = Logger
}

func main() {
	cmd.Execute()
}
