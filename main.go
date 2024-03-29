// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/CycloneDX/sbom-utility/log"

	"github.com/CycloneDX/license-scanner/cmd"
)

var (
	Logger          *log.MiniLogger
	DefaultLogLevel = log.DEFAULT_LEVEL
)

func init() {
	Logger = log.NewLogger(DefaultLogLevel)
	Logger.InitLogLevelAndModeFromFlags()
	Logger.Tracef(" Logger (%T) created: with Level=`%v`", Logger, Logger.GetLevelName())
	Logger.Enter()
	defer Logger.Exit()

	// Set things in packages
	cmd.ProjectLogger = Logger

	Logger.Debug(" * Testing Logger.Debug() from main init()")
}

func main() {
	Logger.Enter()
	defer Logger.Exit()
	cmd.Execute()
}
