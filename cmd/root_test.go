// SPDX-License-Identifier: Apache-2.0

//go:build unit

package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func Test_CLI_version(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	bOut := bytes.NewBufferString("")
	cmd.SetOut(bOut)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Error(err)
	}
	got, err := ioutil.ReadAll(bOut)
	if err != nil {
		t.Error(err)
	}
	expected := "license-scanner version 0.0.0"
	if !bytes.Contains(got, []byte(expected)) {
		t.Errorf("expected output containing %s got %s", expected, got)
	}
}

func Test_CLI_help(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	bOut := bytes.NewBufferString("")
	cmd.SetOut(bOut)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Error(err)
	}
	got, err := ioutil.ReadAll(bOut)
	if err != nil {
		t.Error(err)
	}
	expected := "license-scanner [flags]"
	if !bytes.Contains(got, []byte(expected)) {
		t.Errorf("expected output containing %s got %s", expected, got)
	}
}

func Test_CLI_file_not_found(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"-f", "FILE.TXT"})
	if err := cmd.Execute(); err == nil {
		t.Log("Got error: ", err)
		t.Error("did not get expected error")
	}
}

func Test_CLI_file(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"-f", "../testdata/addAll/input/text/0BSD.txt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
}

// Test_CLI_addAll_Bogus verifies that --addAll <dir-does-not-exist> returns a ErrNotExist error
func Test_CLI_addAll_Bogus(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--addAll", "../testdata/addAll/bogus/no-dir-here", "--spdx", "testing"})
	if err := cmd.Execute(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Expected ErrNotExist got: %v", err)
	}
}

// Test_CLI_no_spdx_json_licenses tests --addAll missing the required SPDX json files
func Test_CLI_no_spdx_json_licenses(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--addAll", "../testdata/addAll/input/no_json_licenses", "--spdx", "testing"})
	if err := cmd.Execute(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Expected ErrNotExist got: %v", err)
	}
}

// Test_CLI_addAll_SPDX tests --addAll input with --spdxPath output
func Test_CLI_addAll_SPDX(t *testing.T) {
	// probably should use t.Parallel() while this is actually writing, verifying, and deleting files

	addAll := "../testdata/addAll"
	input := path.Join(addAll, "input")
	output := path.Join(addAll, "output")
	versionedDir := path.Join(output, "spdx/3.17")
	newTemplate := path.Join(versionedDir, "template", "0BSD.template.txt")
	newTestData := path.Join(versionedDir, "testdata", "0BSD.txt")
	newPreCheck := path.Join(versionedDir, "precheck", "0BSD.json")

	for _, newFile := range []string{newTemplate, newTestData, newPreCheck} {
		if _, err := os.Stat(newFile); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("File should not exist before test creates it: %v", newFile)
		}
	}

	if err := os.Mkdir(output, 0o777); err != nil {
		t.Fatalf("error creating output dir: %v", err)
	}

	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("error removing output dir: %v", err)
		}
	}(output)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--addAll", input,
		"--spdxPath", versionedDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	for _, newFile := range []string{newTemplate, newTestData, newPreCheck} {
		if _, err := os.Stat(newFile); err != nil {
			t.Fatalf("File should exist after test creates it: %v", newFile)
		}
	}
}

// Test_CLI_configPath_not_found verifies that setting --configPath to a dir that does not exist will return ErrNotExist
func Test_CLI_configPath_not_found(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll/bogus", "-f", "../testdata/addAll/input/text/0BSD.txt",
	})
	if err := cmd.Execute(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Expected ErrNotExist for bogus configPath got: %v", err)
	}
}

// Test_CLI_configPath_not_dir verifies that setting --configPath to a file instead of a dir will return an error
func Test_CLI_configPath_not_dir(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll/input/text/0BSD.txt", "-f", "../testdata/addAll/input/text/0BSD.txt",
	})
	if err := cmd.Execute(); !strings.Contains(err.Error(), "is not a dir") {
		t.Fatalf("Expected '...is not a dir...' got: %v", err)
	}
}

// Test_CLI_default_configName_not_found_is_ok verifies that it is NOT ok to have a missing config file when a non-default --configName is provided
func Test_CLI_configName_not_found(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/config",
		"--configName", "bogus",
		"-f", "../testdata/addAll/input/text/0BSD.txt",
	})
	if err := cmd.Execute(); !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		t.Fatalf("Expected ConfigFileNotFoundError got: %v", err)
	}
}

// Test_CLI_default_configName_not_found_is_ok verifies that it is ok to NOT have a config.* file with configPath set
func Test_CLI_default_configName_not_found_is_ok(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll/input",
		"--configName", "config",
		"-f", "../testdata/addAll/input/text/0BSD.txt",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("missing default config file is okay but got: %v", err)
	}
}

// Test_CLI_configPathAndName_help tests happy path for valid --configPath and --configName
func Test_CLI_configPathAndName_help(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll",
		"--configName", "config",
		"--help",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Expected nil err for valid config path and name and --help got: %v", err)
	}
}

func Test_CLI_list(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--list",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Expected nil err for valid config path and name and --help got: %v", err)
	}
}

func Test_CLI_list_spdx(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--spdx", "default",
		"--list",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Expected nil err for valid --spdx dir and --list got: %v", err)
	}
}
