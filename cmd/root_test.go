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

func Test_CLI_addAll_Bogus(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--addAll", "../testdata/addAll/bogus/no-dir-here"})
	if err := cmd.Execute(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Expected ErrNotExist got: %v", err)
	}
}

func Test_CLI_no_json_licenses(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--addAll", "../testdata/addAll/input/no_json_licenses"})
	if err := cmd.Execute(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Expected ErrNotExist got: %v", err)
	}
}

func Test_CLI_addAll(t *testing.T) {
	t.Parallel()

	addAll := "../testdata/addAll"
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
		"--addAll", "testdata/addAll/input",
		"--configPath", "../testdata/addAll",
		"--spdx", "3.17",
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

func Test_CLI__configPath_not_found(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll/bogus",
	})
	if err := cmd.Execute(); !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		t.Fatalf("Expected ConfigFileNotFoundError got: %v", err)
	}
}

func Test_CLI_configName_not_found(t *testing.T) {
	t.Parallel()
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--configPath", "../testdata/addAll/config",
		"--configName", "bogus",
	})
	if err := cmd.Execute(); !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		t.Fatalf("Expected ConfigFileNotFoundError got: %v", err)
	}
}

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
