[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

# license-scanner

_license-scanner_ scans files for licenses and legal terms. It can be used to identify text matching licenses and license exceptions from the [SPDX License List](https://spdx.org/licenses/). _license_scanner_ can also be configured to identify additional legal terms, keywords, aliases, and non-SPDX licenses.

As a library, written in Go, _license-scanner_ is designed to be integrated into your software supply chain pipelines. In addition, _license-scanner_ may be used as a command-line utility.

## Getting started

The license scanner is available as a CLI and as a go module. Importing the scanner as go module is a recommended way to
integrate it in your own tools.

### Compatability

* Building from source requires Go 1.18 or newer
* CycloneDX output is based on v1.4
* SPDX template matching has been tested with SPDX license template versions 3.17 and 3.18

### Installing as a CLI

Install the `license-scanner` CLI executable in your go environment by building from source with `go install`:

```bash
go install github.com/IBM/license-scanner@latest
```

### Installing for developers

For developers, `git clone` the repo and build the source code with `go build`:

Clone the repo:

```bash
git clone https://github.com/IBM/license-scanner.git
```

The commands that follow are to be run from your cloned repo root directory:

```bash
cd license-scanner
```

Build the source code:

```bash
go build ./...
```

Run the CLI from source code in your cloned repo (with local changes):

```bash
go run . --help
```

Optionally, install a _license-scanner_ executable from your cloned repo (with local changes) :

```bash
go install
```

> NOTE: For documentation purposes, the CLI examples assume the use of the _license-scanner_ executable, but typically developers will instead use `go run .` (or `go run ./main.go`) in place of `license-scanner`.

### Installing as a Module

Using the `license-scanner` API is simple. First, use `go get` to install the latest version of the library.

```bash
go get -u github.com/IBM/license-scanner@latest
```

Next, import the scanner API into your application:

```bash
import "github.com/IBM/license-scanner/api/scanner"
```

## CLI usage

To get more information about command-line usage directly from your executable, run `license-scanner --help`. When you run with the `--debug` flag, the latest usage in markdown format will also be updated in [cmd/license-scanner.md](cmd/license-scanner.md)

```bash
Usage:
  license-scanner [flags]


Flags:
  -g, --acceptable          Flag acceptable
      --addAll string       Add the licenses from SPDX unzipped release
      --configName string   Base name for config file (default "config")
      --configPath string   Path to any config files
  -c, --copyrights          Flag copyrights
      --custom string       Custom templates to use (default "default")
  -d, --debug               Enable debug logging
      --dir string          A directory in which to identify licenses
  -f, --file string         A file in which to identify licenses
  -x, --hash                Output file hash
  -h, --help                help for license-scanner
  -k, --keywords            Flag keywords
  -l, --license string      Display match debugging for the given license
      --list                List the license templates to be used
  -n, --normalized          Flag normalized
  -q, --quiet               Set logging to quiet
      --spdx string         SPDX templates to use (default "default")
```

### Example CLI usage

Example usage to scan LICENSE.txt, but only print the license IDs and positions of license matches:

```bash
license-scanner --quiet -f LICENSE.txt
```

Example usage to print license IDs, copyrights, and blocks found in file LICENSE.txt:

```bash
license-scanner -c -f LICENSE.txt
```

Example scan of a license file with output shown:

```bash
$ curl -o ASYNC_LICENSE https://raw.githubusercontent.com/caolan/async/master/LICENSE
```

```bash
$ license-scanner -f ASYNC_LICENSE
[INFO] Looking for all licences

FOUND LICENSE MATCHES:
        License ID:     MIT
                begins:     0   ends:  1061
                begins:    40   ends:   600
                begins:   602   ends:  1061

[INFO] [MIT] :: Copyright (c) 2010-2018 Caolan McMahon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Library usage

### Example library usage

Initialize the `ScanSpecs` with `LicenseText` to scan the license text against the set of SPDX licenses and get the
CycloneDX [LicenseChoice](https://cyclonedx.org/use-cases/#license-compliance). The CycloneDX LicenseChoice includes
SPDX License ID, SPDX License Expression, and License name.

```go
scanSpecs := scanner.ScanSpecs{
	Specs: []scanner.ScanSpec{
		{
			Name:        "async",
			LicenseText: asyncLicenseText,
		},
		{
			Name:        "helmet",
			LicenseText: helmetLicenseText,
		},
	},
}
```

Call the `ScanLicenseText`:

```go
results, err := scanSpecs.ScanLicenseText()
if err != nil {
	// report error and return
	return err
}
```

The `ScanLicenseText` returns `ScanResult` which contains the original specifications along with original license text,
normalized license text, the digest (Md5, Sha256, and Sha512) of the normalized text, and CycloneDX LicenseChoice schema.

For example:

```go
package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/IBM/license-scanner/api/scanner"
)

func GetLicense(urls map[string]string) {
	for n, u := range urls {
		// Create a blank file
		file, err := os.Create(n)
		defer file.Close()
		if err != nil {
			log.Fatal(err)
		}

		// initiate HTTP client with the specified URL
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}

		// Copy content in a file
		resp, err := client.Get(u)
		defer resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.Copy(file, resp.Body)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	sampleLicenses := map[string]string{
		"async":     "https://raw.githubusercontent.com/caolan/async/master/LICENSE",
		"urllib3":   "https://raw.githubusercontent.com/urllib3/urllib3/main/LICENSE.txt",
		"cobra":     "https://raw.githubusercontent.com/spf13/cobra/main/LICENSE.txt",
		"golang-go": "https://raw.githubusercontent.com/golang/go/master/LICENSE",
	}

	GetLicense(sampleLicenses)

	var scanSpecs scanner.ScanSpecs

	for n, u := range sampleLicenses {
		text, _ := ioutil.ReadFile(n)
		scanSpecs.Specs = append(scanSpecs.Specs, scanner.ScanSpec{
			Name:        n,
			Location:    u,
			LicenseText: string(text),
		})
	}

	results, _ := scanSpecs.ScanLicenseText()
	for _, result := range results {
		fmt.Printf("License IDs for %s: ", result.Spec.Name)
		for _, r := range result.CycloneDXLicenses {
			fmt.Printf("%s\n", r.License.ID)
		}
	}
}
```

```bash
License IDs for async: MIT
License IDs for urllib3: MIT
License IDs for cobra: Apache-2.0
License IDs for golang-go: BSD-3-Clause
```

### Scan Results

The `license-scanner` returns a list of identified licenses in CycloneDX `LicenseChoice` schema which holds a `License`
or an `Expression`. The main goal of a `license-scanner` is to return a list of SPDX License IDs in the `License` struct:

```go
type License struct {
	ID   string
	Name string
	Text *AttachedText
	URL  string
}
```

The `ID` here represents the SPDX ID in case of a license is identified against a known SPDX licenses. In case of a no match,
`ID` is left empty string but `Name` is set to `NOASSERTION` to signify that this particular license text was compared
against the known licenses but did not match any.

Here is an example of a [go-yaml](https://github.com/go-yaml/yaml) package with `Apache-2.0` and `MIT` licenses:

```go
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "text": {
              "contentType": "text/plain",
              "encoding": "base64",
              "content": "..."
            },
            "url": "https://www.apache.org/licenses/LICENSE-2.0.txt"
          }
        },
        {
          "license": {
            "id": "MIT",
            "text": {
              "contentType": "text/plain",
              "encoding": "base64",
              "content": "..."
            },
            "url": "https://opensource.org/licenses/mit-license.php"
          }
        }
      ]
```

### Setting flags with the API

Optional flags maybe used with the API to locate the config file and control runtime options. These are the same flags that are used in [CLI Usage](#cli-usage), but instead of using command-line flags, they are set and passed using the API as shown below.

```go
package main

import (
	"github.com/IBM/license-scanner/api/scanner"
	"github.com/IBM/license-scanner/configurer"
)

func main() {
	// To override default flags, start with a new default flag set.
	flagSet := configurer.NewDefaultFlags()
	// Override flags where necessary using Set(flag, value)
	flagSet.Set("spdx", "my3.17")
	// Setup your scanner.ScanSpecs as shown earlier.
	scanSpecs := scanner.ScanSpecs{ /* ...see earlier example... */ }
	// Use WithFlags() to set the non-default flags for a scan
	result, err := scanSpecs.WithFlags(flagSet).ScanLicenseText()
}
```

## Optional Configuration

Refer to [configurer/README.md](configurer/README.md) for advanced configuration options.

## CLI modes

### Help mode

When you add `--help` or `-h` to any _license_scanner_ command it will produce help output and no other action will be performed.

| Name   | Shorthand | Type    | Default | Usage                                                    |
|--------|-----------|---------| -------------|----------------------------------------------------------|
| --help | -h        | Boolean | false        | Print usage help |

In help mode, all other flags are ignored.

### Scan mode

When running `license_scanner --file <input_file>` the input file is scanned for license matches.
When running `license_scanner --dir <input_dir>` the input directory is recursively scanned for license matches.

| Name   | Shorthand | Type   | Usage                                     |
|--------|-----------|--------|-------------------------------------------|
| --file | -f        | string | A file in which to identify licenses      |
| --dir  |           | string | A directory in which to identify licenses |

The following **optional** runtime flags may be used to modify and enhance the behavior:

* Resource flags: **--spdx, --custom**
* Output logging flags: **--quiet, --debug**
* Config file location flags: **--configPath, --configName**
* Output enhancer flags: **--acceptable, --copyrights, --hash, --keywords, --normalized, --license**

### Import mode

When running `license_scanner --addAll <input_dir>` the input directory is used to validate, prepare, and import SPDX licenses.

| Name    | Type   | Usage                                       |
|---------|-----------|---------------------------------------------|
| -addAll | string | Add the licenses from SPDX unzipped release |

The following runtime flags may be used to modify the behavior:

* Resource flags (import destination): **--spdx**
* Config file location (used to locate resources): **--configPath, --configName**

### List mode

When running `license_scanner --list` a listing of the SPDX and custom license templates will be output.

| Name   | Usage                                 |
|--------|---------------------------------------|
| --list | List the license templates to be used |

Since you may have multiple locations for resources and multiple SPDX and custom folders under each of those resources, use the following flags to generate non-default listings:

* Resource flags: **--spdx, --custom**
* Config file location (used to locate resources): **--configPath, --configName**

Example license library listing: [resources/LIST.md](resources/LIST.md)

## Runtime flags

### Resource flags

_license-scanner_ uses configurable resources to identify licenses and legal terms. By default, SPDX licenses and license exceptions are configured under `resources/spdx/default`. This directory is provided in the repo for out-of-the-box functionality.

In addition, default examples used to recognize additional legal terms and extend SPDX license matching are provided under `resources/custom/default`.

Resource flags can be used in scan mode to run scans with alternative resources. The --spdx flag is also in import mode as described in [Importing SPDX license templates](#importing-spdx-license-templates).

| Name     | Default    | Usage                |
|----------|------------|----------------------|
| --spdx   | default  | Suppress all logging |
| --custom | default  | Enable debug logging |

### Output logging flags

Logging flags control the amount of output. --quiet takes priority over --debug and other enhancer flags that rely on printed output.

| Name    | Shorthand | Default | Usage                |
|---------|-----------|---------|----------------------|
| --quiet | -q        | false   | Suppress all logging |
| --debug | -d        | false   | Enable debug logging |

### Output enhancer flags

Output enhancers create additional output details for a license scan. The enhanced output uses logging, so these should not be used with the --quiet flag. All enhancer flags are Boolean except for --license. --license requires a string identifying the license template to use for the diff.

| Name         | Shorthand | Default | Usage                                       |
|--------------|-----------|---------|---------------------------------------------|
| --acceptable | -g        | false   | Flag acceptable pattern matches             |
| --copyrights | -c        | false   | Flag copyrights                             |
| --hash       | -x        | false   | Output the normalized license file hashcode |
| --keywords   | -k        | false   | Flag keywords                               |
| --normalized | -n        | false   | Output the normalized license text          |
| --license    | -l        | | Output normalized diff of input and license |


### Config file location flags

When a _license-scanner_ command is executed or a ScanLicenseText() call is made via the API, _license-scanner_ will look for a config file to initialize runtime options.

By default, _license-scanner_ will look for the config file in:

1. The directory containing the executable
2. The project root (for development and tests)

You can use the `--configPath <path>` flag to read your the config file from an alternate location. You can also override the "config" part of the file name by setting the `--configName <base>`.

For example, `--configPath /tmp/test_dir --configName configTest` would allow you to test using `/tmp/test_dir/configTest.json`.

The default config file is named `config.<ext>` (e.g. `config.json`). Viper provides the ability to read config files in a variety of formats, such as TOML or YAML instead of JSON. Use the file extension to indicate the format and refer to Viper for supported languages. **For _license-scanner_, JSON is presumed for testing and documentation.**


| Name         | Shorthand | Default                          | Usage                     |
|--------------|-----------|----------------------------------|---------------------------|
| --configName |           | config                           | Base name for config file |
| --configPath |           | executable's dir or project root | Path to any config files |

Refer to [configurer/README.md](configurer/README.md) for advanced configuration options.

## Running the tests

### Unit Tests

Each package has many `unit` tests in `*_test.go` which can be executed using `go test`:

```bash
 go test ./... -tags=unit
?       github.com/IBM/license-scanner    [no test files]
ok      github.com/IBM/license-scanner/api/scanner        3.009s
ok      github.com/IBM/license-scanner/cmd        8.646s
?       github.com/IBM/license-scanner/debugger   [no test files]
ok      github.com/IBM/license-scanner/identifier 20.923s
ok      github.com/IBM/license-scanner/licenses   7.151s
?       github.com/IBM/license-scanner/logging    [no test files]
ok      github.com/IBM/license-scanner/normalizer 0.161s
ok      github.com/IBM/license-scanner/resources  0.278s
```

## Importing SPDX license templates

**_license-scanner_ includes a default current release of SPDX license templates already imported**. You would only use this import process if you want to download and work with an alternate version (e.g. newer or older than the one that is currently included).

_license-scanner_ will copy, preprocess, and validate files from an SPDX license list release. These files include templates, metadata, and license text.

Imported SPDX templates will be automatically copied into your *resources* directory using the following directory naming convention:

* **`resources/spdx/<versionDir>`**
    * where `<versionDir>` is set by the `--spdx <versionDir>` command-line flag

#### Steps

1. Download the SPDX license list assets (zip file or tar.gz) from https://github.com/spdx/license-list-data/releases
1. Unzip the file. This will create the `<dir>` that you will import from (below).
1. Ensure that the destination directory named `resources/spdx/<versionDir>` is not in use.
1. Run the `license-scanner --addAll <dir> --spdx <versionDir>` command. For example:
   ```bash
   license-scanner --addAll ~/Downloads/license-list-data-3.17 --spdx my3.17
   ```
1. The new templates, json, testdata, and generated precheck files will all be put in the `resources/spdx/my3.17` directory.

