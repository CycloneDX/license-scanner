# SPDX Templates

The SPDX templates and test data are imported directly from SPDX releases packaged as ZIP files which are published here:
  - https://github.com/spdx/license-list-data/releases

Once unpacked, the following files are imported; including:
- template files (i.e., all `*.txt` files under the `templates` directory)
- license information (i.e., `licenses.json` and `exceptions.json` under the `json` directory)
- test data for validation (i.e., text files under the `text` directory)

In addition, *precheck* files are generated during import. These files contain static strings extracted from the templates.

- "prechecks" provides significant performance improvement vs. simple template/regex matching. However, using "prechecks" does require that the *precheck* files are re-generated anytime template static text is updated.

## Known issues importing SPDX License List Release 3.26

The current default SPDX templates and corresponding test data include all those published under the 3.26 SPDX release using the license-scanner's `import` command.  However, several manual edits were required to pass validation testing as listed in the tables below.

#### Template edits

This table lists the edits made to template files found under the | [resources/spdx/default/template/](default/template/) directory which allow them to pass corresponding validation testcases.  Each entry lists the template file name, the SPDX release where the edit/workaround was introduced as well as the description of the issue and fix.

| Template file | SPDX Release | Problem | Fix |
| --- | --- | --- | --- |
| [Adobe-Display-PostScript.template.txt](default/template/Adobe-Display-PostScript.template.txt) | 3.26 | Template has an erroneous space in the hyphenated word:  `NON- INFRINGEMENT`. | Removed the extra space and the hyphen resulting in: `NONINFRINGEMENT`. |
| [Beerware.template.txt](default/template/Beerware.template.txt) | 3.21 | Template uses logical OR expression to match either of two email addresses which is not supported by current regex. | Reverted template to the version from SPDX release 3.18 without OR logic which defaults to HTML replacement which will match any `<email@example.com>` tag-like address. |
| [Mackerras-3-Clause-acknowledgment.template.txt](default/template/Mackerras-3-Clause-acknowledgment.template.txt) | 3.26 | Template used this logical expression to match either of two email addresses: `match="<paulus@ozlabs.org>\|<paulus@samba.org>"` | Changed the template to match any email address found at that location (from zero to 20 chars. in length): `match=".{0,20}` |
| [MPEG-SSG.template.txt](default/template/MPEG-SSG.template.txt) | 3.26 | Template had an erroneous asterisk character between words: `are * general` | Removed the asterisk and extra space. |
| [Ubuntu-font-1.0.template.txt](default/template/Ubuntu-font-1.0.template.txt) | 3.26 | &bull; Bullet item 1. contained an extra space in a hyphenated word: `human- readable`.  | Removed the extra space. |
| [Xdebug-1.03.template.txt](default/template/Xdebug-1.03.template.txt) | 3.21 | Horizontal separators are expected to start on a new line. |  Added a carriage return before the horizontal separator (line of dashes) to the template. |

#### Test data edits

This table lists the edits made to text-format, test data files found under the [resources/spdx/default/template/](default/testdata/) directory which allow them to pass corresponding template validation testcases.

| Test file | SPDX Release | Problem | Fix |
| --- | --- | --- | --- |
| [CC-BY-NC-SA-2.0-DE.txt](CC-BY-NC-SA-2.0-DE.txt) | 3.21 | The SPDX test file appears to have a missing space character which is inconsistent with the corresponding template as well as test files provided by SPDX in other formats (e.g., html, rdf etc.). |  Added a missing space after the `“` character in `„Schutzgegenstand“wird`. |
| [CC-PDM-1.0.txt](default/testdata/CC-PDM-1.0.txt) | 3.26 | Extra space in text test file. | Removed an erroneous space character between the word `jurisdiction` and an ending period (i.e., `jurisdictions .`). |
| [Ubuntu-font-1.0.txt](default/testdata/Ubuntu-font-1.0.txt) | 3.26 | The following hyphenated word occurred at a LF boundary: `machine-\nreadable`. | Removed the LF character in the hyphenated word. |

**Note**: Many of the edits listed above were found while importing SPDX release 3.26 into `license-scanner` as new default templates and testcases; however, these templates or testcases may have been introduced in SPDX releases 3.22-3.25 which were not imported into any license-scanner releases.

## License test data usage

The `spdx/testdata` directory contains sample license files in text format which are used for validation testing during `import` against SPDX templates and will be ignored by the `go build` command.
