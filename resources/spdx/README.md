# SPDX Templates

The SPDX templates are imported directly from an SPDX release.
This includes template files, license information (licenses.json and exceptions.json),
and example text which will be used as testdata to validate the templates.

In addition, *precheck* files are generated during import. These files contain static
strings extracted from the templates. This provides significant performance improvement
vs. simple template/regex matching, but using prechecks does require that the precheck
file are updated anytime template static text is updated.

## Default (SPDX License List Release 3.21)

The current default SPDX templates include all the 3.21 SPDX release with the following differences:

1. We are using the Beerware template from 3.18. The 3.21 template matches either of two email addresses, but since license-scanner replaces HTML tags, the new template fails to match while the old template will match any `<email@example.com>` tag-like address.

2. The CC-BY-NC-SA-2.0-DE.txt file was modified to add a missing space after the `“` character in `„Schutzgegenstand“wird`. The text file is used for template validation on import, but for license-scanner this one appears to be inconsistent with the template and spec.

3. We added a carriage return before the horizontal separator (line of dashes) in the Xdebug-1.03 template. Separators are expected to start on a new line. This change allows the template to match the example text with license-scanner.

## Testdata

The `spdx/testdata` directory is used for testing. It will be ignored by go build.
