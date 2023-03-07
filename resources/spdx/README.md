# SPDX Templates

The SPDX templates are imported directly from an SPDX release.
This includes template files, license information (licenses.json and exceptions.json),
and example text which will be used as testdata to validate the templates.

In addition, *precheck* files are generated during import. These files contain static
strings extracted from the templates. This provides significant performance improvement
vs. simple template/regex matching, but using prechecks does require that the precheck
file are updated anytime template static text is updated.

## Default (SPDX License List Release 3.20)

The current default SPDX templates include all the 3.20 SPDX release with the following differences:

1. All licenses and exceptions marked deprecated were skipped. In prior versions, license-scanner attempted to use deprecated templates, but in 3.20 the deprecated templates conflict with the not-deprecated templates. Good riddance.

1. We are using the Beerware template from 3.18. The new 3.20 template matches either of two email addresses, but since license-scanner replaces HTML tags, the new template fails to match while the old template will math any `<email@example.com>` tag-like address.

1. The CC-BY-NC-SA-2.0-DE.txt file was modified to add a missing space after the `“` character in `„Schutzgegenstand“wird`. The text file is used for template validation on import, but for license-scanner this one appears to be inconsistent with the template and spec.

## Testdata

The `spdx/testdata` directory is used for testing. It will be ignored by go build.
