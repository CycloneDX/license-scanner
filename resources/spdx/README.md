# SPDX Templates

The SPDX templates are imported directly from an SPDX release.
This includes template files, license information (licenses.json and exceptions.json),
and example text which will be used as testdata to validate the templates.

In addition, *precheck* files are generated during import. These files contain static
strings extracted from the templates. This provides significant performance improvement
vs. simple template/regex matching, but using prechecks does require that the precheck
file are updated anytime template static text is updated.

## Default (SPDX License List Release 3.18)

The current default SPDX templates include all the 3.18 SPDX release with the following differences:

* testdata Nokia-Qt-exception-1.1.txt was renamed to deprecated_Nokia-Qt-exception-1.1.txt to match the template name.

## Testdata

The `spdx/testdata` directory is used for testing. It will be ignored by go build.
