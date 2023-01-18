# License

## MIT

MIT license text as an input to the scanning service:

```text


Permission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>> <<match=.*>> <<beginOptional>>software <<match=and/?o?r?>> associated documentation<<endOptional>> <<beginOptional>>SOFTWARE<<endOptional>> <<beginOptional>><<match=files?>> (the <<match="?Software"?|"?Materials"?>>),<<endOptional>> to deal in the <<match=Software|Code|Materials>> without restriction, including without <<match=limitation,?>> <<beginOptional>>on<<endOptional>> the <<beginOptional>>irrevocable, perpetual, worldwide, and royalty-free<<endOptional>> rights to use, copy, modify, merge, publish, distribute, <<beginOptional>>sublicense,<<endOptional>> <<beginOptional>>distribute with modifications,<<endOptional>> <<beginOptional>><<match=sub ?license,?>><<endOptional>> <<beginOptional>>display, perform, create derivative works from<<endOptional>> <<match=and ?/ ?or>> sell copies of the <<match=Software|code|Materials>>, <<beginOptional>> both in source<<endOptional>> and <<beginOptional>>object code form, and<<endOptional>> to permit persons to whom the <<match=Software|code|materials>> <<match=is|are>> furnished to do so, subject to the following <<match=conditions|disclaimer>>:

<<beginOptional>>
The above copyright notice<<match= and|,>> this permission notice <<beginOptional>>and the disclaimer statement<<endOptional>> <<beginOptional>>(including the next
paragraph)<<endOptional>> <<match=shall|must>> be included in all copies or substantial portions of the <<match=Software|code|materials>>.
<<endOptional>>
```

Normalized license text after running through the normalization guidelines:

```text
permission is hereby granted, free of charge, to any person obtaining a copy of <<this|the>> <<.{0,144}>> <<omitable>>software <<and/?o?r?>> associated documentation<</omitable>> <<omitable>>software<</omitable>> <<omitable>><<files?>> (the <<'?software'?|'?materials'?>>),<</omitable>> to deal in the <<software|code|materials>> without restriction, including without <<limitation,?>> <<omitable>>on<</omitable>> the <<omitable>>irrevocable, perpetual, worldwide, and royalty-free<</omitable>> rights to use, copy, modify, merge, publish, distribute, <<omitable>>sublicense,<</omitable>> <<omitable>>distribute with modifications,<</omitable>> <<omitable>><<sub ?license,?>><</omitable>> <<omitable>>display, perform, create derivative works from<</omitable>> <<and ?/ ?or>> sell copies of the <<software|code|materials>>, <<omitable>> both in source<</omitable>> and <<omitable>>object code form, and<</omitable>> to permit persons to whom the <<software|code|materials>> <<is|are>> furnished to do so, subject to the following <<conditions|disclaimer>>: <<omitable>> the above copyright notice<< and|,>> this permission notice <<omitable>>and the disclaimer statement<</omitable>> <<omitable>>(including the next paragraph)<</omitable>> <<shall|must>> be included in all copies or substantial portions of the <<software|code|materials>>. <</omitable>>
```

License with the metadata:

```
{
  id: 'MIT',
  name: 'MIT License',
  spdx_standard: true,
  osi_approved: true,
  primary_patterns: [
    {
      text: '\n' +
        '\n' +
        '\n' +
        'Permission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>> <<match=.*>> <<beginOptional>>software <<match=and/?o?r?>> associated documentation<<endOptional>> <<beginOptional>>SOFTWARE<<endOptional>> <<beginOptional>><<match=files?>> (the <<match="?Software"?|"?Materials"?>>),<<endOptional>> to deal in the <<match=Software|Code|Materials>> without restriction, including without <<match=limitation,?>> <<beginOptional>>on<<endOptional>> the <<beginOptional>>irrevocable, perpetual, worldwide, and royalty-free<<endOptional>> rights to use, copy, modify, merge, publish, distribute, <<beginOptional>>sublicense,<<endOptional>> <<beginOptional>>distribute with modifications,<<endOptional>> <<beginOptional>><<match=sub ?license,?>><<endOptional>> <<beginOptional>>display, perform, create derivative works from<<endOptional>> <<match=and ?/ ?or>> sell copies of the <<match=Software|code|Materials>>, <<beginOptional>> both in source<<endOptional>> and <<beginOptional>>object code form, and<<endOptional>> to permit persons to whom the <<match=Software|code|materials>> <<match=is|are>> furnished to do so, subject to the following <<match=conditions|disclaimer>>:\n' +
        '\n' +
        '<<beginOptional>>\n' +
        'The above copyright notice<<match= and|,>> this permission notice <<beginOptional>>and the disclaimer statement<<endOptional>> <<beginOptional>>(including the next\n' +
        'paragraph)<<endOptional>> <<match=shall|must>> be included in all copies or substantial portions of the <<match=Software|code|materials>>.\n' +
        '<<endOptional>>\n',
      regex: /permission is hereby granted, free of charge, to any person obtaining a copy of ?(?:(this|the) ?) ?(?:(.{0,144}) ?) ?(?:software ?(?:(and\/?o?r?) ?)associated documentation ?)? ?(?:software ?)? ?(?: ?(?:(files?) ?)\(the ?(?:('?software'?|'?materials'?) ?)\), ?)?to deal in the ?(?:(software|code|materials) ?)without restriction, including without ?(?:(limitation,?) ?) ?(?:on ?)?the ?(?:irrevocable, perpetual, worldwide, and royalty-free ?)?rights to use, copy, modify, merge, publish, distribute, ?(?:sublicense, ?)? ?(?:distribute with modifications, ?)? ?(?: ?(?:(sub ?license,?) ?) ?)? ?(?:display, perform, create derivative works from ?)? ?(?:(and ?\/ ?or) ?)sell copies of the ?(?:(software|code|materials) ?), ?(?:both in source ?)?and ?(?:object code form, and ?)?to permit persons to whom the ?(?:(software|code|materials) ?) ?(?:(is|are) ?)furnished to do so, subject to the following ?(?:(conditions|disclaimer) ?): ?(?:the above copyright notice ?(?:( and|,) ?)this permission notice ?(?:and the disclaimer statement ?)? ?(?:\(including the next paragraph\) ?)? ?(?:(shall|must) ?)be included in all copies or substantial portions of the ?(?:(software|code|materials) ?)\. ?)?/,
      capture_groups: [Array],
      prechecks_required: [Array],
      filename: 'license_MIT.txt'
    },
    {
      text: '<<match=\\(?(?:the )?\\bMIT License\\b(?: license)?\\)?>>',
      regex: / ?(?:(\(?(?:the )?\bmit license\b(?: license)?\)?) ?)/,
      capture_groups: [Array],
      prechecks_required: [Array],
      filename: 'License Name'
    },
    {
      text: '<<match=(?:https?://)?(www\\.)?opensource\\.org/licenses/mit-license\\.php(?:\\/[a-z0-9._-]*)*\\/?>>',
      regex: / ?(?:((?:http?:\/\/)?(www\.)?opensource\.org\/licenses\/mit-license\.php(?:\/[a-z0-9._-]*)*\/?) ?)/,
      capture_groups: [Array],
      prechecks_required: false,
      filename: 'url'
    },
    {
      text: '<<match=(?:https?://)?(www\\.)?opensource\\.org/licenses/MIT(?:\\/[a-z0-9._-]*)*\\/?>>',
      regex: / ?(?:((?:http?:\/\/)?(www\.)?opensource\.org\/licenses\/mit(?:\/[a-z0-9._-]*)*\/?) ?)/,
      capture_groups: [Array],
      prechecks_required: false,
      filename: 'url'
    }
  ],
  primary_pattern_sources: [
    {
      source_text: '\n' +
        '\n' +
        '\n' +
        'Permission is hereby granted, free of charge, to any person obtaining a copy of <<match=this|the>> <<match=.*>> <<beginOptional>>software <<match=and/?o?r?>> associated documentation<<endOptional>> <<beginOptional>>SOFTWARE<<endOptional>> <<beginOptional>><<match=files?>> (the <<match="?Software"?|"?Materials"?>>),<<endOptional>> to deal in the <<match=Software|Code|Materials>> without restriction, including without <<match=limitation,?>> <<beginOptional>>on<<endOptional>> the <<beginOptional>>irrevocable, perpetual, worldwide, and royalty-free<<endOptional>> rights to use, copy, modify, merge, publish, distribute, <<beginOptional>>sublicense,<<endOptional>> <<beginOptional>>distribute with modifications,<<endOptional>> <<beginOptional>><<match=sub ?license,?>><<endOptional>> <<beginOptional>>display, perform, create derivative works from<<endOptional>> <<match=and ?/ ?or>> sell copies of the <<match=Software|code|Materials>>, <<beginOptional>> both in source<<endOptional>> and <<beginOptional>>object code form, and<<endOptional>> to permit persons to whom the <<match=Software|code|materials>> <<match=is|are>> furnished to do so, subject to the following <<match=conditions|disclaimer>>:\n' +
        '\n' +
        '<<beginOptional>>\n' +
        'The above copyright notice<<match= and|,>> this permission notice <<beginOptional>>and the disclaimer statement<<endOptional>> <<beginOptional>>(including the next\n' +
        'paragraph)<<endOptional>> <<match=shall|must>> be included in all copies or substantial portions of the <<match=Software|code|materials>>.\n' +
        '<<endOptional>>\n',
      filename: 'license_MIT.txt'
    },
    {
      source_text: '<<match=\\(?(?:the )?\\bMIT License\\b(?: license)?\\)?>>',
      filename: 'License Name'
    },
    {
      source_text: '<<match=(?:https?://)?(www\\.)?opensource\\.org/licenses/mit-license\\.php(?:\\/[a-z0-9._-]*)*\\/?>>',
      filename: 'url'
    },
    {
      source_text: '<<match=(?:https?://)?(www\\.)?opensource\\.org/licenses/MIT(?:\\/[a-z0-9._-]*)*\\/?>>',
      filename: 'url'
    }
  ],
  associated_patterns: [
    {
      text: '\n' +
        '\n' +
        '<<beginOptional>>The<<endOptional>> MIT <<match=License[: -]*>> <<beginOptional>>(MIT)<<endOptional>>\n',
      regex: / ?(?:the ?)?mit ?(?:(license[: -]*?) ?) ?(?:\(mit\) ?)?/,
      capture_groups: [Array],
      prechecks_required: [Array],
      filename: 'associated_full-title.txt'
    },
    {
      text: '\n' +
        '\n' +
        'THE <<match=SOFTWARE|CODE|MATERIALS>> <<match=IS|ARE>> PROVIDED <<match=["*]?AS IS["*]?,?>> WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE<<beginOptional>> AND <<match=NON-?INFRINGEMENT>><<endOptional>><<match=\\. ?>>IN NO EVENT SHALL <<match=.+>> BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, <<beginOptional>>ARISING FROM,<<endOptional>> OUT OF OR IN CONNECTION WITH THE <<match=SOFTWARE|CODE|MATERIALS>> OR THE USE OR OTHER DEALINGS IN THE <<match=SOFTWARE|CODE|MATERIALS>><<beginOptional>>.<<endOptional>>\n',
      regex: /the ?(?:(software|code|materials) ?) ?(?:(is|are) ?)provided ?(?:(['*]?as is['*]?,?) ?)without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose ?(?:and ?(?:(non-?infringement) ?) ?)? ?(?:(\. ?) ?)in no event shall ?(?:(.{1,144}) ?)be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, ?(?:arising from, ?)?out of or in connection with the ?(?:(software|code|materials) ?)or the use or other dealings in the ?(?:(software|code|materials) ?) ?(?:\. ?)?/,
      capture_groups: [Array],
      prechecks_required: false,
      filename: 'associated_liability_clause.txt'
    },
    {
      text: '\n\n<<match=(^|\\b)\\(?MIT\\)?>>\n',
      regex: / ?(?:((^|\b)\(?mit\)?) ?)/,
      capture_groups: [Array],
      prechecks_required: [Array],
      filename: 'associated_short-title.txt'
    }
  ],
  associated_pattern_sources: [
    {
      source_text: '\n' +
        '\n' +
        '<<beginOptional>>The<<endOptional>> MIT <<match=License[: -]*>> <<beginOptional>>(MIT)<<endOptional>>\n',
      filename: 'associated_full-title.txt'
    },
    {
      source_text: '\n' +
        '\n' +
        'THE <<match=SOFTWARE|CODE|MATERIALS>> <<match=IS|ARE>> PROVIDED <<match=["*]?AS IS["*]?,?>> WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE<<beginOptional>> AND <<match=NON-?INFRINGEMENT>><<endOptional>><<match=\\. ?>>IN NO EVENT SHALL <<match=.+>> BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, <<beginOptional>>ARISING FROM,<<endOptional>> OUT OF OR IN CONNECTION WITH THE <<match=SOFTWARE|CODE|MATERIALS>> OR THE USE OR OTHER DEALINGS IN THE <<match=SOFTWARE|CODE|MATERIALS>><<beginOptional>>.<<endOptional>>\n',
      filename: 'associated_liability_clause.txt'
    },
    {
      source_text: '\n\n<<match=(^|\\b)\\(?MIT\\)?>>\n',
      filename: 'associated_short-title.txt'
    }
  ]
}
```