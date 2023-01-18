# LicenseDB

Using an external [licensedb/dataset.zip](https://github.com/go-enry/go-license-detector/tree/master/licensedb/dataset.zip) of ~1000 most starred repositories on GitHub as of early February 2018.

> NOTE: It is unclear what the correct results are with this dataset. A simple count of directories with detected licenses is used. I.e. **it is a directory count, not license count**. The dataset actually has 954 directories, but the project comparison is using **902** as the goal (without explaining the 52 expected misses).

For license-scanner, we tested the unzipped dataset as-is, and also re-tested after removing the many README.* files.

| Detector                                                                            | Detection rate | Time to scan, sec |
|:------------------------------------------------------------------------------------|:--------------:|:------------------|
| [license-scanner (with READMEs)](https://github.com/go-enry/go-license-detector)    | 86%  (776/902) | 24.0              |
| [license-scanner (without READMEs)](https://github.com/go-enry/go-license-detector) | 82%  (744/902) | 10.8              |


Comparison to other projects on that dataset: [here](https://github.com/go-enry/go-license-detector#quality)

<details><summary>How this was measured</summary>
<pre><code>
time license-scanner -q --dir ~/Downloads/dataset | grep "FOUND LICENSE MATCHES:" |  sed 's#/[^/]*$#/#'  | sort -u  | wc -l
time license-scanner -q --dir ~/Downloads/dataset_no_readmes | grep "FOUND LICENSE MATCHES:" |  sed 's#/[^/]*$#/#'  | sort -u  | wc -l
</code></pre>
</details>

*Tested on 2022/10/07 with commit c3dae8ef7ae904fe440c946996d8668a3994c544*
