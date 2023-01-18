

## Optional Configuration

_license-scanner_ is configured by default to use a set of SPDX license templates and another set of custom matching options. Additional configuration and runtime options may be used to customize _license-scanner_.

Configuration is handled using [Viper](https://github.com/spf13/viper) integrated with command-line flags using [Cobra](https://cobra.dev/). This provides a great deal of configuration flexibility along with a familiar behavior due to the popularity of Viper and Cobra in Go applications.

### The config file

When a _license-scanner_ command is executed or a ScanLicenseText() call is made via the API, _license-scanner_ will look for a config file to initialize runtime options.

#### --configName name

The default config file is named `config.<ext>` (e.g. `config.json`). Viper provides the ability to read config files in a variety of formats, such as TOML or YAML instead of JSON. Use the file extension to indicate the format and refer to Viper for supported languages. **For _license-scanner_, JSON is presumed for testing and documentation.**

You can also override the "config" part of this file name by setting the configName flag. For example, `--configName configTest` would allow you to test using `configTest.json` instead of the default config.json.

#### --configPath path

By default, _license-scanner_ will look for the config file in:

1. The directory containing the executable
2. The project root (for development and tests)

You can use the `--configPath path` flag to read your the config file from an alternate location. For example, `--configPath /tmp/test_dir --configName configTest` would allow you to test using `/tmp/test_dir/configTest.json` instead of the default config.json.

### Running with different resources

_license-scanner_ uses "resources" to configure license templates and legal terms for matching. For example, SPDX license matching is configured by the files under `resources/spdx` and the custom pattern matching is configured by the files under `resources/custom`.

At runtime you can configure an alternate location for resources in config.json. For example, the following config.json would allow you to use resources in `/tmp/test_dir/example_resources/`:

```json
{
  "resources": "/tmp/test_dir/example_resources"
}
```

> *NOTE: If the resources value is not an absolute path, it will be treated as relative to the config file.*

### Configuring runtime flag defaults

Viper provides the following precedence order. Each item takes precedence over the item below it:

1. **explicit call to Set()**
1. **flag**
1. env
1. **config**
1. key/value store
1. **default**

For example, _license-scanner_ has a default value for the --spdx flag. So, the out-of-the-box configuration will use files under `spdx/<default>` unless you use the `--spdx versionDir` flag on the command-line or use `Set("spdx", versionDir)` using the API. Using runtime flags is discussed in more detail below.

Since **config** takes precedence over **default**, and **flag or Set()** takes precedence over **config**, you can essentially customize the flag defaults in your config file. For example:

```json
{
  "resources": "resources",
  "spdx": "my3.17"
}
```

When using the above config file, _license-scanner_ would use the SPDX configuration files that you put under `spdx/my3.17` as the default, but the command-line flag `--spdx 3.18` (or API `Set("spdx", "3.18")`) can still be set to switch back to the spdx/3.18 runtime configuration.

This configurability applies to all the flags wherever it makes sense. Obviously it doesn't make sense to configure the configPath and configName this way. The Boolean flags can be set and unset like the following example:

```json
{
  "resources": "resources",
  "quiet": true
}
```

**--quiet** is a good example for testing. Note the JSON syntax above. The difference in the output when scanning a license file should clearly show a difference between true and false.

For Booean command-line flags, we typically default to false and override with a flag that has no value like `-q`. If you configure a Boolean flag to default to true, you can still override it on the command line by specifying a false value like this: `-q=false` or `--quiet=false`.
