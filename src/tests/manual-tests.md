# CBC Binary Toolkit Manual Tests
This document will go through how to configure you environment for a fresh manual install/test

### Creating a virtualenv
You should create a fresh virtualenv when testing to confirm everything in the package is correctly installed. [More information](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)
```
python3 -m venv env

Mac/Linux:
source env/bin/activate

Windows:
.\env\Scripts\activate
```

### Installing the Toolkit
If you have the repo cloned run the following command otherwise see the [homepage](https://github.com/carbonblack/cbc-binary-toolkit) for instructions cloning the repo.
```
python setup.py install
```

### Testing Install
To test that the toolkit installed correctly use the `cbc-binary-analysis` tool.
```
cbc-binary-analysis --help
```

The config parameter will indicate where the default binary-analysis-config.yaml.example will be installed. Feel free to copy the contents to another location as needed or edit them in place.


### Testing with Yara example
To test a complete end to end of the `cbc-binary-analysis` tool, the following configuration with your Carbon Black Cloud environment variables filled in will allow for a binary to be analyzed and the report be push to your configured feed. The local database file will be created if one doesn't already exist to save the state of analyzed hashes or protect your reports from being lost if a crash occurs during execution.

**Configuration**
```
# Configuration for the Binary Analysis Tool
id: cbc_binary_toolkit
version: 0.0.1
carbonblackcloud:
  url: {Carbon Black Cloud URL}
  api_token: {API Key}/{API Id}
  org_key: {Org Key}
  ssl_verify: False
  expiration_seconds: 3600
database:
  _provider: cbc_binary_toolkit.state.builtin.Persistor
  location: {Local DB file}
engine:
  name: Yara
  feed_id: {Feed Id}
  type: local
  _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
  rules_file: __file__/example_rule.yara
```

The following commands are some basic starting points to test the binary analysis tool.

```
cbc-binary-analysis analyze --list '["{INSERT SHA256 HASH}"]'

cbc-binary-analysis clear --timestamp {YYYY-MM-DD HH:MM:SS.SSS}

cbc-binary-analysis restart
```


### Leaving environment
Once you are finished running the manual tests you can leave the virtualenv with the following command.
```
deactivate
```
