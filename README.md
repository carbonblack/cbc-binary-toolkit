[![Codeship Status for carbonblack/cb-binary-analysis](https://app.codeship.com/projects/6a7a91c0-2a8b-0138-4f71-1610ceb87095/status?branch=develop)](https://app.codeship.com/projects/384255)
[![Coverage Status](https://coveralls.io/repos/github/carbonblack/cb-binary-analysis/badge.svg?branch=develop&t=rhX4tc)](https://coveralls.io/github/carbonblack/cb-binary-analysis?branch=develop)
# Carbon Black Cloud Binary Analysis SDK

**Latest Version:** 0.0.1
<br>
**Release Date:** N/A

The Binary Analysis SDK provides a system of processing incoming SHA256 hashes by integrating with the Universal Binary Store (UBS) on the Carbon Black Cloud (CBC).


## Support

If you have questions about the Binary Analysis SDK, please contact us at dev-support@carbonblack.com
Also review the documentation and guides available on the
[Carbon Black Developer Network website](https://developer.carbonblack.com)

## Requirements

The Binary Analysis SDK is design to work on Python 3.6 and above.

All requirements are installed as part of `pip install` or if you're planning on pushing changes to the Binary Analysis SDK, the following can be used after cloning the repo `pip install requirements.txt`

### Packages
* argparse
* cbapi
* python-dateutil
* pyyaml
* schema
* thespian

## Getting Started

There are two ways to use the Binary Analysis SDK. The following scripts provide all out-of-the-box functionality. You can also use the SDK to develop your own tool for processing binaries.


Installing the Binary Analysis SDK

```
pip install cbc-binary-sdk
```

### Running Binary Analysis tool

The cbc-binary-analysis tool provides out-of-the-box builtin resources for processing binaries and managing the analysis results.

```
usage: cbc-binary-analysis [-h] [-C CONFIG] {analyze,clear} ...

positional arguments:
  {analyze,clear}       Binary analysis commands
    analyze             Analyze a list of hashes by command line or file
    clear               Clear cache of analyzed hashes

optional arguments:
  -h, --help            show this help message and exit
  -C CONFIG, --config CONFIG
                        Location of the configuration file (default
                        config/binary-analysis-config.yaml)
```


### Using the SDK to develop your own tools

```
from cbc_binary_sdk import *
```




## Developing Improvements for the Binary Analysis SDK

If you want to provide additional examples, fix a bug, or add a feature to the SDK the following steps will get you started.

### Installing for SDK development

You will need to fork the repo in order to create pull requests when submitting code for review. For details on forking a repo https://help.github.com/en/github/getting-started-with-github/fork-a-repo

```
git clone https://github.com/{fork-name}/cb-binary-analysis
cd cb-binary-analysis
pip install requirements.txt
```


### Running the SDK tests

```
pytest
  Optional args:
    -s Logs streamed to stdout
    -k {test or file} Selectively runs test matching string or file
```

### Development Flow

Create a branch off of the develop branch
```
git checkout develop
git checkout -b {branch-name}
```

When the feature or bug fix is finished you will need to create a pull request to the CarbonBlack repo, the following will push your changes to Github.
```
git push {remote} {branch-name}
```

If your branch is behind the develop branch then you will need to rebase.
```
git checkout {branch-name}
git rebase develop
```

Note if your develop branch is out of sync with the CarbonBlack repo then you will need to sync your fork. https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork
