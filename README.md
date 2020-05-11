[![Codeship Status for carbonblack/cb-binary-analysis](https://app.codeship.com/projects/6a7a91c0-2a8b-0138-4f71-1610ceb87095/status?branch=develop)](https://app.codeship.com/projects/384255)
[![Coverage Status](https://coveralls.io/repos/github/carbonblack/cb-binary-analysis/badge.svg?branch=develop&t=rhX4tc)](https://coveralls.io/github/carbonblack/cb-binary-analysis?branch=develop)
# Carbon Black Cloud Binary Toolkit

#### \*\*Disclaimer: This is an ALPHA release\*\*

**Latest Version:** 1.0a1
<br>
**Release Date:** 05/11/2020

The Carbon Black Cloud Binary Toolkit provides a system of processing incoming SHA256 hashes by integrating with the Unified Binary Store (UBS) on the Carbon Black Cloud (CBC).


## Recent updates

View the latest release notes [here](https://github.com/carbonblack/cbc-binary-toolkit/releases).


## License

Use of the Carbon Black API is governed by the license found in [LICENSE](LICENSE).

## Support

1. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com) along with reference documentation, video tutorials, and how-to guides.
2. Use the [Developer Community Forum](https://community.carbonblack.com/) to discuss issues and get answers from other API developers in the Carbon Black Community.
3. Create a github issue for bugs and change requests. Formal [Carbon Black Support](http://carbonblack.com/resources/support/) coming with v1.0.

## Requirements

The Carbon Black Cloud Binary Toolkit is design to work on Python 3.6 and above.

All requirements are installed as part of `pip install` or if you're planning on pushing changes to the Carbon Black Cloud Binary Toolkit, the following can be used after cloning the repo `pip install requirements.txt`

### Python Packages
* argparse
* cbapi
* python-dateutil
* pyyaml
* requests
* schema
* yara-python

### Carbon Black Cloud
* Enterprise EDR

## Getting Started

There are two ways to use the Carbon Black Cloud Binary Toolkit. You can either run the Binary Analysis Tool using out-of-the-box functionality, or you can use the Toolkit to develop your own tool for processing binaries.


First you will need to install the Binary Toolkit with the following command:
```
pip install cbc-binary-toolkit
```

### Running Binary Analysis tool

The cbc-binary-analysis tool provides out-of-the-box builtin resources for processing binaries and managing the analysis results. For more information see the [User Guide](https://github.com/carbonblack/cbc-binary-toolkit/wiki/User-Guide) wiki page.

```
usage: cbc-binary-analysis [-h] [-c CONFIG]
                           [-ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                           {analyze,restart,clear} ...

positional arguments:
  {analyze,restart,clear}
                        Binary analysis commands
    analyze             Analyze a list of hashes by command line or file
    restart             Restart a failed job and pick up where the job crashed
                        or exited
    clear               Clear cache of analyzed hashes. All or by timestamp

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Location of the configuration file (default .../carbonblackcloud/binary-toolkit/binary-analysis-config.yaml.example)
  -ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        The base log level (default INFO)
```

**Note: Run --help on any of the commands for up to date arguments**


### Using the Toolkit to develop your own tools

The following python code snippet will allow you to begin developing with the Carbon Black Cloud Binary toolkit. For more information see the [Developer Guide](https://github.com/carbonblack/cbc-binary-toolkit/wiki/Developer-Guide) wiki page.
```
from cbc_binary_toolkit import *
```


## Developing Improvements for the Carbon Black Cloud Binary Toolkit

If you want to provide additional examples, fix a bug, or add a feature to the Toolkit the following steps will get you started.

### Installing for Toolkit development

You will need to fork the repo in order to create pull requests when submitting code for review. For details on forking a repo, see [here](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)

```
git clone https://github.com/{fork-name}/cbc-binary-toolkit
cd cbc-binary-toolkit
pip install requirements.txt
```


### Running the Toolkit tests

To check if your code changes didn't break any use cases the following command will run all the tests:
```
pytest
  Optional args:
    -s Logs streamed to stdout
    -k {test or file} Selectively runs test matching string or file
```

### Development Flow

To begin a code change start by creating a branch off of the develop branch.
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

Note if your develop branch is out of sync with the CarbonBlack repo then you will need to sync your fork. For information on syncing your fork, see [here](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork)
