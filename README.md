[![Codeship Status for carbonblack/cb-binary-analysis](https://app.codeship.com/projects/6a7a91c0-2a8b-0138-4f71-1610ceb87095/status?branch=develop)](https://app.codeship.com/projects/384255)
[![Coverage Status](https://coveralls.io/repos/github/carbonblack/cb-binary-analysis/badge.svg?branch=develop&t=rhX4tc)](https://coveralls.io/github/carbonblack/cb-binary-analysis?branch=develop)
# Carbon Black Cloud Binary Toolkit

**Latest Version:** 0.0.1
<br>
**Release Date:** N/A

The Carbon Black Cloud Binary Toolkit provides a system of processing incoming SHA256 hashes by integrating with the Universal Binary Store (UBS) on the Carbon Black Cloud (CBC).


## Support

If you have questions about the Carbon Black Cloud Binary Toolkit, please contact us at dev-support@carbonblack.com
Also review the documentation and guides available on the
[Carbon Black Developer Network website](https://developer.carbonblack.com)

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
* yara

## Getting Started

There are two ways to use the Carbon Black Cloud Binary Toolkit. The following scripts provide all out-of-the-box functionality. You can also use the Toolkit to develop your own tool for processing binaries.


Installing the Carbon Black Cloud Binary Toolkit

```
pip install cbc-binary-toolkit
```

### Running Binary Analysis tool

The cbc-binary-analysis tool provides out-of-the-box builtin resources for processing binaries and managing the analysis results.

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
                        Location of the configuration file (default
                        /Users/avanbrunt/reno/Work/cb-binary-
                        analysis/bin/../config/binary-analysis-
                        config.yaml.example)
  -ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        The base log level (default INFO)
```


### Using the Toolkit to develop your own tools

```
from cbc_binary_toolkit import *
```




## Developing Improvements for the Carbon Black Cloud Binary Toolkit

If you want to provide additional examples, fix a bug, or add a feature to the Toolkit the following steps will get you started.

### Installing for Toolkit development

You will need to fork the repo in order to create pull requests when submitting code for review. For details on forking a repo https://help.github.com/en/github/getting-started-with-github/fork-a-repo

```
git clone https://github.com/{fork-name}/cb-binary-analysis
cd cb-binary-analysis
pip install requirements.txt
```


### Running the Toolkit tests

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
