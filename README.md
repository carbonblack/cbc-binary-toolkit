[![Codeship Status for carbonblack/cb-binary-analysis](https://app.codeship.com/projects/6a7a91c0-2a8b-0138-4f71-1610ceb87095/status?branch=develop)](https://app.codeship.com/projects/384255)
[![Coverage Status](https://coveralls.io/repos/github/carbonblack/cb-binary-analysis/badge.svg?branch=develop&t=rhX4tc)](https://coveralls.io/github/carbonblack/cb-binary-analysis?branch=develop)
# Carbon Black Cloud Binary Analysis SDK

**Latest Version:** 0.0.1
<br>
**Release Date:** N/A




## Support

If you have questions about the Binary Analysis SDK, please contact us at dev-support@carbonblack.com
Also review the documentation and guides available on the
[Carbon Black Developer Network website](https://developer.carbonblack.com)

## Requirements

The Binary Analysis SDK is design to work on Python 3.6 and above.

All requirements are install as part of `pip install` or
if you're planning on pushing changes to the Binary Analysis SDK then following can be used after cloning the repo
`pip install requirements.txt`

##### Packages
* argparse
* cbapi
* python-dateutil
* pyyaml
* schema
* thespian

## Getting Started


Installing the Binary Analysis SDK

```
pip install cbc-binary-sdk
```

Running Binary Analysis tool

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


Using the SDK

```
from cbc_binary_sdk import *
```


## Improving the Binary Analysis SDK

##### Installing for SDK development
```
git clone https://github.com/carbonblack/cb-binary-analysis
cd cb-binary-analysis
pip install requirements.txt
```


##### Running SDK tests

```
pytest
  Optional args:
    -s Logs streamed to stdout
    -k {test or file} Selectively runs test matching string or file
```
