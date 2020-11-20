[![Codeship Status for carbonblack/cb-binary-analysis](https://app.codeship.com/projects/6a7a91c0-2a8b-0138-4f71-1610ceb87095/status?branch=develop)](https://app.codeship.com/projects/384255)
[![Coverage Status](https://coveralls.io/repos/github/carbonblack/cbc-binary-toolkit/badge.svg?branch=develop)](https://coveralls.io/github/carbonblack/cbc-binary-toolkit?branch=develop)
# Carbon Black Cloud Binary Toolkit

**Latest Version:** 1.1.0
<br>
**Release Date:** 11/20/2020

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

The Carbon Black Cloud Binary Toolkit is designed to work on Python 3.6 and above.

All requirements are installed as part of `pip install cbc-binary-toolkit` or if you're planning on pushing changes to the Carbon Black Cloud Binary Toolkit, the following can be used after cloning the repo `pip install -r requirements.txt`

### Carbon Black Cloud
* Enterprise EDR

### OS Specific Requirements

* **Windows** users will need to have [Microsoft Visual C++ 14.0 Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools) installed in order to compile yara-python.

* **Linux** users will need to have the python developer package installed in order to compile yara-python. If you receive compile errors, make sure you are on the latest gcc compiler version.

Linux Distribution | Command
---- | ----
Amazon Linux/Centos/RHEL | `yum install python3-devel`
Ubuntu | `apt-get install python3-dev`
OpenSUSE/SUSE | `zypper install python3-devel`


### Python Packages
* argparse
* carbon-black-cloud-sdk
* python-dateutil
* pyyaml
* requests
* schema
* yara-python

## Performance Metrics

For details on the expected performance for the CBC Binary Toolkit see the Performance Metrics wiki page [here](https://github.com/carbonblack/cbc-binary-toolkit/wiki/Performance-Metrics).

The wiki page will be updated with any changes or additional tests that may be run in the future.

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

**Note:** Run --help on any of the commands for up to date arguments.


### Using the Toolkit to develop your own tools

The following python code snippet allows you to begin developing with the Carbon Black Cloud Binary toolkit. For more information see the [Developer Guide](https://github.com/carbonblack/cbc-binary-toolkit/wiki/Developer-Guide).
```
from cbc_binary_toolkit import *
```


## Developing Improvements for the Carbon Black Cloud Binary Toolkit

Use the following steps if you want to provide additional examples, fix a bug, or add a feature to the Toolkit.

### Installing for Toolkit development

You will need to fork the repo in order to create pull requests when submitting code for review. For details on forking a repo, see [here](https://help.github.com/en/github/getting-started-with-github/fork-a-repo).

```
git clone https://github.com/{fork-name}/cbc-binary-toolkit
cd cbc-binary-toolkit
pip install -r requirements.txt
```

If you want to test/execute the console scripts from the repo then install the toolkit with the following command. This will install the toolkit in editable mode so changes to the repo modify the installed package. See the [manual-tests](src/tests/manual-tests.md) document for more information on testing from a fresh install.

```
pip install -e .
```

**Note: The above command needs to be run from the base folder of the repo**

### Running the Analysis tool

If you want to execute the analysis tool without installing the package you can run the tool directly using the `analysis_util.py` script in `src/cbc_binary_toolkit_examples/tools`

### Running the Toolkit tests

To check that your code changes didn't break any use cases, or fail our linters, the following will show you how to set up and run our tests:

Install one or all of these versions of Python: `Python 3.6.X, Python 3.7.X or Python 3.8.X` and make sure it is accessible to this project.

For managing different versions of python, an easy solution is: [pyenv(for UNIX based systems)](https://github.com/pyenv/pyenv#basic-github-checkout), or [pyenv-win(for Windows based systems)](https://github.com/pyenv-win/pyenv-win).

Install [tox](https://tox.readthedocs.io/en/latest/install.html) (e.g. `pip install tox` or `brew install tox`)

Run the command `tox -e <the environment you want to run>` from anywhere in the directory to run the tests and linter.

The `tox.ini` file shows that the tests are run against python versions `3.6.x, 3.7.x and 3.8.x` as `py36, py37, py38`.

**Example:** If you just run `tox -e py37`, it will run the tests against the `Python 3.7.X` version installed locally.

But if `tox` is run, it will try to run against all the versions listed in the `tox.ini` file (currently py36, py37, and py38).
If a version is not installed locally, it will just throw an error of:

```
ERROR:  pyXX: InterpreterNotFound: pythonX.X

```
It will continue running against the versions that are installed.


If there are any changes, you need to recreate the virtualenv that tox built. Just run `tox --recreate -e <the environment you want to run>` or `tox --recreate` for all environments.

If this error is thrown:
```
ERROR: cowardly refusing to delete `envdir` (it does not look like a virtualenv):

```
Delete the python env directory (py37) from .tox directory
and rerun `tox --recreate`.

### Development Flow

To begin a code change, start by creating a branch off of the develop branch.
```
git checkout develop
git checkout -b {branch-name}
```

When the feature or bug fix is finished you will need to create a pull request to the CarbonBlack repo, the following will push your changes to Github.
```
git push {remote} {branch-name}
```

If your branch is behind the develop branch, you will need to rebase.
```
git checkout {branch-name}
git rebase develop
```

**Note:** if your develop branch is out of sync with the CarbonBlack repo then you will need to sync your fork. For information on syncing your fork, see [here](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork).
