#!/usr/bin/env python3
"""Python setup script for PIP packaging"""
from __future__ import unicode_literals
import os
from setuptools import setup, find_packages


def read(fname):
    """Process files for configuration"""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_reqs = [
    "argparse",
    "cbapi",
    "python-dateutil",
    "pyyaml",
    "requests",
    "schema",
    "yara"
]

setup(
    name="cbc_binary_toolkit",
    version=read("VERSION"),
    url="https://developer.carbonblack.com/",
    license="MIT",
    author="VMware Carbon Black",
    author_email="dev-support@carbonblack.com",
    description="The VMware Carbon Black Cloud Binary Toolkit provides useful tools to process "
                "binaries and upload IOCs to your Feeds",
    long_description=__doc__,
    platforms="any",
    classifiers=[
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=install_reqs,
    package_dir={'': 'src'},
    packages=find_packages(where="src", exclude=["tests.*", "tests"]),
    entry_points={"console_scripts": ["cbc-binary-analysis = cbc_binary_toolkit_examples.tools.analysis_util:main"]},
    data_files=[("carbonblackcloud/binary-toolkit", ["config/binary-analysis-config.yaml.example"])]
)
