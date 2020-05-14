#!/usr/bin/env python3
"""Python setup script for PIP packaging"""
from __future__ import unicode_literals
import os
from setuptools import setup, find_packages


def read(fname):
    """Process files for configuration"""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_reqs = [
    "cbapi",
    "python-dateutil",
    "pyyaml",
    "requests",
    "schema",
    "yara-python"
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
    long_description=read("README.md"),
    long_description_content_type='text/markdown',
    platforms="any",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=install_reqs,
    package_dir={'': 'src'},
    packages=find_packages(where="src", exclude=["tests.*", "tests"]),
    include_package_data=True,
    entry_points={"console_scripts": ["cbc-binary-analysis = cbc_binary_toolkit_examples.tools.analysis_util:main"]},
    data_files=[("carbonblackcloud/binary-toolkit", ["config/binary-analysis-config.yaml.example"])]
)
