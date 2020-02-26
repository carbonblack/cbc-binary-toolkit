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
    "schema",
    "thespian"
]

setup(
    name="cbc_binary_sdk",
    version=read("VERSION"),
    url="https://developer.carbonblack.com/",
    license="MIT",
    author="Carbon Black",
    author_email="dev-support@carbonblack.com",
    description="Carbon Black Binary Analysis",
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
    scripts=["bin/cbc-binary-analysis"],
    data_files=[("carbonblackcloud/binary-sdk", ["config/binary-analysis-config.yaml.example"])],
    package_data={"cbc-binary-sdk": ["examples/*"]}
)
