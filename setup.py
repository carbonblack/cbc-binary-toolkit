#!/usr/bin/env python3
"""Python setup script for PIP packaging"""
import os
from setuptools import setup


def read(fname):
    """Process files for configuration"""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_reqs = [
    "argparse",
    "python-dateutil",
    "pyyaml",
    "thespian"
]

setup(
    name="cb-binary-analysis",
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
    packages=["cb_binary_analysis"]
)
