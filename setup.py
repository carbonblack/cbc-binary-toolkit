#!/usr/bin/env python3
import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

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
    install_requires=read("requirements.txt").splitlines(),
    tests_require=read("tests/requirements.txt").splitlines()
)
