#!/usr/bin/env python3

from setuptools import setup


def requirements():
    with open("requirements.txt") as requirements:
        return requirements.read().splitlines()


setup(
    name="cb-binary-analysis",
    version="0.0.1",
    url="https://developer.carbonblack.com/",
    license="MIT",
    author="Carbon Black",
    author_email="dev-support@carbonblack.com",
    description="Carbon Black Binary Analysis",
    long_description=__doc__,
    # packages=["cb.psc.integration"],
    # package_dir={"": "app"},
    platforms="any",
    classifiers=[
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=requirements(),
)
