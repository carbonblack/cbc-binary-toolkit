# *******************************************************
# Copyright (c) Broadcom, Inc. 2020-2024. All Rights Reserved. Carbon Black.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
from opensuse/leap
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN zypper --non-interactive install python3-devel
RUN zypper --non-interactive install python3-pip
RUN zypper --non-interactive install gcc
RUN pip3 install awscli
RUN pip3 install -r requirements.txt
RUN python3 setup.py install
