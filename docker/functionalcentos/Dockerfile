from centos:7.8.2003
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN yum -y install python3-devel
RUN yum -y install centos-release-scl
RUN yum -y install devtoolset-9
RUN pip3 install awscli
RUN pip3 install -r requirements.txt
RUN python3 setup.py install
