from python:3.8.3
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN pip3 install awscli
RUN pip3 install -r requirements.txt
RUN python3 setup.py install
