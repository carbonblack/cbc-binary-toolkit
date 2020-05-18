from python:3.7.7
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt
RUN ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
