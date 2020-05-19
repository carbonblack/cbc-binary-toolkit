from python:3.6.10
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt
RUN ln -s /usr/local/lib/python3.6/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
