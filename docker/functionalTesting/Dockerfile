from python:3.8.3
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN pip3 install -r requirements
RUN ln -s /usr/local/lib/python3.8/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
RUN python3 setup.py clean --all install
