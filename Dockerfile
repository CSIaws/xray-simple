FROM  amazonlinux:2.0.20201111.0
MAINTAINER csi <csi@chinasofti.com>
RUN yum -y update && yum -y install glibc-langpack-en gzip hostname openssl tar wget  net-tools gcc gcc-c++ pcre-devel glibc which && yum clean all && useradd www
RUN  wget https://openresty.org/package/amazon/openresty.repo && mv openresty.repo /etc/yum.repos.d/  && yum check-update
RUN  yum install -y openresty  && yum install -y openresty-resty
RUN mkdir /usr/local/openresty/site/lualib/lua && mkdir /usr/local/openresty/lualib/resty/session
COPY nginx.conf   /usr/local/openresty/nginx/conf/nginx.conf
COPY openidc.lua  /usr/local/openresty/site/lualib/lua

CMD ["/usr/bin/openresty", "-g", "daemon off;"]
