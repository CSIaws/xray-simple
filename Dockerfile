FROM  amazonlinux:2.0.20201111.0
MAINTAINER csi <csi@chinasofti.com> 
ENV KEYCLOAK_VERSION 11.0.3
ENV JDBC_POSTGRES_VERSION 42.2.20
ENV JDBC_MYSQL_VERSION 8.0.19
ENV JDBC_MARIADB_VERSION 2.5.4
ENV JDBC_MSSQL_VERSION 7.4.1.jre11

ENV LAUNCH_JBOSS_IN_BACKGROUND 1
ENV PROXY_ADDRESS_FORWARDING false
ENV JBOSS_HOME /opt/jboss/keycloak
ENV LANG en_US.UTF-8

ARG GIT_REPO
ARG GIT_BRANCH
ARG KEYCLOAK_DIST=https://downloads.jboss.org/keycloak/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz

USER root

RUN yum -y update && yum -y install glibc-langpack-en gzip hostname openssl tar net-tools gcc gcc-c++ pcre-devel glibc which && yum clean all

ADD tools   /opt/jboss/tools

RUN  yum -y install  /opt/jboss/tools/jdk-11.0.10_linux-x64_bin.rpm
RUN /opt/jboss/tools/build-keycloak.sh
COPY postgresql-42.2.20.jar  module.xml  /opt/jboss/keycloak/modules/system/layers/keycloak/org/postgresql/main/  
USER 1000

EXPOSE 8080
EXPOSE 8443

ENTRYPOINT [ "/opt/jboss/tools/docker-entrypoint.sh" ]

CMD ["-b", "0.0.0.0"]
