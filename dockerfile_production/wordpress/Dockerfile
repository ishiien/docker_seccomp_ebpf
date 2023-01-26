FROM php:7.4.8-apache

RUN apt-get update && apt-get install -y libonig-dev \
  && docker-wordpress-ext-install pdo_mysql mysqli \
    && apt-get -y install iputils-ping net-tools dnsutils

COPY php.ini /usr/local/etc/php/
WORKDIR /var/www
COPY create.php /var/www/create.php
COPY index.php /var/www/index.php
COPY unallow.php /var/www/unallow.php

#ARG UID=1001
#ARG GID=1002
#RUN groupadd -g ${GID} docker
#RUN useradd -u ${UID} -s /bin/sh tester
#
#USER tester