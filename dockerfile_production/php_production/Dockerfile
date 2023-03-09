FROM php:7.2

RUN apt-get update \
  && docker-php-ext-install pdo_mysql mysqli mbstring \
    && apt-get -y install iputils-ping net-tools dnsutils

COPY php.ini /usr/local/etc/php/
WORKDIR /var/www
COPY create.php /var/www/create.php

ARG UID=1001
ARG GID=1002
RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/sh tester

USER tester