FROM php:7.2
COPY php.ini /usr/local/etc/php/

RUN apt-get update \
  && apt-get install -y zlib1g-dev mariadb-client \
    && apt-get install -y iputils-ping net-tools dnsutils vim

WORKDIR /var/www
COPY cmd.sh /var/cmd.sh
RUN chmod +x ./../cmd.sh

ENTRYPOINT bash -c "./../cmd.sh && /bin/bash "