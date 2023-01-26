FROM php:7.2

RUN apt-get update  \
  && docker-wordpress-ext-install pdo_mysql mysqli mbstring \
    && apt-get -y install iputils-ping net-tools dnsutils

COPY php.ini /usr/local/etc/php/
COPY create.php /var/www/create.php
COPY cmd.sh /var/www/cmd.sh


ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/sh tester

WORKDIR /var/www
RUN chmod +x cmd.sh

ENTRYPOINT bash -c "./cmd.sh && /bin/bash"
USER tester