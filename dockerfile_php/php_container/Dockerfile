FROM php:7.2-fpm

COPY php.ini /usr/local/etc/php/

RUN apt-get update \
  && apt-get install -y zlib1g-dev mariadb-client \
  && docker-php-ext-install zip pdo_mysql

COPY create.php /var/www/create.php
COPY cmd.sh /var/www/cmd.sh

WORKDIR /var/www
RUN chmod +x cmd.sh

CMD bash -c "./cmd.sh && /bin/bash"