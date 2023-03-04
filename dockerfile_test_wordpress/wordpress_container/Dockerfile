FROM wordpress:latest

RUN apt-get update
RUN apt-get install -y zip unzip
RUN docker-php-ext-install pdo_mysql
RUN curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
  && chmod +x wp-cli.phar \
  && mv wp-cli.phar /usr/local/bin/wp \
  && wp --info

RUN apt install -y sudo git default-mysql-client subversion

COPY php.ini /usr/local/etc/php/
COPY create.php /var/www/html/create.php
COPY cmd.sh /var/www/cmd.sh
COPY --from=composer /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
RUN chmod +x /var/www/cmd.sh

#ARG UID=1000
#ARG GID=1000
#RUN groupadd -g ${GID} dockers
#RUN useradd -u ${UID} -s /bin/sh tester


ENTRYPOINT bash -c "../cmd.sh"
#USER tester