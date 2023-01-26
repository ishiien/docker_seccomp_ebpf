FROM wordpress:latest

COPY php.ini /usr/local/etc/php/
COPY create.php /var/www/html/create.php
COPY cmd.sh /var/www/cmd.sh

WORKDIR /var/www/html
RUN chmod +x /var/www/cmd.sh

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} dockers
RUN useradd -u ${UID} -s /bin/sh tester


ENTRYPOINT bash -c "../cmd.sh"
USER tester