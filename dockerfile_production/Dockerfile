FROM php:latest

RUN apt-get update
RUN apt-get install -y sudo

WORKDIR /var/www
COPY ./index.php /var/www

ARG UID=1000
ARG GID=1000

RUN groupadd -g ${GID} docker

RUN useradd -u ${UID} -g ${GID} -s /bin/bash tester

USER ${UID}