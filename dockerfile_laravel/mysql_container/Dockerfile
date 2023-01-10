FROM php:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/sh tester

WORKDIR /var/www
COPY cmd.sh /var/www/cmd.sh
RUN chmod +x cmd.sh

CMD bash -c "./cmd.sh && /bin/bash"
USER tester


