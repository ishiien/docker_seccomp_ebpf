FROM php:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils

WORKDIR /var/www

CMD bash -c "ping -c 1 localhost && /bin/bash"

