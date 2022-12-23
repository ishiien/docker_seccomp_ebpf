FROM php:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils

WORKDIR /var/www
COPY cmd.sh /var/www/cmd.sh
RUN chmod +x cmd.sh

CMD bash -c "./cmd.sh && /bin/bash"


