FROM php:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils

WORKDIR /var/www
ARG UID=1000
ARG GID=1000

RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/bash tester

USER tester

CMD bash -c "/bin/bash"