FROM php:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools

WORKDIR /var/www
COPY public/index.php /var/www


ARG UID=2000
ARG GID=2000

RUN groupadd -g ${GID} docker

RUN useradd -u ${UID} -g ${GID} -s /bin/bash tester

USER ${UID}

CMD bash -c "php index.php && /bin/bash"

