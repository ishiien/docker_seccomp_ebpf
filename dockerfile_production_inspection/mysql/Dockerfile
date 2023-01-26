FROM  mysql:5.6

WORKDIR /var/www

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/sh tester

USER tester