FROM  mysql:5.6

COPY cmd.sh /cmd.sh
COPY mysql.sh /mysql.sh
RUN chmod +x cmd.sh
RUN chmod +x mysql.sh

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} docker
RUN useradd -u ${UID} -s /bin/sh tester

USER tester