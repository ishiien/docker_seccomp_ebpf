FROM nginx:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils vim

WORKDIR /var/www
COPY cmd.sh /var/www/cmd.sh
COPY html /var/www/html
RUN chmod +x cmd.sh

CMD bash -c "./cmd.sh && /bin/bash"