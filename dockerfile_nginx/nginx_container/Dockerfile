FROM nginx:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils vim

COPY index.html /usr/share/nginx/html/index.html

WORKDIR /var/www
COPY cmd.sh /var/www/cmd.sh
RUN chmod +x cmd.sh

ENTRYPOINT bash -c "./cmd.sh"