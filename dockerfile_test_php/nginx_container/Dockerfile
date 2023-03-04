FROM nginx:latest

RUN apt-get update
RUN apt-get -y install iputils-ping net-tools dnsutils vim

WORKDIR /var/www
COPY cmd.sh /var/www/cmd.sh
RUN chmod +x cmd.sh

#ENTRYPOINT bash -c "./../cmd.sh"