FROM php:latest

RUN apt-get update

WORKDIR /var/www
COPY ./index.php /var/www
CMD ["php","index.php"]