FROM nginx:latest

RUN apt-get update \
    && apt-get install -y iputils-ping net-tools \

CMD ["ping","localhost","-c","3"]
CMD ["mkdir","make_directory_docker"]


