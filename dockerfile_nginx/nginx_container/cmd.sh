#!/bin/sh

nslookup localhost
ping -c 3 localhost
exec /usr/sbin/nginx -c /etc/nginx/nginx.conf