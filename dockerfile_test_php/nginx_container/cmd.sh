#!/bin/sh

nslookup localhost
ping -c 3 localhost
/usr/sbin/nginx -g 'daemon off;'