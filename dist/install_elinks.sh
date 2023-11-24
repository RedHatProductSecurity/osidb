#!/bin/bash

if [[ "$(sha256sum gpm-libs-1.20.7-17.el8.x86_64.rpm | cut -d' ' -f1)" == "9fe5b0c5fee372362d423e17b56f01d1c15cc0725bd989bdfc742f30c1119e0b" ]]
then
    rpm -i gpm-libs-1.20.7-17.el8.x86_64.rpm
else
    exit 1
fi

if [[ "$(sha256sum elinks-0.12-0.58.pre6.el8.x86_64.rpm | cut -d' ' -f1)" == "df5761fb479174c71f2ecfa6fdb348c8cbeb6134a3cef34fdf764ce5c9f085bf" ]]
then
    rpm -i elinks-0.12-0.58.pre6.el8.x86_64.rpm
else
    exit 1
fi

