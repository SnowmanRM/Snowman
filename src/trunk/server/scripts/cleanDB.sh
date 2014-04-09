#!/bin/bash

URL="http://192.168.6.11/static/rules/testset.1-1.tar.gz"

echo "DROP DATABASE srm; CREATE DATABASE srm;" | mysql -usrm -pbah5oofa6booyeeJa2Da 
../manage.py syncdb --noinput
python createDemoData.py

echo "INSERT INTO update_source (name, url, md5url, schedule, locked) VALUES ('Testing', '$URL', '$URL.md5', 'No automatic updates', 0);"  | mysql -usrm -pbah5oofa6booyeeJa2Da srm
