#!/bin/bash
/usr/bin/aws s3 cp ${s3bucket}/userdata/aws-userdata-script.sh /root/userdata/aws-userdata-script.sh
/usr/bin/aws s3 cp ${s3bucket}/userdata/data.csv /root/userdata/data.csv
chmod u+x /root/userdata/aws-userdata-script.sh
/root/userdata/aws-userdata-script.sh
yum install python3 -y 
python3 -m pip install --upgrade pip
python3 -m pip install boto3
python3 -m pip install MySQL-python
python3 -m pip install mysql-connector-python
