appname      = "myapp"
subnet_cidr = ["10.0.1.0/24","10.0.2.0/24","10.0.3.0/24","10.0.4.0/24"]
ami          = {
        "us-west-2" = "ami-08628b82e690795c0"
        "us-east-2" = "ami-05602e26de8e96a36"
}    
region       = "us-west-2"
#localip = "0.0.0.0/0"
localip           = "8.8.8.8/32"
instance_type     = "t2.micro"
key_name          = "ec2-keypair"


accesslogbucket_parameter_name = "accesslogbucket"


tablename = "nps_parks"
readcapacity = "1"
writecapacity = "1"
hashkey = "Name"
hashkey_type = "S"



