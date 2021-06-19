variable appname {}
variable region {}
variable subnet_cidr {}
variable ami { type = map}
variable instance_type {}
variable localip {}
variable key_name {}

variable tablename {}
variable readcapacity {}
variable writecapacity {}
variable hashkey {}
variable hashkey_type {}

variable accesslogbucket_parameter_name {} 


data "aws_ssm_parameter" "s3bucket" {
  name = "s3bucket"
}

data "aws_ssm_parameter" "accesslogbucket" {
  name = var.accesslogbucket_parameter_name
}

data aws_availability_zones "azs" {}

data "template_file" "user_data_file" {
    template = file("user_data.tpl")
    vars =  {
        s3bucket = data.aws_ssm_parameter.s3bucket.value
        
    }
}


#Info
provider "aws" {
  version = "~> 2.0"
  region  = var.region
  profile = "myapp"
  access_key = "my-access-key"
  secret_key = "my-secret-key"
}

#VPCConfig
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name    = "${var.appname}_vpc"
    appname = "${var.appname}"
  }
}


#Gateway

resource "aws_internet_gateway" "app_ig" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name    = "${var.appname}_ig"
    appname = "${var.appname}"
  }
}

#NonDefaultRouteTable
resource "aws_route_table" "app_rt" {
  vpc_id = aws_vpc.app_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.app_ig.id
  }
}


#SubnetConfig
resource "aws_subnet" "app_subnets" {
  vpc_id = aws_vpc.app_vpc.id
  count = length(data.aws_availability_zones.azs.names)
  #count = "${length(var.azs)}"
  cidr_block        = element(var.subnet_cidr,count.index)
  availability_zone = data.aws_availability_zones.azs.names[count.index]
  tags = {
    Name    = "${var.appname}_subnet_${element(data.aws_availability_zones.azs.names,count.index)}"
    appname = var.appname
  }
}




resource "aws_route_table_association" "app_rt_subnets" {
  count = length(data.aws_availability_zones.azs.names)
  subnet_id      = aws_subnet.app_subnets[count.index].id
  route_table_id = aws_route_table.app_rt.id
}

resource "aws_iam_role_policy" "app_s3_rds_access_role_policy" {
  name = "${var.appname}-s3access_role_policy"
  role = aws_iam_role.app_s3_rds_access_role.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "rds:*",
                "iam:PassRole",
                "iam:ListInstanceProfiles",
                "ec2:*"
            ],
            "Resource": ["arn:aws:rds:region:*:*"]
        }
    ]
}
  EOF
}

resource "aws_iam_role" "app_s3_rds_access_role" {
  name = "${var.appname}-s3access_role"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}


resource "aws_iam_instance_profile" "app_instance_profile" {
  name = "${var.appname}-instance-profile"
  role = aws_iam_role.app_s3_rds_access_role.name
}


#SecurityGroup
resource "aws_security_group" "app_sg_allow_localip" {
  vpc_id      = aws_vpc.app_vpc.id
  name        = "allow_localip"
  description = "Allow HTTP, HTTPS and SSH traffic"
  

    ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    description = "http to VPC from localip"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups  = [aws_security_group.app_sg_allow_public.id]
  }
  

  ingress {
    description = "ssh to VPC from localip"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.localip}"]
  }

  ingress {
    description = "ping to VPC from localip"
    from_port   = 0
    to_port     = 0
    protocol    = "icmp"
    cidr_blocks = ["${var.localip}"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_http_https"
  }
}


resource "aws_security_group" "app_sg_allow_public" {
  vpc_id      = aws_vpc.app_vpc.id
  name        = "allow_publicip"
  description = "Allow HTTP and HTTPS inbound traffic"
  
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "http to VPC from localip"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_http"
  }
}



#EC2InstanceConfiguration
resource "aws_instance" "app-web" {
  ami                         = lookup(var.ami,var.region)
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.app_sg_allow_localip.id]
  subnet_id                   = aws_subnet.app_subnets[0].id
  associate_public_ip_address = true
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.app_instance_profile.name
  user_data                   = data.template_file.user_data_file.rendered
  
  tags = {
    Name = "${var.appname}-web"
  }
}



#RDS

resource "aws_db_table" "app-db-table" {
  name = var.tablename 
  read_capacity = var.readcapacity
  write_capacity = var.writecapacity
  hash_key = var.hashkey 
  

  attribute {
    name = var.hashkey
    type = var.hashkey_type
  }


  
  tags = {
    Name = "${var.appname}-mysql-${var.tablename}"
    appname = var.appname

  }
}



#EC2AMI

resource "aws_ami_from_instance" "app-ami" {
  name = "${var.appname}-golden-ami"
  source_instance_id = aws_instance.app-web.id
}

#LaunchConfiguration

resource "aws_launch_configuration" "app-launch-config" {
  image_id = aws_ami_from_instance.app-ami.id
  name = "${var.appname}-launch-config"
  instance_type = var.instance_type
  
  iam_instance_profile = aws_iam_instance_profile.app_instance_profile.name
  associate_public_ip_address  = true
  security_groups     = [aws_security_group.app_sg_allow_localip.id]
  key_name = var.key_name
  user_data =  data.template_file.user_data_file.rendered
}

#AutoScallingGroup

resource "aws_autoscaling_group" "app-asg" {
  name               = "${var.appname}-asg"
  max_size           = 3
  min_size           = 2
  desired_capacity   = 2
  launch_configuration = aws_launch_configuration.app-launch-config.name
  vpc_zone_identifier  = [aws_subnet.app_subnets[0].id,aws_subnet.app_subnets[1].id]
  lifecycle {
    create_before_destroy = true
  }
  #load_balancers = [aws_lb.app-lb.id]
  target_group_arns = [aws_lb_target_group.app-lb-tg.arn]
  depends_on = [aws_lb_target_group.app-lb-tg,aws_lb.app-lb]

}



#Application Load Balancer

# Load balancer
resource "aws_lb" "app-lb" {
  name = "${var.appname}-lb"
  internal = false
  load_balancer_type = "application"
  security_groups = [aws_security_group.app_sg_allow_public.id]
  subnets = [aws_subnet.app_subnets[0].id,aws_subnet.app_subnets[1].id]

  tags = {
    name = "${var.appname}-lb"
    appname = var.appname
  }


  access_logs {
    bucket = data.aws_ssm_parameter.accesslogbucket.value
    prefix = "${var.appname}-lb"
    enabled = true
  }

}


#Elastic IP for load balancer
resource "aws_eip" "lb_eip" {
  vpc = true
  tags = {
    name = "${var.appname}-eip"
    appname = var.appname
    type = "eip"
  }
}

# LB listener

resource "aws_lb_listener" "app-lb_listner" {
  load_balancer_arn = aws_lb.app-lb.arn
  port              = "80"
  protocol          = "HTTP"

resource "aws_lb_listener" "app-lb_listner" {
  load_balancer_arn = aws_lb.app-lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2021-06"
  certificate_arn   = "arn:aws:iam::#"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.app-lb-tg.arn
  }
}

#ReDirection

resource "aws_lb_listener" "app-lb_listne" {
  load_balancer_arn = aws_lb.app-lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

#LB target group 
resource "aws_lb_target_group" "app-lb-tg" {
  name     = "${var.appname}-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.app_vpc.id

  stickiness {
    type = "lb_cookie"
    cookie_duration = 20 ## sec
    enabled = true
  }

  health_check {
    enabled = true
    interval = 10  ## 10 sec 
    path = "/"
    protocol = "HTTP"
    timeout = 8
    healthy_threshold = 3
    unhealthy_threshold = 3

  }
}



resource "aws_s3_bucket" "b" {
  bucket = "accesslogbucket"
  acl    = "private"

  tags = {
    Name = "My bucket"
  }
}

locals {
  s3_origin_id = "myS3Origin"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  aliases = ["mysite.example.com", "yoursite.example.com"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

output "DNS_public_link" {  
    value = aws_lb.app-lb.dns_name
}

}