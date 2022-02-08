#Que3 : Creating RDS 
#1..aws_db_instance 
#2 .aws_db_instance_role_association 
#3 .aws_db_option_group 
#4 .aws_db_parameter_group 
#5 .aws_db_proxy_endpoint
#6 .aws_db_security_group 
#7 .aws_db_snapshot 
#8 .aws_db_subnet_group 

provider "aws" {
    region = "ap-south-1"
    access_key = "AKIAVVY4VBOFTQEKYINA"
    secret_key = "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"
}

#create VPC and subnet
resource "aws_vpc" "info_vpc" {
  cidr_block = "172.16.0.0/16"
  enable_dns_support = "true"
  enable_dns_hostnames = "true"
  enable_classiclink = "false"
  
  tags = {
    Name = "info-myvpc"
  }
}

#internet GW
resource "aws_internet_gateway" "main_gw" {
  vpc_id = aws_vpc.info_vpc.id

  tags = {
    name = "maingw"
  } 
}

#route table
resource "aws_route_table" "main_rt" {
  vpc_id = aws_vpc.info_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.main_gw.id}"
  }
  tags = {
    Name = "main_public-1"
  } 
}

#route assosciate public
resource "aws_route_table_association" "main_public-1a" {
  subnet_id = "${aws_subnet.subnetpub1.id}"
  route_table_id = "${aws_route_table.main_rt.id}" 
}

# create subnet
resource "aws_subnet"  "subnetpub1" {
  vpc_id            = aws_vpc.info_vpc.id
  cidr_block        = "172.16.10.0/23"
  map_public_ip_on_launch = "true"
  availability_zone = "ap-south-1a"

  tags = {
    Name = "myinfo_sub_1"
  }
}

resource "aws_subnet"  "subnetpub2" {
  vpc_id            = aws_vpc.info_vpc.id
  cidr_block        = "172.16.12.0/23"
  map_public_ip_on_launch = "true"
  availability_zone = "ap-south-1b"

  tags = {
    Name = "myinfo_sub_2"
  }
}

#create instance for connection

resource "aws_instance" "terradb" {
    ami = "ami-08ee6644906ff4d6c"
    instance_type = "t2.micro"
    availability_zone = "ap-south-1a"
    key_name = "terakey"
    subnet_id = "${aws_subnet.subnetpub1.id}"
    vpc_security_group_ids =  [aws_security_group.db.id]
    
    user_data = <<-EOF
                #!/bin/bash
                sudo apt update -y
                wget -c https://dev.mysql.com/get/mysql-apt-config_0.8.11-1_all.deb
                sudo dpkg -i mysql-apt-config_0.8.11-1_all.deb
                sudo apt-get update
                sudo apt-get install mysql-server
                EOF
    tags = {
    Name = "terraconnect-instance"
  }
}

output "instance" {
    value = "${aws_instance.terradb.public_ip}"
}

#creat IAM role and policy
resource "aws_iam_role_policy" "rds_policy" {
  name = "rds_policy"
  role = "${aws_iam_role.rds_role.id}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:*",
          "rds:*",
          "rds-db:connect"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
resource "aws_iam_role_policy" "awsrdspolicy" {
  name = "awsrdspolicy"
  role = "${aws_iam_role.rds_role.id}"
  policy = "${file("AwsRDSpolicy.json")}"
}

resource "aws_iam_role" "rds_role" {
  name = "rds_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement : [
      {
        "Action" : "sts:AssumeRole"
        "Effect" : "Allow"
        "Sid"    : ""
        "Principal" : {
          "Service" : "rds.amazonaws.com"
        }
      },
    ]
  })
}

#1.aws_db_instance 

resource "aws_db_instance" "default" {
  allocated_storage    = 20
  storage_type		   = "gp2"
  engine               = "mysql"
  engine_version       = "8.0.27"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "root"
  password             = "root12345"
  parameter_group_name = "mysql-pg"
  db_subnet_group_name = aws_db_subnet_group.db_subnet.name
  vpc_security_group_ids = [aws_security_group.db.id]
  backup_retention_period = 0
  availability_zone    = aws_subnet.subnetpub1.availability_zone
  skip_final_snapshot  = true
}

output "end_point" {
	value = aws_db_instance.default.endpoint
	}

# 2 .aws_db_instance_role_association 
resource "aws_db_instance_role_association" "dbrole" {
  db_instance_identifier = aws_db_instance.default.id
  feature_name           = "DB_INTEGRATION"
  role_arn               = "${aws_iam_role.rds_role.arn}"
}

# 3 .aws_db_option_group 

resource "aws_db_option_group" "mydboption" {
  name                     = "option-group-test-terraform"
  option_group_description = "Terraform Option Group"
  engine_name              = "mysql"
  major_engine_version     = "8.0"
}

# 4 .aws_db_parameter_group 

resource "aws_db_parameter_group" "default" {
	name 	= "mysql-pg"
	family 	= "mysql8.0"
	
	parameter {
		name  = "max_allowed_packet"
		value = "16777216"
		}
	}
	
# 5 .aws_db_proxy_endpoint
resource "aws_secretsmanager_secret" "mysecretdb" {
  name = "mysecretdb"
}

resource "aws_db_proxy" "dbproxy" {
  name                   = "dbproxy"
  debug_logging          = false
  engine_family          = "MYSQL"
  idle_client_timeout    = 1800
  require_tls            = true
  role_arn               = "${aws_iam_role.rds_role.arn}"
  vpc_security_group_ids = [aws_security_group.db.id]
  vpc_subnet_ids         = [aws_subnet.subnetpub1.id, aws_subnet.subnetpub2.id]

  auth {
    auth_scheme = "SECRETS"
    description = "example"
    iam_auth    = "DISABLED"
    secret_arn  = aws_secretsmanager_secret.mysecretdb.arn
  }

  tags = {
    Name = "dbpro"
    Key  = "value"
  }
}

resource "aws_db_proxy_endpoint" "proxyendpoint" {
  db_proxy_name          = aws_db_proxy.dbproxy.name
  db_proxy_endpoint_name = "proxyendpoint"
  vpc_subnet_ids         = [aws_subnet.subnetpub1.id, aws_subnet.subnetpub2.id]
  target_role            = "READ_ONLY"
}

# 6 .aws db security_group 
resource "aws_security_group" "db" {
    name        = "allow_ssh-db"
    description = "Allow ssh inbound traffic"
    vpc_id      = aws_vpc.info_vpc.id

  ingress {
      description = "DB"
      from_port = 3306
      to_port = 3306
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
      description = "SSH"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]      
  }
  egress {
      from_port = 0
      to_port = 0 
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
      Name = "allow_ssh"
  }
}

# 7 .aws_db_snapshot 
resource "aws_db_snapshot" "test" {
  db_instance_identifier = aws_db_instance.default.id
  db_snapshot_identifier = "testsnapshot1234"
  #snapshot_type = "manual"
}

# 8 .aws_db_subnet_group 
resource "aws_db_subnet_group" "db_subnet" {
	name 		=	"main"
    description = "RDS subnet group"
	subnet_ids	=	[aws_subnet.subnetpub1.id, aws_subnet.subnetpub2.id]
	
	tags = {
		Name = "My DB subnet group"
	}
  }