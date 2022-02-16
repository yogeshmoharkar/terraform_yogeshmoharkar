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
resource "aws_main_route_table_association" "my-route-association" {
  vpc_id         = aws_vpc.info_vpc.id
  route_table_id = aws_route_table.main_rt.id
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
    iam_instance_profile = "${aws_iam_instance_profile.ec2_profile.id}"
    
    user_data = <<-EOF
                #!/bin/bash
                sudo apt update -y
                wget -c https://dev.mysql.com/get/mysql-apt-config_0.8.11-1_all.deb
                sudo dpkg -i mysql-apt-config_0.8.11-1_all.deb
                sudo apt-get update
                EOF
    tags = {
    Name = "terraconnect-instance"
  }
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "db-ec2-profile"
  role = "${aws_iam_role.rds_role.name}"
}

output "instance_public_ip" {
    description = "Public IP of EC2 instance"
    value = "${aws_instance.terradb.public_ip}"
}
output "instance_id" {
    description = "ID of the EC2 instance"
    value = "${aws_instance.terradb.id}"
}

#1.aws_db_instance 

resource "aws_db_instance" "my-rds-db" {
  identifier              = "my-rds-db"
  allocated_storage       = 20
  #max_allocated_storage  = 30
  storage_type		        = "gp2"
  engine                  = "mysql"
  engine_version          = "8.0.27"
  instance_class          = "db.t2.micro"
  port                    = "3306"
  name                    = "mydb"
  username                = "root"
  password                = "root12345"
  parameter_group_name    = "mysql-pg1"
  option_group_name       = "option-group-test-terraform"
  db_subnet_group_name    = aws_db_subnet_group.db_subnet.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  maintenance_window      = "sat:07:01-sat:08:00"
  backup_window           = "06:01-07:00"
  backup_retention_period = 0         # store upto 35 days (by default select 7)
  delete_automated_backups = true     # remove automated backups immediately after the DB instance is deleted
  availability_zone       = aws_subnet.subnetpub1.availability_zone
  multi_az                = false
  skip_final_snapshot     = true
  publicly_accessible     = true
  deletion_protection     = false 
  auto_minor_version_upgrade  = false  #auto minor version upgrades for the database like 8.0.3 to 8.0.23
  allow_major_version_upgrade = false  #upgrading the major version of an engine must be set to true.
  #apply_immediately      = true       #To make the changes take effect immediately
  storage_encrypted       = false      #without AWS KMS encryption key you can't share encrypted snapshot

  tags = {
    name = "Mysql-RDS-instance"
  }
}

output "end_point" {
	value = aws_db_instance.my-rds-db.endpoint
	}
output "rds_address" {
  value = aws_db_instance.my-rds-db.address
}

#2 .aws_db_instance_role_association 
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

# 3 .aws_db_option_group 

resource "aws_db_option_group" "mydboption" {
  name                     = "option-group-test-terraform"
  option_group_description = "Terraform Option Group"
  engine_name              = "mysql"
  major_engine_version     = "8.0"

}


# 4 .aws_db_parameter_group 

resource "aws_db_parameter_group" "rds-db-paragp" {
	name 	= "mysql-pg1"
	family 	= "mysql8.0"
	
	parameter {
		name  = "max_allowed_packet"
		value = "16777216"
    apply_method = "immediate"
		}

  parameter {
    name         = "character_set_client"
    value        = var.character_set
    apply_method = "immediate"
  }
  
  parameter {
    name         = "time_zone"
    value        = var.time_zone
    apply_method = "immediate"
  }
}
	
# 5 .aws_db_proxy_endpoint
resource "aws_secretsmanager_secret" "mysecret-db-1" {
  name = "mysecret-db-1"
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
    secret_arn  = aws_secretsmanager_secret.mysecret-db-1.arn
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
  db_instance_identifier = aws_db_instance.my-rds-db.id
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
