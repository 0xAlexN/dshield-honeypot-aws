terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -------------------------------------------------------------------
# Data
# -------------------------------------------------------------------
data "aws_ami" "debian" {
  most_recent = true
  owners      = ["136693071363"] # Debian official

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# -------------------------------------------------------------------
# Networking — dedicated VPC to isolate the honeypot
# -------------------------------------------------------------------
resource "aws_vpc" "honeypot" {
  cidr_block           = "10.42.0.0/24"
  enable_dns_hostnames = true

  tags = { Name = "dshield-honeypot-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeypot.id
  tags   = { Name = "dshield-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = "10.42.0.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "dshield-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.honeypot.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "dshield-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# -------------------------------------------------------------------
# Security Group
# DShield ports: SSH decoy (22), Telnet decoy (23), HTTP decoy (80)
# Admin SSH on non-standard port, restricted to your IP
# Egress unrestricted: required for log upload to SANS ISC
# -------------------------------------------------------------------
resource "aws_security_group" "honeypot" {
  name        = "dshield-honeypot-sg"
  description = "DShield honeypot inbound rules"
  vpc_id      = aws_vpc.honeypot.id

  ingress {
    description = "Admin SSH - restricted to operator IP"
    from_port   = 12222
    to_port     = 12222
    protocol    = "tcp"
    cidr_blocks = ["${var.admin_ip}/32"]
  }

  ingress {
    description = "SSH decoy"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Telnet decoy"
    from_port   = 23
    to_port     = 23
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP decoy"
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

  tags = { Name = "dshield-honeypot-sg" }
}

# -------------------------------------------------------------------
# Key Pair
# -------------------------------------------------------------------
resource "aws_key_pair" "honeypot" {
  key_name   = "dshield-key"
  public_key = var.ssh_public_key
}

# -------------------------------------------------------------------
# EC2 Instance
# -------------------------------------------------------------------
resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.debian.id
  instance_type          = "t3.nano"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  key_name               = aws_key_pair.honeypot.key_name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/cloud-init.sh", {
    dshield_email  = var.dshield_email
    dshield_apikey = var.dshield_apikey
    admin_ssh_port = 12222
    admin_ip       = var.admin_ip
  })

  tags = {
    Name    = "dshield-honeypot"
    Project = "dshield"
  }
}

# -------------------------------------------------------------------
# Elastic IP — fixed public IP required for SANS ISC reporting
# -------------------------------------------------------------------
resource "aws_eip" "honeypot" {
  instance = aws_instance.honeypot.id
  domain   = "vpc"
  tags     = { Name = "dshield-eip" }
}
