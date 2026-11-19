terraform {
  required_version = ">= 1.5"
}

provider "aws" {
  region = "eu-west-1"
}

variable "unused" {
  default = "x"
}

resource "aws_security_group" "ssh" {
  name = "ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "pathos-fixture-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

resource "aws_db_instance" "db" {
  identifier          = "fixture"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  publicly_accessible = true
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t1.2xlarge"
}
