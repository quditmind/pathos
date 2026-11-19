# Example shop infrastructure (test fixture).
resource "aws_db_instance" "shop" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
}

resource "aws_secretsmanager_secret" "shop_db" {
  name = "shop-db"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
