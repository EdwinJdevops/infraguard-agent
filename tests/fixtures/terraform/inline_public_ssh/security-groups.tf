resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"
  vpc_id      = "vpc-123456"

  ingress {
    description = "public ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

