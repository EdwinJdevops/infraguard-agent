resource "aws_vpc_security_group_ingress_rule" "ssh_public" {
  security_group_id = "sg-1234567890abcdef0"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

