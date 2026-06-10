resource "aws_security_group_rule" "fix_alert-001" {
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = var.security_group_id
}