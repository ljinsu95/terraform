output "hostname" {
  value = "${var.prefix}.${var.aws_hostingzone}"
}