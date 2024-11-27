module "eks" {
  source = "./eks"

  prefix                = var.prefix
  security_group_ids    = ["${aws_security_group.all.id}"]
  subnet_ids            = aws_subnet.main.*.id
  pem_key_name          = var.pem_key_name
  AWS_ACCESS_KEY_ID     = var.AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY = var.AWS_SECRET_ACCESS_KEY
  aws_region            = var.aws_region
}
