# 참고 : https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster
# EKS Cluster
resource "aws_eks_cluster" "eks_cluster" {
  name     = "${var.prefix}_eks_cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = var.security_group_ids
    subnet_ids              = var.subnet_ids
  }

  # Option
  version = var.k8s_version
}

# 참고 : https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_node_group
# EKS Node Group
resource "aws_eks_node_group" "eks_node" {
  cluster_name  = aws_eks_cluster.eks_cluster.name
  node_role_arn = aws_iam_role.eks_worker_node_role.arn
  subnet_ids    = var.subnet_ids

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 1
  }

  # Option
  node_group_name = "${var.prefix}_eks_node"
  instance_types  = ["t3.medium"]
  labels = {
    "Name" = "${var.prefix}_eks_node"
  }
  tags = {
    "Name" = "${var.prefix}_eks_node"
  }

  remote_access {
    ec2_ssh_key               = var.pem_key_name
    source_security_group_ids = var.security_group_ids
  }

  update_config {
    max_unavailable = 1
  }

  version = var.k8s_version
}


# data "aws_autoscaling_group" "eks" {
#   name = data.aws_eks_node_group.example.resources[0].autoscaling_groups[0].name
# }
# output "eks_autoscaling_group" {
#   value = data.aws_autoscaling_group.eks.id
# }
# import {
#   to = aws_autoscaling_group.test
#   id = data.aws_autoscaling_group.eks.id
# }
# resource "aws_autoscaling_group" "test" {
#   max_size = 2
#   min_size = 1
#   tag {
#     key = "Name"
#     value = "test"
#     propagate_at_launch = true
#   }
# }




### EC2 Cluster Controller Server 생성
## Amazon Linux 2 AMI 조회
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami
data "aws_ami" "amazon_linux_2" {
  most_recent = true

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  owners = ["amazon"]
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance
resource "aws_instance" "eks_controller" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t2.micro"
  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = var.security_group_ids
  key_name               = var.pem_key_name

  tags = {
    Name = "${var.prefix}_eks_controller"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = "10"
    tags = {
      Name = "${var.prefix}_volume"
    }
  }

  ## EKS Cluster 생성 후 EKS Controller 서버가 생성 됨
  depends_on = [aws_eks_cluster.eks_cluster]

  # https://developer.hashicorp.com/terraform/language/resources/provisioners/remote-exec
  provisioner "remote-exec" {
    inline = [
      "cd /home/ec2-user",
      "curl \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o \"awscliv2.zip\"",
      "unzip awscliv2.zip",
      "sudo ./aws/install --bin-dir /usr/bin --install-dir /usr/aws-cli --update",
      "aws configure set aws_access_key_id     '${var.AWS_ACCESS_KEY_ID}'",
      "aws configure set aws_secret_access_key '${var.AWS_SECRET_ACCESS_KEY}'",
      "aws configure set region                '${var.aws_region}'",
      "mkdir -p ~/.kube",
      "sudo curl -o kubectl https://s3.us-west-2.amazonaws.com/amazon-eks/1.23.7/2022-06-29/bin/linux/amd64/kubectl",
      "sudo chmod +x ./kubectl",
      "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
      "curl --silent --location \"https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz\" | tar xz -C /tmp",
      "sudo mv /tmp/eksctl /usr/local/bin/eksctl",
      "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.eks_cluster.name}"
    ]
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("${path.module}/../file/${var.pem_key_name}.pem")
      host        = aws_instance.eks_controller.public_ip
    }
  }
}
