# # terraform {
# #   required_providers {
# #     # AWS Provider 버전 제약 조건
# #     aws = {
# #       source  = "hashicorp/aws"
# #       version = "~> 5.0"
# #     }
# #   }
# # }

# terraform {
#   required_providers {
#     # AWS Provider 버전 제약 조건
#     aws = {
#     #   source  = "hashicorp/aws" # provider source 주소
#       version = "~> 5.0"        # 5.0 버전 이상 요구
#     }
#   }
# }

# # AWS Provider 구성
# provider "aws" {
#   region = "us-east-1"
# }

# # AWS VPC 생성
# resource "aws_vpc" "example" {
#   cidr_block = "10.0.0.0/16"
# }

# # ## VPC
# # resource "aws_vpc" "main" {
# #   cidr_block = var.aws_vpc_cidr

# #   enable_dns_hostnames = true # DNS 호스트 네임 활성화 여부 RDS publicly_accessible 활성화시 필요
# # }

# # # : 한 줄 주석
# # // : 한 줄 주석
# # /* 여러 줄 주석 */
# # resource "aws_subnet" "main" {
# #   count = length(var.map_subnet_az[var.aws_region]) # 지정한 AZ 수 만큼 Subnet 생성

# #   vpc_id = aws_vpc.main.id // vpc id 지정

# #   /*
# #   availability_zone = var.map_subnet_az[var.aws_region][count.index].availability_zone
# #   cidr_block        = cidrsubnet(var.aws_vpc_cidr, 8, count.index) # cidr 블록 지정
# #   map_public_ip_on_launch = true # 퍼블릭 IP 주소 자동 할당
# #   */
# # }

# # ## variable
# # variable "prefix" {
# #   default     = "terraform"
# #   description = "prefix"
# # }

# # ## Route Table
# # resource "aws_route_table" "main" {
# #   vpc_id = aws_vpc.main.id
# #   route {
# #     cidr_block = "0.0.0.0/0"
# #     gateway_id = aws_internet_gateway.main.id
# #   }

# #   tags = {
# #     Name = "${var.prefix}_rtb_public"
# #   }
# # }

# # sad

# # # Block
# # <BLOCK TYPE> "<BLOCK LABEL>" "<BLOCK LABEL>" {
# #   # Block body
# #   <IDENTIFIER> = <EXPRESSION> # Argument
# # }
