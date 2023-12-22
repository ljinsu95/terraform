variable "prefix" {
  default     = "jinsu_tfe_fdo"
  description = "prefix"
}

variable "AWS_ACCESS_KEY_ID" {
  description = "AWS ACCESS KEY"
  sensitive = true
}

variable "AWS_SECRET_ACCESS_KEY" {
  description = "AWS SECRET ACCESS KEY"
  sensitive = true
}

variable "tfe_license" {
  description = "TFE License"
  sensitive = true
}

variable "aws_region" {
  default     = "ca-central-1"
  description = "aws region"
}

### az, cidr 설정
variable "map_subnet_az" {
  type = map(list(object({
    availability_zone = string
    cidr_block        = string
  })))

  default = {
    ## ca-central-1
    "ca-central-1" = [
      {
        availability_zone = "ca-central-1a"
        cidr_block        = "172.170.1.0/24"
      },
      {
        availability_zone = "ca-central-1b"
        cidr_block        = "172.170.2.0/24"
      },
    ],

    ## ap-northeast-2
    "ap-northeast-2" = [
      {
        availability_zone = "ap-northeast-2a"
        cidr_block        = "172.170.11.0/24"
      },
      {
        availability_zone = "ap-northeast-2c"
        cidr_block        = "172.170.12.0/24"
      },
      {
        availability_zone = "ap-northeast-2d"
        cidr_block        = "172.170.13.0/24"
      },
    ]
  }

  description = "Subnet AZ 설정 값 목록"
}

variable "aws_hostingzone" {
  default = "inside-vault.com"
  description = "AWS Route 53에 등록된 호스팅 영역 명"
}

variable "pem_key_name" {
  default = "jinsu"
  description = "AWS PEM KEY 명"
}