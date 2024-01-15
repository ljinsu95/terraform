### Provider
provider "aws" {
  ## AWS Region
  region     = var.aws_region
  access_key = var.AWS_ACCESS_KEY_ID
  secret_key = var.AWS_SECRET_ACCESS_KEY
}
##########################
### VPC Resource START ###
##########################
## VPC
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc
resource "aws_vpc" "fdo" {
  cidr_block = var.aws_vpc_cidr

  instance_tenancy     = "default"
  enable_dns_hostnames = true # DNS 호스트 네임 활성화 여부 RDS publicly_accessible 활성화시 필요

  tags = {
    Name = "${var.prefix}_vpc"
  }
}

## Subnet
## https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet
resource "aws_subnet" "fdo" {
  count = length(var.map_subnet_az[var.aws_region]) # 지정한 AZ 수 만큼 Subnet 생성

  vpc_id = aws_vpc.fdo.id

  availability_zone = var.map_subnet_az[var.aws_region][count.index].availability_zone
  cidr_block        = var.map_subnet_az[var.aws_region][count.index].cidr_block

  map_public_ip_on_launch = true # 퍼블릭 IP 주소 자동 할당

  tags = {
    Name = "${var.prefix}_subnet_public${tonumber(count.index) + 1}-${var.map_subnet_az[var.aws_region][count.index].availability_zone}"
  }
}

## Internet Gateway
resource "aws_internet_gateway" "fdo" {
  vpc_id = aws_vpc.fdo.id

  tags = {
    Name = "${var.prefix}_igw"
  }

}

## Route Table
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table
resource "aws_route_table" "fdo" {
  vpc_id = aws_vpc.fdo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fdo.id
  }

  tags = {
    Name = "${var.prefix}_rtb_public"
  }
}

## Route Table 연결
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association
resource "aws_route_table_association" "rtb_sn" {
  count          = length(var.map_subnet_az[var.aws_region])
  subnet_id      = aws_subnet.fdo[count.index].id
  route_table_id = aws_route_table.fdo.id
}

## Security Group
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
resource "aws_security_group" "all" {
  name   = "${var.prefix}-All-allowed"
  vpc_id = aws_vpc.fdo.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}_sg_All_allowed"
  }
}

// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl
## Network ACL
resource "aws_network_acl" "fdo" {
  vpc_id = aws_vpc.fdo.id

  egress {
    protocol   = "all"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "all"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "${var.prefix}-acl"
  }
}

## Network ACL 연결
resource "aws_network_acl_association" "fdo" {
  count          = length(var.map_subnet_az[var.aws_region])
  network_acl_id = aws_network_acl.fdo.id
  subnet_id      = aws_subnet.fdo[count.index].id
}
########################
### VPC Resource END ###
########################

##########################
### RDS Resource START ###
##########################

## RDS DB Subnet Group 구성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_subnet_group
resource "aws_db_subnet_group" "fdo" {
  name       = "${var.prefix}_db_subnet_group" # aws_db_instance.db_subnet_group_name에서 사용
  subnet_ids = aws_subnet.fdo.*.id

  tags = {
    Name = "${var.prefix}_db_subnet_group"
  }
}

## RDS 구성 (RDS Aurora 사용 시 aws_rds_cluster 리소스 구성)
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance
resource "aws_db_instance" "fdo" {
  identifier = replace("${var.prefix}_postgre", "_", "-") # RDS 데이터베이스 식별자 명 (언더바 사용 불가)

  engine                      = "postgres" # 지원 하는 값은 https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html#API_CreateDBInstance_RequestParameters - Engine 확인
  engine_version              = "15"       # 지원하는 버전 목록 https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html
  allow_major_version_upgrade = false
  auto_minor_version_upgrade  = false

  db_name  = "${var.prefix}_database"
  username = "postgres"
  password = "insideinfo"

  instance_class         = "db.t3.micro" # RDS 인스턴스의 인스턴스 유형
  allocated_storage      = 10
  availability_zone      = var.map_subnet_az[var.aws_region][0].availability_zone
  multi_az               = false # 다중 AZ 여부
  db_subnet_group_name   = aws_db_subnet_group.fdo.name
  publicly_accessible    = true # public access 가능 여부
  skip_final_snapshot    = true # DB 인스턴스가 삭제되기 전 최종 DB 스냅샷 생성 스킵 여부
  vpc_security_group_ids = [aws_security_group.all.id]
}
########################
### RDS Resource END ###
########################

##################################
### ElastiCache Resource START ###
##################################

## redis subnet group 구성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_subnet_group
resource "aws_elasticache_subnet_group" "fdo" {
  name       = replace("${var.prefix}_redis_subnet_group", "_", "-") # 언더바 사용 불가
  subnet_ids = aws_subnet.fdo.*.id
  tags = {
    Name = "${var.prefix}_redis_subnet_group"
  }
}

## redis parameter group 구성
# resource "aws_elasticache_parameter_group" "fdo" {
#   name   = replace("${var.prefix}_redis_parameter_group", "_", "-") # 언더바 사용 불가
#   family = "redis7"
# }

## redis parameter group 구성
resource "aws_elasticache_parameter_group" "fdo_redis_cluster" {
  name   = replace("${var.prefix}_redis_cluster_parameter_group", "_", "-") # 언더바 사용 불가
  family = "redis7"
}


## redis cluster 구성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster
resource "aws_elasticache_cluster" "fdo" {
  cluster_id                 = lower(replace("${var.prefix}_redis", "_", "-")) # redis cluster 명 (소문자 및 하이픈 만 지원)
  engine                     = "redis"
  node_type                  = "cache.t4g.micro"
  num_cache_nodes            = 1                                                      # redis node 갯수
  parameter_group_name       = aws_elasticache_parameter_group.fdo_redis_cluster.name # 파라미터 구성 명
  engine_version             = "7.1"                                                  # redis 버전
  auto_minor_version_upgrade = false
  port                       = 6379
  security_group_ids         = [aws_security_group.all.id]           # 보안 그룹 id 리스트
  subnet_group_name          = aws_elasticache_subnet_group.fdo.name # redis subnet group 명
}

## redis 복제
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group
# resource "aws_elasticache_replication_group" "name" {
#   automatic_failover_enabled = true
#   engine                     = "redis"
#   engine_version             = "7.1"
#   auto_minor_version_upgrade = false
#   # preferred_cache_cluster_azs = [var.map_subnet_az[var.aws_region][0].availability_zone]
#   preferred_cache_cluster_azs = flatten([for az in var.map_subnet_az[var.aws_region] : az.availability_zone])
#   replication_group_id        = lower(replace("${var.prefix}_redis_rep_group", "_", "-"))
#   description                 = "example description"
#   node_type                   = "cache.t4g.micro"
#   multi_az_enabled            = false
#   num_cache_clusters          = 2
#   parameter_group_name        = aws_elasticache_parameter_group.fdo.name
#   subnet_group_name           = aws_elasticache_subnet_group.fdo.name
#   port                        = 6379
# }

################################
### ElastiCache Resource END ###
################################

##########################
### ACM Resource START ###
##########################
## TLS private_key.pem 생성
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key.html
resource "tls_private_key" "fdo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

## TLS cert.pem 생성
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/self_signed_cert
resource "tls_self_signed_cert" "fdo" {
  private_key_pem = tls_private_key.fdo.private_key_pem
  dns_names       = ["${var.prefix}.${var.aws_hostingzone}"]

  # 인증서 요청 대상 지정
  subject {
    country             = "KR"
    province            = "Seoul"
    locality            = "Gang-Nam"
    organization        = "Insideinfo, Inc"
    organizational_unit = "Engineering"
    common_name         = "${var.prefix}.${var.aws_hostingzone}" # DNS 명
  }

  validity_period_hours = 24 * 30 # 발급 후 인증서가 유효한 상태로 유지되는 시간

  # 발급된 인증서에 허용된 키 사용 목록
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

## AWS ACM 인증서 가져오기로 등록
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate
resource "aws_acm_certificate" "cert" {
  private_key       = tls_private_key.fdo.private_key_pem # private_key.pem
  certificate_body  = tls_self_signed_cert.fdo.cert_pem   # cert.pem
  certificate_chain = tls_self_signed_cert.fdo.cert_pem   # 인증서 체인은 cert.pem과 동일한 키 사용
}

########################
### ACM Resource END ###
########################

######################
### ALB 구성 START ###
######################

## 대상 그룹 생성 (HTTPS)
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group
resource "aws_lb_target_group" "fdo_https" {
  target_type = "instance"
  name        = replace("${var.prefix}_lb_tg_443", "_", "-")
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.fdo.id

  # heath check 설정
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group#health_check
  health_check {
    enabled  = true
    protocol = "HTTPS"
    path     = "/_health_check"
    matcher  = "200-399"
  }
}

## 대상 그룹 생성 (HTTP)
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group
resource "aws_lb_target_group" "fdo_http" {
  target_type = "instance"
  name        = replace("${var.prefix}_lb_tg_8800", "_", "-")
  port        = 8800
  protocol    = "HTTP"
  vpc_id      = aws_vpc.fdo.id

  # heath check 설정
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group#health_check
  health_check {
    enabled  = true
    protocol = "HTTP"
    path     = "/"
    matcher  = "200-399"
  }
}

## ALB 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb
resource "aws_lb" "fdo" {
  name               = replace("${var.prefix}_alb", "_", "-")
  internal           = false # 내부망 여부
  load_balancer_type = "application"
  security_groups    = [aws_security_group.all.id]
  subnets            = aws_subnet.fdo.*.id

  enable_deletion_protection = false # 삭제 보호 활성화 (true인 경우 Terraform이 로드밸런스 삭제 불가)
}

## ALB Listener(HTTPS) 추가
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
resource "aws_lb_listener" "fdo_https" {
  load_balancer_arn = aws_lb.fdo.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06" # SSL 정책 명 https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies
  certificate_arn   = aws_acm_certificate.cert.arn          # SSL 서버 인증서의 ARN

  default_action {
    type             = "forward"                         # forward : 대상 그룹으로 전달
    target_group_arn = aws_lb_target_group.fdo_https.arn # 트래픽을 라우팅할 대상 그룹의 ARN
  }
}

## ALB Listener(HTTP) 추가
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
resource "aws_lb_listener" "fdo_http" {
  load_balancer_arn = aws_lb.fdo.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect" # redirect : URL로 리디렉트

    # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener#redirect
    redirect {
      protocol    = "HTTPS"
      port        = 443
      status_code = "HTTP_301" # 영구 이동
    }
  }
}

####################
### ALB 구성 END ###
####################

###########################
### Route 53 구성 START ###
###########################

## Route 53 호스팅 영역 조회
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/route53_zone
data "aws_route53_zone" "selected" {
  name = var.aws_hostingzone # 호스팅 영역 이름으로 데이터 조회
}

## Route 53 레코드 추가
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record
resource "aws_route53_record" "fdo" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "${var.prefix}.${var.aws_hostingzone}" # 레코드 이름
  type    = "A"
  alias {
    name                   = aws_lb.fdo.dns_name # LB DNS 명
    zone_id                = aws_lb.fdo.zone_id  # LB 호스팅 영역 ID
    evaluate_target_health = false               # 대상 상태 평가
  }
}

#########################
### Route 53 구성 END ###
#########################

############################
### S3 Bucket 구성 Start ###
############################
# S3 Bucket에 TLS PEM KEY와 TFE License를 저장해두고, 시작 템플릿 User Data에서 사용
## S3 Bucket 추가
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
resource "aws_s3_bucket" "fdo" {
  bucket = lower(replace("${var.prefix}_bucket", "_", "-"))
}

## S3 Bucket 파일(terraform.hclic) 업로드
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object
resource "aws_s3_object" "license" {
  bucket  = aws_s3_bucket.fdo.bucket
  key     = "terraform/tfe_license/terraform.hclic"
  content = var.tfe_license
}

## S3 Bucket 파일(cert.pem) 업로드
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object
resource "aws_s3_object" "cert_pem" {
  bucket  = aws_s3_bucket.fdo.bucket
  key     = "terraform/certs/cert.pem"
  content = tls_self_signed_cert.fdo.cert_pem
}

## S3 Bucket 파일(key.pem) 업로드
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object
resource "aws_s3_object" "private_key_pem" {
  bucket  = aws_s3_bucket.fdo.bucket
  key     = "terraform/certs/key.pem"
  content = tls_private_key.fdo.private_key_pem
}

## S3 Bucket 파일(bundle.pem) 업로드
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object
resource "aws_s3_object" "bundle_pem" {
  bucket  = aws_s3_bucket.fdo.bucket
  key     = "terraform/certs/bundle.pem"
  content = tls_self_signed_cert.fdo.cert_pem
}

##########################
### S3 Bucket 구성 END ###
##########################

######################
### IAM 구성 START ###
######################

## IAM Policy 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy
resource "aws_iam_policy" "s3" {
  name        = "${var.prefix}_S3_policy"
  description = "${var.prefix}_S3_policy"
  path        = "/"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetBucketLocation"
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.fdo.bucket}/*",
          "arn:aws:s3:::${aws_s3_bucket.fdo.bucket}"
        ]
      },
      {
        Action = [
          "s3:ListAllMyBuckets"
        ]
        Effect   = "Allow"
        Resource = "*"

      },
    ]
  })
}

## IAM Role 신뢰 관계 정책 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
data "aws_iam_policy_document" "ec2_trust_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

## IAM Role 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role
resource "aws_iam_role" "fdo" {
  name                = "${var.prefix}_role"
  assume_role_policy  = data.aws_iam_policy_document.ec2_trust_policy.json
  managed_policy_arns = [aws_iam_policy.s3.arn]
}

## IAM instance profile 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile
resource "aws_iam_instance_profile" "fdo" {
  name = "${var.prefix}_profile"
  role = aws_iam_role.fdo.name
}

####################
### IAM 구성 END ###
####################

#############################
### 시작 템플릿 생성 START ###
#############################

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

## user data template 설정
data "template_file" "user_data" {
  template = file("${path.module}/user_data.tpl")

  vars = {
    COMPOSE_PROJECT_NAME = "$${COMPOSE_PROJECT_NAME}"
    HOME                 = "/home/ec2-user"
    BUCKET               = aws_s3_bucket.fdo.bucket
    TFE_HOSTNAME         = "${var.prefix}.${var.aws_hostingzone}"
    TFE_IACT_SUBNETS = join(",", flatten([
      for az in var.map_subnet_az[var.aws_region] : az.cidr_block
    ]))
    TFE_DATABASE_USER            = aws_db_instance.fdo.username
    TFE_DATABASE_PASSWORD        = aws_db_instance.fdo.password
    TFE_DATABASE_HOST            = aws_db_instance.fdo.endpoint
    TFE_DATABASE_NAME            = aws_db_instance.fdo.db_name
    TFE_OBJECT_STORAGE_S3_REGION = var.aws_region
    TFE_OBJECT_STORAGE_S3_BUCKET = aws_s3_bucket.fdo.bucket
    ## todo : redis node hostname 으로 변경 필요
    # TFE_REDIS_HOST               = "${aws_elasticache_replication_group.name.primary_endpoint_address}:${aws_elasticache_replication_group.name.port}"
    TFE_REDIS_HOST = "${aws_elasticache_cluster.fdo.cache_nodes[0]["address"]}:${aws_elasticache_cluster.fdo.cache_nodes[0]["port"]}"
  }
}

## 시작 템플릿 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template
resource "aws_launch_template" "fdo" {
  name                   = "${var.prefix}_template"
  update_default_version = true
  description            = "테라폼으로 자동 생성한 시작 템플릿"

  # 인스턴스 세부 정보
  instance_type = "t3.small"
  image_id      = data.aws_ami.amazon_linux_2.image_id
  # vpc_security_group_ids = [aws_security_group.all.id]
  key_name = var.pem_key_name

  # 스토리지
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template#block-devices
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      delete_on_termination = true  # 종료 시 삭제
      volume_type           = "gp3" # 볼륨 유형
      encrypted             = false # 암호화됨
      iops                  = 3000  # IOPS
      throughput            = 125   # 처리량
      volume_size           = 100   # 크기
    }
  }

  # 리소스 태그
  tag_specifications {
    resource_type = "instance"
    tags = {
      "Name" = "${var.prefix}_server"
    }
  }

  # 네트워크 인터페이스
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template#network-interfaces
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.all.id]
  }

  iam_instance_profile {
    arn = aws_iam_instance_profile.fdo.arn
  }

  user_data = base64encode(data.template_file.user_data.rendered)
}

###########################
### 시작 템플릿 생성 END ###
###########################



### todo... ASG 생성
## Auto Scale Group 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group
resource "aws_autoscaling_group" "fdo" {
  name = "${var.prefix}_asg"

  # 1. 시작 템플릿 또는 구성 선택
  # launch_configuration = aws_launch_template.fdo.name
  launch_template {
    name    = aws_launch_template.fdo.name
    version = "$Default" # 사용할 템플릿 버전 $Default, $Latest 사용 가능
  }

  # 2. 인스턴스 시작 옵션 선택
  vpc_zone_identifier = aws_subnet.fdo.*.id

  # 3. 고급 옵션 구성
  target_group_arns = [aws_lb_target_group.fdo_http.arn, aws_lb_target_group.fdo_https.arn] # ALB 대상 그룹 선택

  # 4. 그룹 크기 및 크기 조정 구성
  max_size = 1
  min_size = 1
}
