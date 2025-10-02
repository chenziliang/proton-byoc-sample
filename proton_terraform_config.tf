# Terraform configuration as an alternative to Go implementation
# This provides Infrastructure as Code approach for Proton BYOC deployment

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Timeplus Proton BYOC"
      ManagedBy   = "Terraform"
      Cluster     = var.cluster_name
      Environment = var.environment
    }
  }
}

# Variables for configurable deployment
variable "aws_region" {
  description = "AWS region for Proton deployment"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "Name of the Proton cluster"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, production)"
  type        = string
  default     = "production"
}

variable "proton_version" {
  description = "Proton Docker image version"
  type        = string
  default     = "latest"
}

variable "instance_type" {
  description = "EC2 instance type for Proton nodes"
  type        = string
  default     = "c5.2xlarge"
}

variable "instance_count" {
  description = "Number of Proton instances to deploy"
  type        = number
  default     = 3
}

variable "disk_size_gb" {
  description = "EBS volume size in GB"
  type        = number
  default     = 500
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access Proton"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_encryption" {
  description = "Enable encryption at rest for EBS and S3"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

variable "ssh_key_name" {
  description = "SSH key pair name for instance access"
  type        = string
  default     = ""
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Create VPC for Proton cluster
resource "aws_vpc" "proton" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.cluster_name}-proton-vpc"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "proton" {
  vpc_id = aws_vpc.proton.id

  tags = {
    Name = "${var.cluster_name}-proton-igw"
  }
}

# Create public subnets
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.proton.id
  cidr_block              = "10.0.${count.index * 2}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.cluster_name}-proton-public-subnet-${count.index + 1}"
    Type = "public"
  }
}

# Create private subnets
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.proton.id
  cidr_block        = "10.0.${count.index * 2 + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.cluster_name}-proton-private-subnet-${count.index + 1}"
    Type = "private"
  }
}

# Create Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"

  tags = {
    Name = "${var.cluster_name}-proton-nat-eip-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.proton]
}

# Create NAT Gateways
resource "aws_nat_gateway" "proton" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.cluster_name}-proton-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.proton]
}

# Create public route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.proton.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.proton.id
  }

  tags = {
    Name = "${var.cluster_name}-proton-public-rt"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Create private route tables
resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.proton.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.proton[count.index].id
  }

  tags = {
    Name = "${var.cluster_name}-proton-private-rt-${count.index + 1}"
  }
}

# Associate private subnets with private route tables
resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security group for Proton instances
resource "aws_security_group" "proton" {
  name_prefix = "${var.cluster_name}-proton-sg-"
  description = "Security group for Timeplus Proton cluster"
  vpc_id      = aws_vpc.proton.id

  # Proton HTTP interface
  ingress {
    from_port   = 8123
    to_port     = 8123
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "Proton HTTP interface"
  }

  # Proton native TCP interface
  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "Proton native TCP interface"
  }

  # Inter-cluster communication
  ingress {
    from_port = 9009
    to_port   = 9009
    protocol  = "tcp"
    self      = true
    description = "Inter-cluster communication"
  }

  # SSH access (if key specified)
  dynamic "ingress" {
    for_each = var.ssh_key_name != "" ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidr_blocks
      description = "SSH access"
    }
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.cluster_name}-proton-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Security group for load balancer
resource "aws_security_group" "lb" {
  name_prefix = "${var.cluster_name}-proton-lb-sg-"
  description = "Security group for Proton load balancer"
  vpc_id      = aws_vpc.proton.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "HTTP access"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "HTTPS access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.cluster_name}-proton-lb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# S3 bucket for Proton data storage
resource "aws_s3_bucket" "proton_data" {
  bucket_prefix = "${var.cluster_name}-proton-data-"

  tags = {
    Name = "${var.cluster_name}-proton-data"
  }
}

# Enable versioning for data protection
resource "aws_s3_bucket_versioning" "proton_data" {
  bucket = aws_s3_bucket.proton_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "proton_data" {
  count  = var.enable_encryption ? 1 : 0
  bucket = aws_s3_bucket.proton_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle policy for backups
resource "aws_s3_bucket_lifecycle_configuration" "proton_data" {
  bucket = aws_s3_bucket.proton_data.id

  rule {
    id     = "backup-retention"
    status = "Enabled"

    filter {
      prefix = "backups/"
    }

    expiration {
      days = var.backup_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# Block public access to S3 bucket
resource "aws_s3_bucket_public_access_block" "proton_data" {
  bucket = aws_s3_bucket.proton_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM role for Proton EC2 instances
resource "aws_iam_role" "proton_instance" {
  name_prefix = "${var.cluster_name}-proton-instance-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.cluster_name}-proton-instance-role"
  }
}

# IAM policy for S3 access
resource "aws_iam_role_policy" "s3_access" {
  name_prefix = "proton-s3-access-"
  role        = aws_iam_role.proton_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.proton_data.arn,
          "${aws_s3_bucket.proton_data.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "s3:ListAllMyBuckets"
        Resource = "*"
      }
    ]
  })
}

# IAM policy for CloudWatch access
resource "aws_iam_role_policy" "cloudwatch_access" {
  name_prefix = "proton-cloudwatch-access-"
  role        = aws_iam_role.proton_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "proton" {
  name_prefix = "${var.cluster_name}-proton-profile-"
  role        = aws_iam_role.proton_instance.name

  tags = {
    Name = "${var.cluster_name}-proton-instance-profile"
  }
}

# CloudWatch Log Group for Proton logs
resource "aws_cloudwatch_log_group" "proton" {
  name              = "/aws/proton/${var.cluster_name}"
  retention_in_days = 30

  tags = {
    Name = "${var.cluster_name}-proton-logs"
  }
}

# Launch template for Proton instances
resource "aws_launch_template" "proton" {
  name_prefix   = "${var.cluster_name}-proton-lt-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.ssh_key_name != "" ? var.ssh_key_name : null

  iam_instance_profile {
    name = aws_iam_instance_profile.proton.name
  }

  vpc_security_group_ids = [aws_security_group.proton.id]

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.disk_size_gb
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = var.enable_encryption
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    cluster_name   = var.cluster_name
    proton_version = var.proton_version
    s3_bucket      = aws_s3_bucket.proton_data.id
    aws_region     = var.aws_region
  }))

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${var.cluster_name}-proton-instance"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name = "${var.cluster_name}-proton-volume"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for Proton instances
resource "aws_autoscaling_group" "proton" {
  name_prefix         = "${var.cluster_name}-proton-asg-"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.proton.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  min_size            = var.instance_count
  max_size            = var.instance_count * 2
  desired_capacity    = var.instance_count

  launch_template {
    id      = aws_launch_template.proton.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.cluster_name}-proton-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Cluster"
    value               = var.cluster_name
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer
resource "aws_lb" "proton" {
  name_prefix        = "prot-"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false
  enable_http2               = true

  tags = {
    Name = "${var.cluster_name}-proton-lb"
  }
}

# Target group for load balancer
resource "aws_lb_target_group" "proton" {
  name_prefix = "prot-"
  port        = 8123
  protocol    = "HTTP"
  vpc_id      = aws_vpc.proton.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/ping"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.cluster_name}-proton-tg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Load balancer listener
resource "aws_lb_listener" "proton_http" {
  load_balancer_arn = aws_lb.proton.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proton.arn
  }
}

# CloudWatch alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.cluster_name}-proton-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EC2 CPU utilization"
  alarm_actions       = [] # Add SNS topic ARN for notifications

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.proton.name
  }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.cluster_name}-proton-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "Alert when targets are unhealthy"
  alarm_actions       = [] # Add SNS topic ARN for notifications

  dimensions = {
    LoadBalancer = aws_lb.proton.arn_suffix
    TargetGroup  = aws_lb_target_group.proton.arn_suffix
  }
}

# Outputs
output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.proton.dns_name
}

output "load_balancer_url" {
  description = "URL to access Proton cluster"
  value       = "http://${aws_lb.proton.dns_name}"
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for Proton data"
  value       = aws_s3_bucket.proton_data.id
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.proton.id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "security_group_id" {
  description = "ID of the Proton security group"
  value       = aws_security_group.proton.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for Proton logs"
  value       = aws_cloudwatch_log_group.proton.name
}

output "cluster_info" {
  description = "Complete cluster information"
  value = {
    cluster_name  = var.cluster_name
    region        = var.aws_region
    instance_type = var.instance_type
    instance_count = var.instance_count
    load_balancer_dns = aws_lb.proton.dns_name
    s3_bucket = aws_s3_bucket.proton_data.id
  }
}
