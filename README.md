# Timeplus Proton BYOC (Bring Your Own Cloud) - AWS Implementation

## Overview

This implementation provides a complete BYOC (Bring Your Own Cloud) solution for deploying [Timeplus Proton](https://github.com/timeplus-io/proton) on AWS infrastructure. The solution allows customers to run Proton streaming analytics in their own AWS account while maintaining full control over their data and infrastructure.

## Architecture

### Components

1. **VPC Infrastructure**
   - Isolated VPC with public and private subnets across multiple availability zones
   - Internet Gateway for public internet access
   - NAT Gateways for private subnet internet access
   - Security Groups with configurable firewall rules

2. **Compute Layer**
   - EC2 instances running Proton in Docker containers
   - Auto-configured across multiple AZs for high availability
   - Instance profiles with IAM roles for secure AWS service access

3. **Storage Layer**
   - S3 bucket for data storage and backups
   - EBS volumes for local instance storage
   - Encryption at rest (optional)
   - Versioning and lifecycle policies

4. **Load Balancing**
   - Application Load Balancer for traffic distribution
   - Health checks and automatic failover
   - Support for HTTP/HTTPS protocols

5. **Monitoring & Logging**
   - CloudWatch metrics for instance and application monitoring
   - CloudWatch Logs for centralized log aggregation
   - Custom alarms for critical metrics

6. **Security**
   - IAM roles with least-privilege access
   - Security groups with restrictive rules
   - Optional encryption for data at rest and in transit
   - Cross-account roles for SaaS provider management

## Prerequisites

### AWS Account Requirements

- Active AWS account with appropriate permissions
- AWS CLI configured with credentials
- Sufficient service limits:
  - EC2: At least 3-10 instances (depending on cluster size)
  - VPC: 1 VPC with multiple subnets
  - ELB: 1 Application Load Balancer
  - S3: Bucket creation permissions

### Go Environment

```bash
# Go 1.19 or later
go version

# Required AWS SDK dependencies
go get github.com/aws/aws-sdk-go-v2/aws
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/ec2
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/aws/aws-sdk-go-v2/service/elbv2
go get github.com/aws/aws-sdk-go-v2/service/iam
go get github.com/aws/aws-sdk-go-v2/service/cloudwatch
go get github.com/aws/aws-sdk-go-v2/service/secretsmanager
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/timeplus-io/proton.git
cd proton/byoc/aws
```

### 2. Configure AWS Credentials

```bash
# Option 1: Using AWS CLI
aws configure

# Option 2: Using environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-west-2"

# Option 3: Using IAM roles (recommended for EC2/ECS)
# Attach appropriate IAM role to your compute instance
```

### 3. Build the Application

```bash
go build -o proton-byoc-deploy main.go iam.go
```

## Configuration

### Basic Configuration Example

```go
config := &ProtonBYOCConfig{
    // AWS Settings
    Region:            "us-west-2",
    AvailabilityZones: []string{"us-west-2a", "us-west-2b", "us-west-2c"},
    VpcCIDR:           "10.0.0.0/16",
    
    // Cluster Settings
    ClusterName:       "production-proton",
    ProtonVersion:     "latest", // or specific version like "v1.5.0"
    InstanceType:      "c5.2xlarge",
    InstanceCount:     3,
    DiskSizeGB:        500,
    
    // Storage Settings
    S3BucketName:      "my-company-proton-data",
    EnableBackups:     true,
    BackupRetentionDays: 30,
    
    // Network Settings
    EnablePublicAccess: false, // Set to true for public internet access
    AllowedCIDRs:      []string{"10.0.0.0/8"}, // Your corporate network
    
    // Security Settings
    SSHKeyName:        "my-ssh-key", // Optional, for SSH access
    EnableEncryption:  true,
    
    // Resource Tags
    Tags: map[string]string{
        "Environment": "production",
        "Team":        "data-platform",
        "CostCenter":  "engineering",
    },
}
```

### Instance Type Selection Guide

| Use Case | Instance Type | vCPU | Memory | Network | Cost (approx) |
|----------|---------------|------|--------|---------|---------------|
| Development | t3.large | 2 | 8 GB | Up to 5 Gbps | $0.0832/hr |
| Small Production | c5.xlarge | 4 | 8 GB | Up to 10 Gbps | $0.17/hr |
| Medium Production | c5.2xlarge | 8 | 16 GB | Up to 10 Gbps | $0.34/hr |
| Large Production | c5.4xlarge | 16 | 32 GB | Up to 10 Gbps | $0.68/hr |
| Memory-Intensive | r5.2xlarge | 8 | 64 GB | Up to 10 Gbps | $0.504/hr |

### Storage Configuration

```go
// For high-throughput workloads
config.DiskSizeGB = 1000
config.EnableBackups = true
config.BackupRetentionDays = 90

// For development/testing
config.DiskSizeGB = 100
config.EnableBackups = false
```

## Deployment

### Step 1: Deploy the Cluster

```go
package main

import (
    "context"
    "log"
)

func main() {
    ctx := context.Background()

    // Create configuration
    config := &ProtonBYOCConfig{
        // ... your configuration
    }

    // Initialize BYOC manager
    manager, err := NewProtonBYOCManager(ctx, config)
    if err != nil {
        log.Fatalf("Failed to create BYOC manager: %v", err)
    }

    // Deploy the cluster
    cluster, err := manager.DeployProtonCluster(ctx)
    if err != nil {
        log.Fatalf("Failed to deploy cluster: %v", err)
    }

    log.Printf("Cluster deployed successfully!")
    log.Printf("Load Balancer DNS: %s", cluster.LoadBalancerDNS)
}
```

### Step 2: Verify Deployment

```bash
# Check cluster health
./proton-byoc-deploy health --cluster-id=<cluster-id>

# Test connectivity
curl http://<load-balancer-dns>/ping

# Run a test query
curl -X POST http://<load-balancer-dns>:8123/ \
  -d "SELECT version()"
```

### Step 3: Connect to Proton

```bash
# Using HTTP interface
curl http://<load-balancer-dns>:8123/

# Using native TCP client
proton-client --host=<load-balancer-dns> --port=9000

# Using Docker
docker run -it --rm ghcr.io/timeplus-io/proton-client:latest \
  --host=<load-balancer-dns> --port=9000
```

## Operations

### Scaling the Cluster

```go
// Scale up to 5 instances
err := manager.ScaleCluster(ctx, cluster, 5)

// Scale down to 2 instances
err := manager.ScaleCluster(ctx, cluster, 2)
```

### Creating Backups

```go
// Create an on-demand backup
backupID, err := manager.BackupCluster(ctx, cluster)
if err != nil {
    log.Fatalf("Backup failed: %v", err)
}
log.Printf("Backup created: %s", backupID)

// Backups are stored in S3: s3://<bucket-name>/backups/<backup-id>/
```

### Restoring from Backup

```go
// Restore cluster from a backup
err := manager.RestoreCluster(ctx, "backup-production-proton-1234567890")
if err != nil {
    log.Fatalf("Restore failed: %v", err)
}
```

### Monitoring

```go
// Check cluster health status
health, err := manager.GetClusterHealth(ctx, cluster)
for instanceID, status := range health {
    log.Printf("Instance %s: %s", instanceID, status)
}
```

### Accessing CloudWatch Metrics

```bash
# View CPU utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=<instance-id> \
  --start-time 2025-01-01T00:00:00Z \
  --end-time 2025-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average

# View Proton-specific metrics
aws cloudwatch get-metric-statistics \
  --namespace ProtonCluster/production-proton \
  --metric-name QueryDuration \
  --start-time 2025-01-01T00:00:00Z \
  --end-time 2025-01-02T00:00:00Z \
  --period 300 \
  --statistics Average,Maximum
```

### Viewing Logs

```bash
# View Proton logs
aws logs tail /aws/proton/production-proton --follow

# View specific instance logs
aws logs tail /aws/proton/production-proton \
  --log-stream-name-prefix i-1234567890abcdef0 \
  --follow
```

## Security Best Practices

### 1. Network Security

```go
// Restrict access to known IP ranges
config.AllowedCIDRs = []string{
    "10.0.0.0/8",      // Internal network
    "203.0.113.0/24",  // Office network
}

// Disable public access for production
config.EnablePublicAccess = false
```

### 2. Encryption

```go
// Enable encryption at rest
config.EnableEncryption = true

// S3 bucket encryption is automatically enabled
// EBS volumes are encrypted with AWS-managed keys
```

### 3. IAM Roles

```go
// Create IAM roles with least-privilege access
iamManager := NewIAMManager(cfg)
roleARN, err := iamManager.CreateProtonInstanceRole(
    ctx,
    config.ClusterName,
    config.S3BucketName,
)
```

### 4. Regular Updates

```bash
# Update Proton to latest version
# This requires updating the config and redeploying
config.ProtonVersion = "v1.5.2"
```

## Troubleshooting

### Common Issues

#### 1. Instances Fail to Launch

```bash
# Check EC2 service limits
aws service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code L-1216C47A

# Verify subnet availability
aws ec2 describe-subnets --subnet-ids subnet-xxx

# Check security group rules
aws ec2 describe-security-groups --group-ids sg-xxx
```

#### 2. Load Balancer Health Checks Failing

```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn>

# Verify Proton is running on instances
ssh ec2-user@<instance-ip>
docker ps | grep proton
docker logs proton
```

#### 3. S3 Access Issues

```bash
# Verify IAM role permissions
aws iam get-role --role-name production-proton-proton-role

# Test S3 access from instance
aws s3 ls s3://my-company-proton-data/

# Check bucket policy
aws s3api get-bucket-policy --bucket my-company-proton-data
```

#### 4. High CPU Usage

```go
// Scale up the cluster
err := manager.ScaleCluster(ctx, cluster, 5)

// Or upgrade instance type
config.InstanceType = "c5.4xlarge"
// Redeploy cluster
```

## Cost Optimization

### 1. Use Spot Instances (for non-production)

```go
// Note: Requires additional implementation
// Add spot instance support to RunInstances call
```

### 2. Right-Size Instances

```bash
# Monitor actual usage
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-xxx \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Average

# If average CPU < 40%, consider smaller instance type
```

### 3. Use S3 Lifecycle Policies

```bash
# Automatically archive old data to Glacier
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-company-proton-data \
  --lifecycle-configuration file://lifecycle.json
```

### 4. Clean Up Unused Resources

```go
// Delete old backups
// Implemented in BackupRetentionDays configuration

// Terminate unused clusters
err := manager.DeleteCluster(ctx, cluster)
```

## Cleanup

### Delete a Cluster

```go
// WARNING: This will delete all resources
err := manager.DeleteCluster(ctx, cluster)
if err != nil {
    log.Fatalf("Failed to delete cluster: %v", err)
}
```

### Manual Cleanup (if automated deletion fails)

```bash
# 1. Terminate EC2 instances
aws ec2 terminate-instances --instance-ids i-xxx i-yyy

# 2. Delete load balancer
aws elbv2 delete-load-balancer --load-balancer-arn <arn>

# 3. Delete target groups
aws elbv2 delete-target-group --target-group-arn <arn>

# 4. Delete VPC resources
aws ec2 delete-subnet --subnet-id subnet-xxx
aws ec2 delete-security-group --group-id sg-xxx
aws ec2 detach-internet-gateway --internet-gateway-id igw-xxx --vpc-id vpc-xxx
aws ec2 delete-internet-gateway --internet-gateway-id igw-xxx
aws ec2 delete-vpc --vpc-id vpc-xxx

# 5. Delete S3 bucket (optional - only if you want to delete data)
aws s3 rb s3://my-company-proton-data --force

# 6. Delete IAM roles
aws iam delete-instance-profile --instance-profile-name production-proton-proton-profile
aws iam delete-role --role-name production-proton-proton-role
```

## Support

For issues and questions:

- **Timeplus Proton GitHub**: https://github.com/timeplus-io/proton
- **Documentation**: https://docs.timeplus.com/
- **Community Slack**: [Join here]

## License

This BYOC implementation is provided as-is under the Apache 2.0 License.

## Contributing

Contributions are welcome! Please submit pull requests to the main Proton repository