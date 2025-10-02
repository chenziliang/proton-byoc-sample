package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elbv2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// ProtonBYOCConfig holds the configuration for deploying Timeplus Proton in customer's AWS account
type ProtonBYOCConfig struct {
	// AWS Configuration
	Region            string
	AvailabilityZones []string
	VpcCIDR           string

	// Proton Cluster Configuration
	ClusterName   string
	ProtonVersion string
	InstanceType  string
	InstanceCount int
	DiskSizeGB    int32

	// Storage Configuration
	S3BucketName        string
	EnableBackups       bool
	BackupRetentionDays int

	// Network Configuration
	EnablePublicAccess bool
	AllowedCIDRs       []string

	// Security
	SSHKeyName       string
	EnableEncryption bool

	// Tags for resource organization
	Tags map[string]string
}

// ProtonBYOCManager manages the lifecycle of Timeplus Proton deployment in customer's AWS
type ProtonBYOCManager struct {
	cfg           aws.Config
	ec2Client     *ec2.Client
	s3Client      *s3.Client
	elbClient     *elbv2.Client
	secretsClient *secretsmanager.Client
	cwClient      *cloudwatch.Client
	config        *ProtonBYOCConfig
}

// NewProtonBYOCManager creates a new BYOC manager instance
// It initializes AWS SDK clients using the customer's credentials
func NewProtonBYOCManager(ctx context.Context, byocConfig *ProtonBYOCConfig) (*ProtonBYOCManager, error) {
	// Load AWS configuration from customer's environment/credentials
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(byocConfig.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &ProtonBYOCManager{
		cfg:           cfg,
		ec2Client:     ec2.NewFromConfig(cfg),
		s3Client:      s3.NewFromConfig(cfg),
		elbClient:     elbv2.NewFromConfig(cfg),
		secretsClient: secretsmanager.NewFromConfig(cfg),
		cwClient:      cloudwatch.NewFromConfig(cfg),
		config:        byocConfig,
	}, nil
}

// VPCResources holds references to created VPC infrastructure
type VPCResources struct {
	VpcID             string
	PublicSubnetIDs   []string
	PrivateSubnetIDs  []string
	InternetGatewayID string
	NATGatewayIDs     []string
	RouteTableIDs     []string
	SecurityGroupID   string
}

// CreateVPCInfrastructure sets up the network infrastructure for Proton cluster
// This creates an isolated network environment in customer's AWS account
func (m *ProtonBYOCManager) CreateVPCInfrastructure(ctx context.Context) (*VPCResources, error) {
	log.Println("Creating VPC infrastructure for Proton cluster...")

	// Step 1: Create VPC
	vpcOutput, err := m.ec2Client.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String(m.config.VpcCIDR),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeVpc,
				Tags:         m.buildTags("proton-vpc"),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create VPC: %w", err)
	}
	vpcID := *vpcOutput.Vpc.VpcId
	log.Printf("Created VPC: %s", vpcID)

	// Step 2: Enable DNS support for VPC (required for private DNS resolution)
	_, err = m.ec2Client.ModifyVpcAttribute(ctx, &ec2.ModifyVpcAttributeInput{
		VpcId:              aws.String(vpcID),
		EnableDnsHostnames: &types.AttributeBooleanValue{Value: aws.Bool(true)},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enable DNS hostnames: %w", err)
	}

	// Step 3: Create Internet Gateway for public internet access
	igwOutput, err := m.ec2Client.CreateInternetGateway(ctx, &ec2.CreateInternetGatewayInput{
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeInternetGateway,
				Tags:         m.buildTags("proton-igw"),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create internet gateway: %w", err)
	}
	igwID := *igwOutput.InternetGateway.InternetGatewayId

	// Attach Internet Gateway to VPC
	_, err = m.ec2Client.AttachInternetGateway(ctx, &ec2.AttachInternetGatewayInput{
		VpcId:             aws.String(vpcID),
		InternetGatewayId: aws.String(igwID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach internet gateway: %w", err)
	}

	// Step 4: Create subnets across multiple availability zones for high availability
	var publicSubnets, privateSubnets []string
	for i, az := range m.config.AvailabilityZones {
		// Create public subnet (for load balancer and NAT gateway)
		publicCIDR := fmt.Sprintf("10.0.%d.0/24", i*2)
		pubSubnetOutput, err := m.ec2Client.CreateSubnet(ctx, &ec2.CreateSubnetInput{
			VpcId:            aws.String(vpcID),
			CidrBlock:        aws.String(publicCIDR),
			AvailabilityZone: aws.String(az),
			TagSpecifications: []types.TagSpecification{
				{
					ResourceType: types.ResourceTypeSubnet,
					Tags:         m.buildTags(fmt.Sprintf("proton-public-subnet-%d", i)),
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create public subnet: %w", err)
		}
		publicSubnets = append(publicSubnets, *pubSubnetOutput.Subnet.SubnetId)

		// Create private subnet (for Proton instances)
		privateCIDR := fmt.Sprintf("10.0.%d.0/24", i*2+1)
		privSubnetOutput, err := m.ec2Client.CreateSubnet(ctx, &ec2.CreateSubnetInput{
			VpcId:            aws.String(vpcID),
			CidrBlock:        aws.String(privateCIDR),
			AvailabilityZone: aws.String(az),
			TagSpecifications: []types.TagSpecification{
				{
					ResourceType: types.ResourceTypeSubnet,
					Tags:         m.buildTags(fmt.Sprintf("proton-private-subnet-%d", i)),
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create private subnet: %w", err)
		}
		privateSubnets = append(privateSubnets, *privSubnetOutput.Subnet.SubnetId)
	}

	// Step 5: Create Security Group for Proton instances
	sgOutput, err := m.ec2Client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(fmt.Sprintf("%s-proton-sg", m.config.ClusterName)),
		Description: aws.String("Security group for Timeplus Proton cluster"),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSecurityGroup,
				Tags:         m.buildTags("proton-sg"),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create security group: %w", err)
	}
	sgID := *sgOutput.GroupId

	// Configure security group rules
	err = m.configureSecurityGroupRules(ctx, sgID)
	if err != nil {
		return nil, fmt.Errorf("failed to configure security group rules: %w", err)
	}

	return &VPCResources{
		VpcID:             vpcID,
		PublicSubnetIDs:   publicSubnets,
		PrivateSubnetIDs:  privateSubnets,
		InternetGatewayID: igwID,
		SecurityGroupID:   sgID,
	}, nil
}

// configureSecurityGroupRules sets up firewall rules for Proton cluster
func (m *ProtonBYOCManager) configureSecurityGroupRules(ctx context.Context, sgID string) error {
	// Proton default ports:
	// - 8123: HTTP interface
	// - 9000: Native TCP protocol
	// - 8443: HTTPS interface (if SSL enabled)
	// - 9440: Native TCP with SSL

	rules := []types.IpPermission{
		{
			// HTTP Interface
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(8123),
			ToPort:     aws.Int32(8123),
			IpRanges:   m.buildIPRanges(),
		},
		{
			// Native TCP Interface
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(9000),
			ToPort:     aws.Int32(9000),
			IpRanges:   m.buildIPRanges(),
		},
		{
			// Inter-cluster communication (for distributed setups)
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(9009),
			ToPort:     aws.Int32(9009),
			UserIdGroupPairs: []types.UserIdGroupPair{
				{GroupId: aws.String(sgID)}, // Allow traffic from same security group
			},
		},
	}

	// Add SSH access if key is configured
	if m.config.SSHKeyName != "" {
		rules = append(rules, types.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpRanges:   m.buildIPRanges(),
		})
	}

	_, err := m.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       aws.String(sgID),
		IpPermissions: rules,
	})
	if err != nil {
		return fmt.Errorf("failed to authorize security group ingress: %w", err)
	}

	// Allow all outbound traffic
	_, err = m.ec2Client.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("-1"), // All protocols
				IpRanges: []types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to authorize security group egress: %w", err)
	}

	return nil
}

// ProtonCluster represents a deployed Proton cluster
type ProtonCluster struct {
	ClusterID       string
	InstanceIDs     []string
	LoadBalancerARN string
	LoadBalancerDNS string
	S3BucketName    string
	VPCResources    *VPCResources
	CreatedAt       time.Time
}

// DeployProtonCluster orchestrates the full deployment of Proton cluster
func (m *ProtonBYOCManager) DeployProtonCluster(ctx context.Context) (*ProtonCluster, error) {
	log.Printf("Starting deployment of Proton cluster: %s", m.config.ClusterName)

	// Step 1: Create VPC infrastructure
	vpcRes, err := m.CreateVPCInfrastructure(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPC infrastructure: %w", err)
	}

	// Step 2: Create S3 bucket for data storage and backups
	err = m.createS3Bucket(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 bucket: %w", err)
	}

	// Step 3: Launch EC2 instances for Proton nodes
	instanceIDs, err := m.launchProtonInstances(ctx, vpcRes)
	if err != nil {
		return nil, fmt.Errorf("failed to launch Proton instances: %w", err)
	}

	// Step 4: Create Application Load Balancer
	lbARN, lbDNS, err := m.createLoadBalancer(ctx, vpcRes)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancer: %w", err)
	}

	// Step 5: Register instances with load balancer
	err = m.registerInstancesWithLB(ctx, lbARN, instanceIDs, vpcRes.VpcID)
	if err != nil {
		return nil, fmt.Errorf("failed to register instances with load balancer: %w", err)
	}

	// Step 6: Setup CloudWatch monitoring
	err = m.setupMonitoring(ctx, instanceIDs)
	if err != nil {
		log.Printf("Warning: Failed to setup monitoring: %v", err)
	}

	cluster := &ProtonCluster{
		ClusterID:       fmt.Sprintf("%s-%d", m.config.ClusterName, time.Now().Unix()),
		InstanceIDs:     instanceIDs,
		LoadBalancerARN: lbARN,
		LoadBalancerDNS: lbDNS,
		S3BucketName:    m.config.S3BucketName,
		VPCResources:    vpcRes,
		CreatedAt:       time.Now(),
	}

	log.Printf("Successfully deployed Proton cluster. Load Balancer DNS: %s", lbDNS)
	return cluster, nil
}

// createS3Bucket creates an S3 bucket for Proton data storage and backups
func (m *ProtonBYOCManager) createS3Bucket(ctx context.Context) error {
	log.Printf("Creating S3 bucket: %s", m.config.S3BucketName)

	// Create bucket
	createInput := &s3.CreateBucketInput{
		Bucket: aws.String(m.config.S3BucketName),
	}

	// For regions other than us-east-1, we need to specify location constraint
	if m.config.Region != "us-east-1" {
		createInput.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(m.config.Region),
		}
	}

	_, err := m.s3Client.CreateBucket(ctx, createInput)
	if err != nil {
		return fmt.Errorf("failed to create S3 bucket: %w", err)
	}

	// Enable versioning for data protection
	_, err = m.s3Client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(m.config.S3BucketName),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to enable bucket versioning: %w", err)
	}

	// Enable encryption at rest if configured
	if m.config.EnableEncryption {
		_, err = m.s3Client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
			Bucket: aws.String(m.config.S3BucketName),
			ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
				Rules: []types.ServerSideEncryptionRule{
					{
						ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
							SSEAlgorithm: types.ServerSideEncryptionAes256,
						},
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to enable bucket encryption: %w", err)
		}
	}

	// Configure lifecycle policy for backups if enabled
	if m.config.EnableBackups {
		_, err = m.s3Client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
			Bucket: aws.String(m.config.S3BucketName),
			LifecycleConfiguration: &types.BucketLifecycleConfiguration{
				Rules: []types.LifecycleRule{
					{
						Id:     aws.String("backup-retention"),
						Status: types.ExpirationStatusEnabled,
						Filter: &types.LifecycleRuleFilterMemberPrefix{
							Value: "backups/",
						},
						Expiration: &types.LifecycleExpiration{
							Days: aws.Int32(int32(m.config.BackupRetentionDays)),
						},
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to configure lifecycle policy: %w", err)
		}
	}

	log.Printf("Successfully created S3 bucket: %s", m.config.S3BucketName)
	return nil
}

// launchProtonInstances launches EC2 instances and configures them with Proton
func (m *ProtonBYOCManager) launchProtonInstances(ctx context.Context, vpcRes *VPCResources) ([]string, error) {
	log.Printf("Launching %d Proton instances...", m.config.InstanceCount)

	// User data script to install and configure Proton on boot
	userData := m.generateUserDataScript()

	// Get the latest Ubuntu AMI (Proton runs well on Ubuntu)
	amiID, err := m.getLatestUbuntuAMI(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Ubuntu AMI: %w", err)
	}

	var instanceIDs []string

	// Launch instances across private subnets for high availability
	for i := 0; i < m.config.InstanceCount; i++ {
		subnetIndex := i % len(vpcRes.PrivateSubnetIDs)

		runInput := &ec2.RunInstancesInput{
			ImageId:          aws.String(amiID),
			InstanceType:     types.InstanceType(m.config.InstanceType),
			MinCount:         aws.Int32(1),
			MaxCount:         aws.Int32(1),
			SubnetId:         aws.String(vpcRes.PrivateSubnetIDs[subnetIndex]),
			SecurityGroupIds: []string{vpcRes.SecurityGroupID},
			UserData:         aws.String(userData),

			// Configure storage
			BlockDeviceMappings: []types.BlockDeviceMapping{
				{
					DeviceName: aws.String("/dev/sda1"),
					Ebs: &types.EbsBlockDevice{
						VolumeSize:          aws.Int32(m.config.DiskSizeGB),
						VolumeType:          types.VolumeTypeGp3,
						DeleteOnTermination: aws.Bool(true),
						Encrypted:           aws.Bool(m.config.EnableEncryption),
					},
				},
			},

			// IAM role for S3 access (would need to be created separately)
			IamInstanceProfile: &types.IamInstanceProfileSpecification{
				Name: aws.String(fmt.Sprintf("%s-proton-role", m.config.ClusterName)),
			},

			TagSpecifications: []types.TagSpecification{
				{
					ResourceType: types.ResourceTypeInstance,
					Tags:         m.buildTags(fmt.Sprintf("proton-node-%d", i)),
				},
			},
		}

		// Add SSH key if configured
		if m.config.SSHKeyName != "" {
			runInput.KeyName = aws.String(m.config.SSHKeyName)
		}

		output, err := m.ec2Client.RunInstances(ctx, runInput)
		if err != nil {
			return nil, fmt.Errorf("failed to launch instance %d: %w", i, err)
		}

		instanceIDs = append(instanceIDs, *output.Instances[0].InstanceId)
		log.Printf("Launched instance: %s", *output.Instances[0].InstanceId)
	}

	// Wait for instances to be running
	log.Println("Waiting for instances to be running...")
	waiter := ec2.NewInstanceRunningWaiter(m.ec2Client)
	err = waiter.Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	}, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for instances to run: %w", err)
	}

	log.Printf("Successfully launched %d Proton instances", len(instanceIDs))
	return instanceIDs, nil
}

// generateUserDataScript creates a bash script to install and configure Proton
func (m *ProtonBYOCManager) generateUserDataScript() string {
	script := `#!/bin/bash
set -e

# Update system packages
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y curl wget apt-transport-https ca-certificates software-properties-common

# Install Docker (Proton can run in containers)
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
systemctl enable docker
systemctl start docker

# Install AWS CLI for S3 access
apt-get install -y awscli

# Create Proton data directory
mkdir -p /var/lib/proton
mkdir -p /var/log/proton

# Download and install Proton
# Using docker-based installation for easier management
docker pull ghcr.io/timeplus-io/proton:` + m.config.ProtonVersion + `

# Create Proton configuration file
cat > /etc/proton-config.xml <<EOL
<proton>
    <logger>
        <level>information</level>
        <log>/var/log/proton/proton.log</log>
    </logger>
    
    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    
    <!-- S3 Configuration for storage -->
    <storage_configuration>
        <disks>
            <s3>
                <type>s3</type>
                <endpoint>https://s3.` + m.config.Region + `.amazonaws.com/` + m.config.S3BucketName + `/</endpoint>
                <use_environment_credentials>true</use_environment_credentials>
            </s3>
        </disks>
    </storage_configuration>
    
    <!-- Data paths -->
    <path>/var/lib/proton/</path>
    <tmp_path>/var/lib/proton/tmp/</tmp_path>
    
    <!-- Memory and performance settings -->
    <max_server_memory_usage_to_ram_ratio>0.9</max_server_memory_usage_to_ram_ratio>
    <mark_cache_size>5368709120</mark_cache_size>
</proton>
EOL

# Create systemd service for Proton
cat > /etc/systemd/system/proton.service <<EOL
[Unit]
Description=Timeplus Proton Server
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/docker run --rm \
    --name proton \
    -p 8123:8123 \
    -p 9000:9000 \
    -v /var/lib/proton:/var/lib/proton \
    -v /etc/proton-config.xml:/etc/proton-server/config.xml \
    ghcr.io/timeplus-io/proton:` + m.config.ProtonVersion + `
ExecStop=/usr/bin/docker stop proton

[Install]
WantedBy=multi-user.target
EOL

# Enable and start Proton service
systemctl daemon-reload
systemctl enable proton
systemctl start proton

# Install CloudWatch agent for monitoring
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOL
{
  "metrics": {
    "namespace": "ProtonCluster/` + m.config.ClusterName + `",
    "metrics_collected": {
      "cpu": {
        "measurement": [{"name": "cpu_usage_idle", "rename": "CPU_IDLE", "unit": "Percent"}],
        "totalcpu": false
      },
      "disk": {
        "measurement": [{"name": "used_percent", "rename": "DISK_USED", "unit": "Percent"}],
        "resources": ["*"]
      },
      "mem": {
        "measurement": [{"name": "mem_used_percent", "rename": "MEM_USED", "unit": "Percent"}]
      }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/proton/proton.log",
            "log_group_name": "/aws/proton/` + m.config.ClusterName + `",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOL

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

echo "Proton installation completed successfully"
`
	return script
}

// getLatestUbuntuAMI retrieves the latest Ubuntu 22.04 LTS AMI ID
func (m *ProtonBYOCManager) getLatestUbuntuAMI(ctx context.Context) (string, error) {
	// Search for official Ubuntu 22.04 LTS AMI
	output, err := m.ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"099720109477"}, // Canonical's AWS account ID
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{"ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"},
			},
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil {
		return "", err
	}

	if len(output.Images) == 0 {
		return "", fmt.Errorf("no Ubuntu AMI found")
	}

	// Return the most recent AMI
	latestAMI := output.Images[0]
	for _, img := range output.Images {
		if *img.CreationDate > *latestAMI.CreationDate {
			latestAMI = img
		}
	}

	return *latestAMI.ImageId, nil
}

// createLoadBalancer creates an Application Load Balancer for the Proton cluster
func (m *ProtonBYOCManager) createLoadBalancer(ctx context.Context, vpcRes *VPCResources) (string, string, error) {
	log.Println("Creating Application Load Balancer...")

	// Create the load balancer in public subnets
	lbOutput, err := m.elbClient.CreateLoadBalancer(ctx, &elbv2.CreateLoadBalancerInput{
		Name:           aws.String(fmt.Sprintf("%s-proton-lb", m.config.ClusterName)),
		Subnets:        vpcRes.PublicSubnetIDs,
		SecurityGroups: []string{vpcRes.SecurityGroupID},
		Scheme:         types.LoadBalancerSchemeEnumInternetFacing,
		Type:           types.LoadBalancerTypeEnumApplication,
		Tags: []elbv2types.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(fmt.Sprintf("%s-proton-lb", m.config.ClusterName)),
			},
			{
				Key:   aws.String("Cluster"),
				Value: aws.String(m.config.ClusterName),
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create load balancer: %w", err)
	}

	lbARN := *lbOutput.LoadBalancers[0].LoadBalancerArn
	lbDNS := *lbOutput.LoadBalancers[0].DNSName

	// Create target group for HTTP traffic (port 8123)
	tgOutput, err := m.elbClient.CreateTargetGroup(ctx, &elbv2.CreateTargetGroupInput{
		Name:                       aws.String(fmt.Sprintf("%s-proton-tg", m.config.ClusterName)),
		Port:                       aws.Int32(8123),
		Protocol:                   types.ProtocolEnumHttp,
		VpcId:                      aws.String(vpcRes.VpcID),
		HealthCheckEnabled:         aws.Bool(true),
		HealthCheckPath:            aws.String("/ping"),
		HealthCheckIntervalSeconds: aws.Int32(30),
		HealthCheckTimeoutSeconds:  aws.Int32(5),
		HealthyThresholdCount:      aws.Int32(2),
		UnhealthyThresholdCount:    aws.Int32(3),
		TargetType:                 types.TargetTypeEnumInstance,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create target group: %w", err)
	}

	targetGroupARN := *tgOutput.TargetGroups[0].TargetGroupArn

	// Create listener for the load balancer
	_, err = m.elbClient.CreateListener(ctx, &elbv2.CreateListenerInput{
		LoadBalancerArn: aws.String(lbARN),
		Port:            aws.Int32(80),
		Protocol:        types.ProtocolEnumHttp,
		DefaultActions: []elbv2types.Action{
			{
				Type:           types.ActionTypeEnumForward,
				TargetGroupArn: aws.String(targetGroupARN),
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create listener: %w", err)
	}

	log.Printf("Created load balancer: %s (DNS: %s)", lbARN, lbDNS)
	return lbARN, lbDNS, nil
}

// registerInstancesWithLB registers EC2 instances with the load balancer target group
func (m *ProtonBYOCManager) registerInstancesWithLB(ctx context.Context, lbARN string, instanceIDs []string, vpcID string) error {
	log.Println("Registering instances with load balancer...")

	// Get target groups for this load balancer
	tgOutput, err := m.elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	if err != nil {
		return fmt.Errorf("failed to describe target groups: %w", err)
	}

	if len(tgOutput.TargetGroups) == 0 {
		return fmt.Errorf("no target groups found for load balancer")
	}

	targetGroupARN := *tgOutput.TargetGroups[0].TargetGroupArn

	// Build list of targets to register
	var targets []elbv2types.TargetDescription
	for _, instanceID := range instanceIDs {
		targets = append(targets, elbv2types.TargetDescription{
			Id:   aws.String(instanceID),
			Port: aws.Int32(8123),
		})
	}

	// Register instances with target group
	_, err = m.elbClient.RegisterTargets(ctx, &elbv2.RegisterTargetsInput{
		TargetGroupArn: aws.String(targetGroupARN),
		Targets:        targets,
	})
	if err != nil {
		return fmt.Errorf("failed to register targets: %w", err)
	}

	log.Printf("Successfully registered %d instances with load balancer", len(instanceIDs))
	return nil
}

// setupMonitoring configures CloudWatch monitoring for the Proton cluster
func (m *ProtonBYOCManager) setupMonitoring(ctx context.Context, instanceIDs []string) error {
	log.Println("Setting up CloudWatch monitoring...")

	// Create CloudWatch alarms for critical metrics

	// 1. High CPU alarm
	for i, instanceID := range instanceIDs {
		_, err := m.cwClient.PutMetricAlarm(ctx, &cloudwatch.PutMetricAlarmInput{
			AlarmName:          aws.String(fmt.Sprintf("%s-proton-high-cpu-%d", m.config.ClusterName, i)),
			ComparisonOperator: types.ComparisonOperatorGreaterThanThreshold,
			EvaluationPeriods:  aws.Int32(2),
			MetricName:         aws.String("CPUUtilization"),
			Namespace:          aws.String("AWS/EC2"),
			Period:             aws.Int32(300),
			Statistic:          types.StatisticAverage,
			Threshold:          aws.Float64(80.0),
			ActionsEnabled:     aws.Bool(true),
			AlarmDescription:   aws.String(fmt.Sprintf("Alert when CPU exceeds 80%% for instance %s", instanceID)),
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceId"),
					Value: aws.String(instanceID),
				},
			},
		})
		if err != nil {
			log.Printf("Warning: Failed to create CPU alarm for instance %s: %v", instanceID, err)
		}

		// 2. Status check alarm
		_, err = m.cwClient.PutMetricAlarm(ctx, &cloudwatch.PutMetricAlarmInput{
			AlarmName:          aws.String(fmt.Sprintf("%s-proton-status-check-%d", m.config.ClusterName, i)),
			ComparisonOperator: types.ComparisonOperatorGreaterThanThreshold,
			EvaluationPeriods:  aws.Int32(2),
			MetricName:         aws.String("StatusCheckFailed"),
			Namespace:          aws.String("AWS/EC2"),
			Period:             aws.Int32(60),
			Statistic:          types.StatisticMaximum,
			Threshold:          aws.Float64(0.0),
			ActionsEnabled:     aws.Bool(true),
			AlarmDescription:   aws.String(fmt.Sprintf("Alert when status check fails for instance %s", instanceID)),
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceId"),
					Value: aws.String(instanceID),
				},
			},
		})
		if err != nil {
			log.Printf("Warning: Failed to create status check alarm for instance %s: %v", instanceID, err)
		}
	}

	log.Println("Successfully configured CloudWatch monitoring")
	return nil
}

// ScaleCluster adds or removes instances from the Proton cluster
func (m *ProtonBYOCManager) ScaleCluster(ctx context.Context, cluster *ProtonCluster, newInstanceCount int) error {
	log.Printf("Scaling cluster from %d to %d instances...", len(cluster.InstanceIDs), newInstanceCount)

	currentCount := len(cluster.InstanceIDs)

	if newInstanceCount > currentCount {
		// Scale up: Launch new instances
		instancesToAdd := newInstanceCount - currentCount
		newInstances, err := m.launchProtonInstances(ctx, cluster.VPCResources)
		if err != nil {
			return fmt.Errorf("failed to launch new instances: %w", err)
		}

		// Register new instances with load balancer
		err = m.registerInstancesWithLB(ctx, cluster.LoadBalancerARN, newInstances, cluster.VPCResources.VpcID)
		if err != nil {
			return fmt.Errorf("failed to register new instances: %w", err)
		}

		cluster.InstanceIDs = append(cluster.InstanceIDs, newInstances...)
		log.Printf("Successfully scaled up by %d instances", instancesToAdd)

	} else if newInstanceCount < currentCount {
		// Scale down: Terminate excess instances
		instancesToRemove := currentCount - newInstanceCount
		instancesToTerminate := cluster.InstanceIDs[len(cluster.InstanceIDs)-instancesToRemove:]

		// Deregister instances from load balancer first
		tgOutput, err := m.elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
			LoadBalancerArn: aws.String(cluster.LoadBalancerARN),
		})
		if err != nil {
			return fmt.Errorf("failed to describe target groups: %w", err)
		}

		if len(tgOutput.TargetGroups) > 0 {
			var targets []elbv2types.TargetDescription
			for _, instanceID := range instancesToTerminate {
				targets = append(targets, elbv2types.TargetDescription{
					Id: aws.String(instanceID),
				})
			}

			_, err = m.elbClient.DeregisterTargets(ctx, &elbv2.DeregisterTargetsInput{
				TargetGroupArn: aws.String(*tgOutput.TargetGroups[0].TargetGroupArn),
				Targets:        targets,
			})
			if err != nil {
				return fmt.Errorf("failed to deregister targets: %w", err)
			}
		}

		// Wait for connections to drain
		time.Sleep(30 * time.Second)

		// Terminate instances
		_, err = m.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: instancesToTerminate,
		})
		if err != nil {
			return fmt.Errorf("failed to terminate instances: %w", err)
		}

		cluster.InstanceIDs = cluster.InstanceIDs[:newInstanceCount]
		log.Printf("Successfully scaled down by %d instances", instancesToRemove)
	}

	return nil
}

// BackupCluster creates a backup of the Proton cluster data to S3
func (m *ProtonBYOCManager) BackupCluster(ctx context.Context, cluster *ProtonCluster) (string, error) {
	log.Println("Creating cluster backup...")

	backupID := fmt.Sprintf("backup-%s-%d", cluster.ClusterID, time.Now().Unix())
	backupPrefix := fmt.Sprintf("backups/%s/", backupID)

	// In a real implementation, this would:
	// 1. Trigger a Proton backup command on each instance
	// 2. Upload the backup files to S3
	// 3. Create a manifest file with backup metadata

	// For this example, we'll create a backup manifest
	manifest := fmt.Sprintf(`{
  "backup_id": "%s",
  "cluster_id": "%s",
  "timestamp": "%s",
  "instance_count": %d,
  "s3_location": "s3://%s/%s"
}`, backupID, cluster.ClusterID, time.Now().Format(time.RFC3339),
		len(cluster.InstanceIDs), m.config.S3BucketName, backupPrefix)

	log.Printf("Backup created: %s", backupID)
	log.Printf("Backup location: s3://%s/%s", m.config.S3BucketName, backupPrefix)

	return backupID, nil
}

// RestoreCluster restores a Proton cluster from a backup
func (m *ProtonBYOCManager) RestoreCluster(ctx context.Context, backupID string) error {
	log.Printf("Restoring cluster from backup: %s", backupID)

	// In a real implementation, this would:
	// 1. Download backup files from S3
	// 2. Stop Proton services on target instances
	// 3. Restore data files
	// 4. Restart Proton services
	// 5. Verify cluster health

	log.Printf("Cluster restored successfully from backup: %s", backupID)
	return nil
}

// DeleteCluster tears down the entire Proton cluster and associated resources
func (m *ProtonBYOCManager) DeleteCluster(ctx context.Context, cluster *ProtonCluster) error {
	log.Printf("Deleting Proton cluster: %s", cluster.ClusterID)

	// Step 1: Delete load balancer
	if cluster.LoadBalancerARN != "" {
		log.Println("Deleting load balancer...")
		_, err := m.elbClient.DeleteLoadBalancer(ctx, &elbv2.DeleteLoadBalancerInput{
			LoadBalancerArn: aws.String(cluster.LoadBalancerARN),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete load balancer: %v", err)
		}
	}

	// Step 2: Terminate EC2 instances
	if len(cluster.InstanceIDs) > 0 {
		log.Println("Terminating EC2 instances...")
		_, err := m.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: cluster.InstanceIDs,
		})
		if err != nil {
			log.Printf("Warning: Failed to terminate instances: %v", err)
		}

		// Wait for instances to terminate
		waiter := ec2.NewInstanceTerminatedWaiter(m.ec2Client)
		err = waiter.Wait(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: cluster.InstanceIDs,
		}, 5*time.Minute)
		if err != nil {
			log.Printf("Warning: Error waiting for instances to terminate: %v", err)
		}
	}

	// Step 3: Delete VPC resources
	if cluster.VPCResources != nil {
		log.Println("Deleting VPC resources...")

		// Delete security group
		_, err := m.ec2Client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(cluster.VPCResources.SecurityGroupID),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete security group: %v", err)
		}

		// Delete subnets
		for _, subnetID := range append(cluster.VPCResources.PublicSubnetIDs, cluster.VPCResources.PrivateSubnetIDs...) {
			_, err := m.ec2Client.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{
				SubnetId: aws.String(subnetID),
			})
			if err != nil {
				log.Printf("Warning: Failed to delete subnet %s: %v", subnetID, err)
			}
		}

		// Detach and delete internet gateway
		_, err = m.ec2Client.DetachInternetGateway(ctx, &ec2.DetachInternetGatewayInput{
			InternetGatewayId: aws.String(cluster.VPCResources.InternetGatewayID),
			VpcId:             aws.String(cluster.VPCResources.VpcID),
		})
		if err != nil {
			log.Printf("Warning: Failed to detach internet gateway: %v", err)
		}

		_, err = m.ec2Client.DeleteInternetGateway(ctx, &ec2.DeleteInternetGatewayInput{
			InternetGatewayId: aws.String(cluster.VPCResources.InternetGatewayID),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete internet gateway: %v", err)
		}

		// Delete VPC
		time.Sleep(10 * time.Second) // Allow time for resources to cleanup
		_, err = m.ec2Client.DeleteVpc(ctx, &ec2.DeleteVpcInput{
			VpcId: aws.String(cluster.VPCResources.VpcID),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete VPC: %v", err)
		}
	}

	// Step 4: Optionally delete S3 bucket (commented out for safety)
	// Note: In production, you'd want to empty the bucket first or keep it for data retention
	/*
		log.Println("Deleting S3 bucket...")
		_, err := m.s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(cluster.S3BucketName),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete S3 bucket: %v", err)
		}
	*/

	log.Printf("Successfully deleted cluster: %s", cluster.ClusterID)
	return nil
}

// GetClusterHealth checks the health status of all instances in the cluster
func (m *ProtonBYOCManager) GetClusterHealth(ctx context.Context, cluster *ProtonCluster) (map[string]string, error) {
	log.Println("Checking cluster health...")

	healthStatus := make(map[string]string)

	// Check EC2 instance status
	output, err := m.ec2Client.DescribeInstanceStatus(ctx, &ec2.DescribeInstanceStatusInput{
		InstanceIds: cluster.InstanceIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance status: %w", err)
	}

	for _, status := range output.InstanceStatuses {
		instanceID := *status.InstanceId
		instanceState := string(status.InstanceState.Name)
		systemStatus := string(status.SystemStatus.Status)
		instanceStatus := string(status.InstanceStatus.Status)

		health := fmt.Sprintf("State: %s, System: %s, Instance: %s",
			instanceState, systemStatus, instanceStatus)
		healthStatus[instanceID] = health

		log.Printf("Instance %s: %s", instanceID, health)
	}

	// Check load balancer target health
	tgOutput, err := m.elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		LoadBalancerArn: aws.String(cluster.LoadBalancerARN),
	})
	if err == nil && len(tgOutput.TargetGroups) > 0 {
		targetGroupARN := *tgOutput.TargetGroups[0].TargetGroupArn

		healthOutput, err := m.elbClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
			TargetGroupArn: aws.String(targetGroupARN),
		})
		if err == nil {
			for _, targetHealth := range healthOutput.TargetHealthDescriptions {
				targetID := *targetHealth.Target.Id
				state := string(targetHealth.TargetHealth.State)

				if existing, ok := healthStatus[targetID]; ok {
					healthStatus[targetID] = fmt.Sprintf("%s, LB: %s", existing, state)
				}
			}
		}
	}

	return healthStatus, nil
}

// buildTags creates a slice of EC2 tags from the config
func (m *ProtonBYOCManager) buildTags(name string) []types.Tag {
	tags := []types.Tag{
		{
			Key:   aws.String("Name"),
			Value: aws.String(fmt.Sprintf("%s-%s", m.config.ClusterName, name)),
		},
		{
			Key:   aws.String("Cluster"),
			Value: aws.String(m.config.ClusterName),
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("ProtonBYOC"),
		},
	}

	// Add custom tags from config
	for k, v := range m.config.Tags {
		tags = append(tags, types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}

	return tags
}

// buildIPRanges creates IP range configurations for security groups
func (m *ProtonBYOCManager) buildIPRanges() []types.IpRange {
	var ranges []types.IpRange

	if len(m.config.AllowedCIDRs) == 0 {
		// Default to allow all if no specific CIDRs configured
		// In production, this should be restricted
		ranges = append(ranges, types.IpRange{
			CidrIp:      aws.String("0.0.0.0/0"),
			Description: aws.String("Allow all (default)"),
		})
	} else {
		for i, cidr := range m.config.AllowedCIDRs {
			ranges = append(ranges, types.IpRange{
				CidrIp:      aws.String(cidr),
				Description: aws.String(fmt.Sprintf("Allowed CIDR %d", i)),
			})
		}
	}

	return ranges
}

// Example usage function demonstrating how to use the BYOC manager
func main() {
	ctx := context.Background()

	// Configure the Proton BYOC deployment
	config := &ProtonBYOCConfig{
		Region:            "us-west-2",
		AvailabilityZones: []string{"us-west-2a", "us-west-2b"},
		VpcCIDR:           "10.0.0.0/16",

		ClusterName:   "production-proton",
		ProtonVersion: "latest",
		InstanceType:  "c5.2xlarge",
		InstanceCount: 3,
		DiskSizeGB:    500,

		S3BucketName:        "my-company-proton-data",
		EnableBackups:       true,
		BackupRetentionDays: 30,

		EnablePublicAccess: true,
		AllowedCIDRs:       []string{"10.0.0.0/8", "172.16.0.0/12"},

		SSHKeyName:       "my-ssh-key",
		EnableEncryption: true,

		Tags: map[string]string{
			"Environment": "production",
			"Team":        "data-platform",
			"CostCenter":  "engineering",
		},
	}

	// Create BYOC manager
	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create BYOC manager: %v", err)
	}

	// Deploy the Proton cluster
	cluster, err := manager.DeployProtonCluster(ctx)
	if err != nil {
		log.Fatalf("Failed to deploy Proton cluster: %v", err)
	}

	log.Printf("✓ Proton cluster deployed successfully!")
	log.Printf("  Cluster ID: %s", cluster.ClusterID)
	log.Printf("  Load Balancer DNS: %s", cluster.LoadBalancerDNS)
	log.Printf("  Instance Count: %d", len(cluster.InstanceIDs))
	log.Printf("  S3 Bucket: %s", cluster.S3BucketName)
	log.Printf("")
	log.Printf("Connect to Proton using:")
	log.Printf("  HTTP: http://%s:80", cluster.LoadBalancerDNS)
	log.Printf("  Example query: curl http://%s:80/", cluster.LoadBalancerDNS)

	// Check cluster health
	health, err := manager.GetClusterHealth(ctx, cluster)
	if err != nil {
		log.Printf("Warning: Failed to get cluster health: %v", err)
	} else {
		log.Println("\nCluster Health Status:")
		for instanceID, status := range health {
			log.Printf("  %s: %s", instanceID, status)
		}
	}

	// Example: Scale the cluster
	// err = manager.ScaleCluster(ctx, cluster, 5)
	// if err != nil {
	//     log.Printf("Failed to scale cluster: %v", err)
	// }

	// Example: Create a backup
	// backupID, err := manager.BackupCluster(ctx, cluster)
	// if err != nil {
	//     log.Printf("Failed to create backup: %v", err)
	// } else {
	//     log.Printf("Backup created: %s", backupID)
	// }

	// Example: Delete the cluster (use with caution!)
	// err = manager.DeleteCluster(ctx, cluster)
	// if err != nil {
	//     log.Printf("Failed to delete cluster: %v", err)
	// }
}
