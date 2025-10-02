package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMManager handles IAM role and policy creation for Proton BYOC
type IAMManager struct {
	client *iam.Client
}

// NewIAMManager creates a new IAM manager instance
func NewIAMManager(cfg aws.Config) *IAMManager {
	return &IAMManager{
		client: iam.NewFromConfig(cfg),
	}
}

// PolicyDocument represents an IAM policy document
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single statement in an IAM policy
type PolicyStatement struct {
	Effect    string                 `json:"Effect"`
	Principal map[string]interface{} `json:"Principal,omitempty"`
	Action    interface{}            `json:"Action"`   // Can be string or []string
	Resource  interface{}            `json:"Resource"` // Can be string or []string
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

// CreateProtonInstanceRole creates an IAM role for Proton EC2 instances
// This role allows instances to access S3, CloudWatch, and Secrets Manager
func (m *IAMManager) CreateProtonInstanceRole(ctx context.Context, clusterName string, s3BucketName string) (string, error) {
	log.Printf("Creating IAM role for Proton instances: %s-proton-role", clusterName)

	// Step 1: Create the IAM role with EC2 as the trusted entity
	assumeRolePolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: map[string]interface{}{
					"Service": "ec2.amazonaws.com",
				},
				Action:   "sts:AssumeRole",
				Resource: "*",
			},
		},
	}

	assumeRolePolicyJSON, err := json.Marshal(assumeRolePolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal assume role policy: %w", err)
	}

	roleName := fmt.Sprintf("%s-proton-role", clusterName)

	createRoleOutput, err := m.client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(assumeRolePolicyJSON)),
		Description:              aws.String("IAM role for Timeplus Proton instances"),
		Tags: []iamtypes.Tag{
			{
				Key:   aws.String("Cluster"),
				Value: aws.String(clusterName),
			},
			{
				Key:   aws.String("ManagedBy"),
				Value: aws.String("ProtonBYOC"),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create IAM role: %w", err)
	}

	roleARN := *createRoleOutput.Role.Arn
	log.Printf("Created IAM role: %s", roleARN)

	// Step 2: Create and attach inline policy for S3 access
	s3Policy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Action: []string{
					"s3:GetObject",
					"s3:PutObject",
					"s3:DeleteObject",
					"s3:ListBucket",
				},
				Resource: []string{
					fmt.Sprintf("arn:aws:s3:::%s", s3BucketName),
					fmt.Sprintf("arn:aws:s3:::%s/*", s3BucketName),
				},
			},
			{
				// Allow listing all buckets (required for some S3 operations)
				Effect:   "Allow",
				Action:   "s3:ListAllMyBuckets",
				Resource: "*",
			},
		},
	}

	s3PolicyJSON, err := json.Marshal(s3Policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal S3 policy: %w", err)
	}

	_, err = m.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("ProtonS3Access"),
		PolicyDocument: aws.String(string(s3PolicyJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach S3 policy: %w", err)
	}

	// Step 3: Attach CloudWatch policy for logging and metrics
	cloudWatchPolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Action: []string{
					"cloudwatch:PutMetricData",
					"ec2:DescribeVolumes",
					"ec2:DescribeTags",
					"logs:CreateLogGroup",
					"logs:CreateLogStream",
					"logs:PutLogEvents",
					"logs:DescribeLogStreams",
				},
				Resource: "*",
			},
		},
	}

	cloudWatchPolicyJSON, err := json.Marshal(cloudWatchPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CloudWatch policy: %w", err)
	}

	_, err = m.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("ProtonCloudWatchAccess"),
		PolicyDocument: aws.String(string(cloudWatchPolicyJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach CloudWatch policy: %w", err)
	}

	// Step 4: Attach Secrets Manager policy for storing credentials
	secretsPolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Action: []string{
					"secretsmanager:GetSecretValue",
					"secretsmanager:DescribeSecret",
				},
				Resource: fmt.Sprintf("arn:aws:secretsmanager:*:*:secret:%s-proton-*", clusterName),
			},
		},
	}

	secretsPolicyJSON, err := json.Marshal(secretsPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Secrets Manager policy: %w", err)
	}

	_, err = m.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("ProtonSecretsAccess"),
		PolicyDocument: aws.String(string(secretsPolicyJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach Secrets Manager policy: %w", err)
	}

	// Step 5: Attach Systems Manager policy for parameter store access
	ssmPolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Action: []string{
					"ssm:GetParameter",
					"ssm:GetParameters",
					"ssm:GetParametersByPath",
				},
				Resource: fmt.Sprintf("arn:aws:ssm:*:*:parameter/%s/proton/*", clusterName),
			},
		},
	}

	ssmPolicyJSON, err := json.Marshal(ssmPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal SSM policy: %w", err)
	}

	_, err = m.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("ProtonSSMAccess"),
		PolicyDocument: aws.String(string(ssmPolicyJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach SSM policy: %w", err)
	}

	// Step 6: Create instance profile and associate with role
	// Instance profiles are required to attach IAM roles to EC2 instances
	instanceProfileName := fmt.Sprintf("%s-proton-profile", clusterName)

	_, err = m.client.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileName),
		Tags: []iamtypes.Tag{
			{
				Key:   aws.String("Cluster"),
				Value: aws.String(clusterName),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create instance profile: %w", err)
	}

	// Add role to instance profile
	_, err = m.client.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileName),
		RoleName:            aws.String(roleName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to add role to instance profile: %w", err)
	}

	log.Printf("Successfully created IAM role and instance profile for Proton cluster")
	return roleARN, nil
}

// CreateCrossAccountRole creates an IAM role that allows Proton management from another AWS account
// This is useful for SaaS providers managing customer infrastructure
func (m *IAMManager) CreateCrossAccountRole(ctx context.Context, clusterName string, trustedAccountID string, externalID string) (string, error) {
	log.Printf("Creating cross-account IAM role for external management")

	// Cross-account assume role policy with external ID for security
	assumeRolePolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: map[string]interface{}{
					"AWS": fmt.Sprintf("arn:aws:iam::%s:root", trustedAccountID),
				},
				Action: "sts:AssumeRole",
				Condition: map[string]interface{}{
					"StringEquals": map[string]string{
						"sts:ExternalId": externalID,
					},
				},
			},
		},
	}

	assumeRolePolicyJSON, err := json.Marshal(assumeRolePolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal assume role policy: %w", err)
	}

	roleName := fmt.Sprintf("%s-proton-cross-account-role", clusterName)

	createRoleOutput, err := m.client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(assumeRolePolicyJSON)),
		Description:              aws.String("Cross-account role for Proton cluster management"),
		MaxSessionDuration:       aws.Int32(3600), // 1 hour sessions
		Tags: []iamtypes.Tag{
			{
				Key:   aws.String("Cluster"),
				Value: aws.String(clusterName),
			},
			{
				Key:   aws.String("Type"),
				Value: aws.String("CrossAccount"),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create cross-account role: %w", err)
	}

	roleARN := *createRoleOutput.Role.Arn

	// Attach management policy - allows managing EC2, S3, CloudWatch, etc.
	managementPolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Action: []string{
					// EC2 permissions
					"ec2:DescribeInstances",
					"ec2:DescribeInstanceStatus",
					"ec2:StartInstances",
					"ec2:StopInstances",
					"ec2:RebootInstances",
					"ec2:TerminateInstances",
					"ec2:CreateTags",
					// Load balancer permissions
					"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:DescribeTargetGroups",
					"elasticloadbalancing:DescribeTargetHealth",
					// CloudWatch permissions
					"cloudwatch:GetMetricStatistics",
					"cloudwatch:ListMetrics",
					"cloudwatch:DescribeAlarms",
					"logs:GetLogEvents",
					"logs:DescribeLogStreams",
					// S3 permissions (read-only for monitoring)
					"s3:ListBucket",
					"s3:GetBucketLocation",
					"s3:GetBucketVersioning",
				},
				Resource: "*",
			},
		},
	}

	managementPolicyJSON, err := json.Marshal(managementPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal management policy: %w", err)
	}

	_, err = m.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("ProtonManagementAccess"),
		PolicyDocument: aws.String(string(managementPolicyJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach management policy: %w", err)
	}

	log.Printf("Successfully created cross-account role: %s", roleARN)
	log.Printf("External ID for role assumption: %s", externalID)

	return roleARN, nil
}

// DeleteProtonInstanceRole removes the IAM role and instance profile
func (m *IAMManager) DeleteProtonInstanceRole(ctx context.Context, clusterName string) error {
	log.Printf("Deleting IAM role for cluster: %s", clusterName)

	roleName := fmt.Sprintf("%s-proton-role", clusterName)
	instanceProfileName := fmt.Sprintf("%s-proton-profile", clusterName)

	// Step 1: Remove role from instance profile
	_, err := m.client.RemoveRoleFromInstanceProfile(ctx, &iam.RemoveRoleFromInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileName),
		RoleName:            aws.String(roleName),
	})
	if err != nil {
		log.Printf("Warning: Failed to remove role from instance profile: %v", err)
	}

	// Step 2: Delete instance profile
	_, err = m.client.DeleteInstanceProfile(ctx, &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileName),
	})
	if err != nil {
		log.Printf("Warning: Failed to delete instance profile: %v", err)
	}

	// Step 3: Delete inline policies
	inlinePolicies := []string{
		"ProtonS3Access",
		"ProtonCloudWatchAccess",
		"ProtonSecretsAccess",
		"ProtonSSMAccess",
	}

	for _, policyName := range inlinePolicies {
		_, err = m.client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			log.Printf("Warning: Failed to delete policy %s: %v", policyName, err)
		}
	}

	// Step 4: Delete role
	_, err = m.client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	log.Printf("Successfully deleted IAM role and instance profile")
	return nil
}

// CreateServiceLinkedRole creates a service-linked role if needed
// Service-linked roles are used by AWS services on behalf of the customer
func (m *IAMManager) CreateServiceLinkedRole(ctx context.Context, serviceName string) error {
	log.Printf("Creating service-linked role for: %s", serviceName)

	_, err := m.client.CreateServiceLinkedRole(ctx, &iam.CreateServiceLinkedRoleInput{
		AWSServiceName: aws.String(serviceName),
		Description:    aws.String(fmt.Sprintf("Service-linked role for %s", serviceName)),
	})
	if err != nil {
		// It's okay if the role already exists
		log.Printf("Service-linked role may already exist: %v", err)
		return nil
	}

	log.Printf("Successfully created service-linked role for %s", serviceName)
	return nil
}

// ValidateRolePermissions checks if a role has the required permissions
func (m *IAMManager) ValidateRolePermissions(ctx context.Context, roleName string) (bool, []string, error) {
	log.Printf("Validating permissions for role: %s", roleName)

	// Get role policies
	listPoliciesOutput, err := m.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return false, nil, fmt.Errorf("failed to list role policies: %w", err)
	}

	requiredPolicies := []string{
		"ProtonS3Access",
		"ProtonCloudWatchAccess",
		"ProtonSecretsAccess",
		"ProtonSSMAccess",
	}

	var missingPolicies []string
	foundPolicies := make(map[string]bool)

	for _, policyName := range listPoliciesOutput.PolicyNames {
		foundPolicies[policyName] = true
	}

	for _, required := range requiredPolicies {
		if !foundPolicies[required] {
			missingPolicies = append(missingPolicies, required)
		}
	}

	if len(missingPolicies) > 0 {
		log.Printf("Missing required policies: %v", missingPolicies)
		return false, missingPolicies, nil
	}

	log.Printf("All required permissions are present")
	return true, nil, nil
}

// GenerateExternalID generates a secure external ID for cross-account access
// External IDs prevent the "confused deputy" problem in cross-account scenarios
func GenerateExternalID(clusterName string) string {
	// In production, use a cryptographically secure random generator
	// This is a simplified example
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	return fmt.Sprintf("proton-%s-%s", clusterName, timestamp)
}

// Example usage demonstrating IAM setup
func ExampleIAMSetup() {
	ctx := context.Background()

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create IAM manager
	iamManager := NewIAMManager(cfg)

	// Create instance role for Proton EC2 instances
	clusterName := "production-proton"
	s3BucketName := "my-company-proton-data"

	roleARN, err := iamManager.CreateProtonInstanceRole(ctx, clusterName, s3BucketName)
	if err != nil {
		log.Fatalf("Failed to create instance role: %v", err)
	}
	log.Printf("Created instance role: %s", roleARN)

	// Create cross-account role for SaaS provider management
	trustedAccountID := "123456789012" // SaaS provider's AWS account
	externalID := GenerateExternalID(clusterName)

	crossAccountRoleARN, err := iamManager.CreateCrossAccountRole(ctx, clusterName, trustedAccountID, externalID)
	if err != nil {
		log.Fatalf("Failed to create cross-account role: %v", err)
	}
	log.Printf("Created cross-account role: %s", crossAccountRoleARN)
	log.Printf("Share this External ID with the SaaS provider: %s", externalID)

	// Validate permissions
	valid, missing, err := iamManager.ValidateRolePermissions(ctx, fmt.Sprintf("%s-proton-role", clusterName))
	if err != nil {
		log.Fatalf("Failed to validate permissions: %v", err)
	}

	if !valid {
		log.Printf("Warning: Missing policies: %v", missing)
	} else {
		log.Printf("✓ All required permissions are configured correctly")
	}

	// Create service-linked roles if needed
	services := []string{
		"elasticloadbalancing.amazonaws.com",
		"autoscaling.amazonaws.com",
	}

	for _, service := range services {
		err = iamManager.CreateServiceLinkedRole(ctx, service)
		if err != nil {
			log.Printf("Warning: Failed to create service-linked role for %s: %v", service, err)
		}
	}
}
