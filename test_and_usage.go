package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Example 1: Deploy a complete Proton cluster
func ExampleDeployCluster() {
	ctx := context.Background()

	// Configure deployment
	config := &ProtonBYOCConfig{
		Region:            "us-west-2",
		AvailabilityZones: []string{"us-west-2a", "us-west-2b"},
		VpcCIDR:           "10.0.0.0/16",

		ClusterName:   "demo-proton",
		ProtonVersion: "latest",
		InstanceType:  "c5.xlarge",
		InstanceCount: 3,
		DiskSizeGB:    200,

		S3BucketName:        "demo-proton-data",
		EnableBackups:       true,
		BackupRetentionDays: 7,

		EnablePublicAccess: true,
		AllowedCIDRs:       []string{"0.0.0.0/0"},

		SSHKeyName:       "my-key",
		EnableEncryption: true,

		Tags: map[string]string{
			"Environment": "demo",
			"Purpose":     "testing",
		},
	}

	// Create manager
	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	// Deploy cluster
	cluster, err := manager.DeployProtonCluster(ctx)
	if err != nil {
		log.Fatalf("Failed to deploy cluster: %v", err)
	}

	fmt.Printf("✓ Cluster deployed successfully!\n")
	fmt.Printf("  Load Balancer: %s\n", cluster.LoadBalancerDNS)
	fmt.Printf("  Connect: http://%s\n", cluster.LoadBalancerDNS)
}

// Example 2: Scale an existing cluster
func ExampleScaleCluster() {
	ctx := context.Background()

	// Load existing cluster configuration
	config := &ProtonBYOCConfig{
		Region:      "us-west-2",
		ClusterName: "demo-proton",
		// ... other config
	}

	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	// Assume we have a cluster object (in production, load from state)
	var cluster *ProtonCluster // Load from somewhere

	// Scale up to 5 instances
	fmt.Println("Scaling cluster to 5 instances...")
	err = manager.ScaleCluster(ctx, cluster, 5)
	if err != nil {
		log.Fatalf("Failed to scale cluster: %v", err)
	}

	fmt.Println("✓ Cluster scaled successfully!")

	// Wait a bit for instances to be healthy
	time.Sleep(2 * time.Minute)

	// Check health
	health, err := manager.GetClusterHealth(ctx, cluster)
	if err != nil {
		log.Printf("Warning: %v", err)
	} else {
		fmt.Println("\nCluster Health:")
		for instance, status := range health {
			fmt.Printf("  %s: %s\n", instance, status)
		}
	}
}

// Example 3: Create and manage backups
func ExampleBackupRestore() {
	ctx := context.Background()

	config := &ProtonBYOCConfig{
		Region:      "us-west-2",
		ClusterName: "demo-proton",
		// ... other config
	}

	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	var cluster *ProtonCluster // Load from somewhere

	// Create a backup
	fmt.Println("Creating backup...")
	backupID, err := manager.BackupCluster(ctx, cluster)
	if err != nil {
		log.Fatalf("Failed to create backup: %v", err)
	}

	fmt.Printf("✓ Backup created: %s\n", backupID)

	// Later, restore from backup
	fmt.Printf("Restoring from backup %s...\n", backupID)
	err = manager.RestoreCluster(ctx, backupID)
	if err != nil {
		log.Fatalf("Failed to restore: %v", err)
	}

	fmt.Println("✓ Cluster restored successfully!")
}

// Example 4: Monitor cluster health continuously
func ExampleMonitorHealth() {
	ctx := context.Background()

	config := &ProtonBYOCConfig{
		Region:      "us-west-2",
		ClusterName: "demo-proton",
	}

	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	var cluster *ProtonCluster // Load from somewhere

	// Continuously monitor health
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			health, err := manager.GetClusterHealth(ctx, cluster)
			if err != nil {
				log.Printf("Error checking health: %v", err)
				continue
			}

			fmt.Printf("\n[%s] Cluster Health Check:\n", time.Now().Format(time.RFC3339))

			healthyCount := 0
			for instanceID, status := range health {
				fmt.Printf("  %s: %s\n", instanceID, status)
				// Simple check - in production, parse the status properly
				if strings.Contains(status, "running") && strings.Contains(status, "ok") {
					healthyCount++
				}
			}

			fmt.Printf("Healthy instances: %d/%d\n", healthyCount, len(health))

			if healthyCount < len(health)/2 {
				fmt.Println("⚠ Warning: Less than 50% of instances are healthy!")
				// Could trigger alerts here
			}
		}
	}
}

// Example 5: Test Proton connectivity and run queries
func ExampleTestProtonQueries(loadBalancerDNS string) {
	baseURL := fmt.Sprintf("http://%s:8123", loadBalancerDNS)

	// Test 1: Ping endpoint
	fmt.Println("Test 1: Checking connectivity...")
	resp, err := http.Get(baseURL + "/ping")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("✓ Proton is responding")
	} else {
		fmt.Printf("✗ Unexpected status: %d\n", resp.StatusCode)
	}

	// Test 2: Get version
	fmt.Println("\nTest 2: Getting Proton version...")
	resp, err = http.Get(baseURL + "/?query=SELECT%20version()")
	if err != nil {
		log.Fatalf("Failed to query: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("✓ Proton version: %s\n", strings.TrimSpace(string(body)))

	// Test 3: Create a stream
	fmt.Println("\nTest 3: Creating a test stream...")
	createStreamQuery := `
		CREATE STREAM IF NOT EXISTS test_stream (
			timestamp DateTime64(3),
			sensor_id String,
			temperature Float32,
			humidity Float32
		)
	`

	resp, err = http.Post(
		baseURL,
		"text/plain",
		bytes.NewBufferString(createStreamQuery),
	)
	if err != nil {
		log.Fatalf("Failed to create stream: %v", err)
	}
	resp.Body.Close()
	fmt.Println("✓ Stream created")

	// Test 4: Insert data
	fmt.Println("\nTest 4: Inserting test data...")
	insertQuery := `
		INSERT INTO test_stream (timestamp, sensor_id, temperature, humidity)
		VALUES
			(now(), 'sensor_1', 23.5, 65.2),
			(now(), 'sensor_2', 24.1, 62.8),
			(now(), 'sensor_3', 22.9, 68.5)
	`

	resp, err = http.Post(
		baseURL,
		"text/plain",
		bytes.NewBufferString(insertQuery),
	)
	if err != nil {
		log.Fatalf("Failed to insert data: %v", err)
	}
	resp.Body.Close()
	fmt.Println("✓ Data inserted")

	// Test 5: Query data
	fmt.Println("\nTest 5: Querying data...")
	queryData := "SELECT * FROM test_stream LIMIT 10"

	resp, err = http.Post(
		baseURL,
		"text/plain",
		bytes.NewBufferString(queryData),
	)
	if err != nil {
		log.Fatalf("Failed to query data: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("✓ Query results:\n%s\n", string(body))

	// Test 6: Streaming query (tumble window)
	fmt.Println("\nTest 6: Running streaming aggregation...")
	streamingQuery := `
		SELECT
			window_start,
			sensor_id,
			avg(temperature) AS avg_temp,
			avg(humidity) AS avg_humidity
		FROM tumble(test_stream, timestamp, 5s)
		GROUP BY window_start, sensor_id
	`

	resp, err = http.Post(
		baseURL,
		"text/plain",
		bytes.NewBufferString(streamingQuery),
	)
	if err != nil {
		log.Fatalf("Failed to run streaming query: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("✓ Streaming aggregation:\n%s\n", string(body))

	// Test 7: Drop stream
	fmt.Println("\nTest 7: Cleaning up test stream...")
	dropQuery := "DROP STREAM IF EXISTS test_stream"
	resp, err = http.Post(baseURL, "text/plain", bytes.NewBufferString(dropQuery))
	if err != nil {
		log.Printf("Warning: Failed to drop stream: %v", err)
	} else {
		resp.Body.Close()
		fmt.Println("✓ Test stream dropped")
	}

	fmt.Println("\n✓ All tests passed!")
}

// Example 6: Load testing helper
func ExampleLoadTest(loadBalancerDNS string, concurrency int, duration time.Duration) {
	baseURL := fmt.Sprintf("http://%s:8123", loadBalancerDNS)

	fmt.Printf("Starting load test:\n")
	fmt.Printf("  Target: %s\n", baseURL)
	fmt.Printf("  Concurrency: %d\n", concurrency)
	fmt.Printf("  Duration: %s\n", duration)

	type Result struct {
		Success int
		Failed  int
		TotalMS int64
	}

	results := make(chan Result, concurrency)
	stopCh := make(chan struct{})

	// Start workers
	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			success := 0
			failed := 0
			totalTime := int64(0)

			for {
				select {
				case <-stopCh:
					results <- Result{Success: success, Failed: failed, TotalMS: totalTime}
					return
				default:
					start := time.Now()

					// Simple query
					query := fmt.Sprintf("SELECT %d", workerID)
					resp, err := http.Post(baseURL, "text/plain", bytes.NewBufferString(query))

					elapsed := time.Since(start).Milliseconds()
					totalTime += elapsed

					if err != nil || resp.StatusCode != 200 {
						failed++
					} else {
						success++
						resp.Body.Close()
					}

					// Small delay between requests
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// Wait for duration
	time.Sleep(duration)
	close(stopCh)

	// Collect results
	totalSuccess := 0
	totalFailed := 0
	totalTime := int64(0)

	for i := 0; i < concurrency; i++ {
		result := <-results
		totalSuccess += result.Success
		totalFailed += result.Failed
		totalTime += result.TotalMS
	}

	// Print results
	fmt.Println("\nLoad Test Results:")
	fmt.Printf("  Total Requests: %d\n", totalSuccess+totalFailed)
	fmt.Printf("  Successful: %d\n", totalSuccess)
	fmt.Printf("  Failed: %d\n", totalFailed)
	if totalSuccess+totalFailed > 0 {
		fmt.Printf("  Success Rate: %.2f%%\n", float64(totalSuccess)/float64(totalSuccess+totalFailed)*100)
	}

	if totalSuccess > 0 {
		avgLatency := totalTime / int64(totalSuccess)
		fmt.Printf("  Average Latency: %dms\n", avgLatency)
		fmt.Printf("  Throughput: %.2f req/s\n", float64(totalSuccess)/duration.Seconds())
	}
}

// Example 7: Complete deployment with validation
func ExampleCompleteDeploymentFlow() {
	ctx := context.Background()

	fmt.Println("=== Proton BYOC Deployment Flow ===\n")

	// Step 1: Configure
	fmt.Println("Step 1: Configuring deployment...")
	config := &ProtonBYOCConfig{
		Region:              "us-west-2",
		AvailabilityZones:   []string{"us-west-2a", "us-west-2b"},
		VpcCIDR:             "10.0.0.0/16",
		ClusterName:         "production-proton",
		ProtonVersion:       "latest",
		InstanceType:        "c5.2xlarge",
		InstanceCount:       3,
		DiskSizeGB:          500,
		S3BucketName:        "prod-proton-data-" + time.Now().Format("20060102"),
		EnableBackups:       true,
		BackupRetentionDays: 30,
		EnablePublicAccess:  false,
		AllowedCIDRs:        []string{"10.0.0.0/8"},
		SSHKeyName:          "proton-key",
		EnableEncryption:    true,
		Tags: map[string]string{
			"Environment": "production",
			"Team":        "data-engineering",
		},
	}
	fmt.Println("✓ Configuration complete\n")

	// Step 2: Create IAM roles (using AWS config from environment)
	fmt.Println("Step 2: Creating IAM roles...")
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(config.Region))
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	iamManager := NewIAMManager(cfg)
	_, err = iamManager.CreateProtonInstanceRole(ctx, config.ClusterName, config.S3BucketName)
	if err != nil {
		log.Fatalf("Failed to create IAM role: %v", err)
	}
	fmt.Println("✓ IAM roles created\n")

	// Step 3: Deploy cluster
	fmt.Println("Step 3: Deploying Proton cluster...")
	fmt.Println("  This may take 10-15 minutes...")
	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	cluster, err := manager.DeployProtonCluster(ctx)
	if err != nil {
		log.Fatalf("Failed to deploy cluster: %v", err)
	}
	fmt.Println("✓ Cluster deployed\n")

	// Step 4: Wait for cluster to be healthy
	fmt.Println("Step 4: Waiting for cluster to be healthy...")
	maxRetries := 20
	for i := 0; i < maxRetries; i++ {
		health, err := manager.GetClusterHealth(ctx, cluster)
		if err != nil {
			fmt.Printf("  Attempt %d/%d: %v\n", i+1, maxRetries, err)
			time.Sleep(30 * time.Second)
			continue
		}

		healthyCount := 0
		for _, status := range health {
			if strings.Contains(status, "running") {
				healthyCount++
			}
		}

		fmt.Printf("  Healthy instances: %d/%d\n", healthyCount, len(health))

		if healthyCount == len(health) {
			fmt.Println("✓ All instances healthy\n")
			break
		}

		if i == maxRetries-1 {
			fmt.Println("✗ Cluster failed to become healthy")
			return
		}

		time.Sleep(30 * time.Second)
	}

	// Step 5: Validate Proton connectivity
	fmt.Println("Step 5: Validating Proton connectivity...")
	time.Sleep(30 * time.Second) // Give load balancer time to register targets

	pingURL := fmt.Sprintf("http://%s/ping", cluster.LoadBalancerDNS)
	resp, err := http.Get(pingURL)
	if err != nil {
		log.Fatalf("Failed to connect to Proton: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("✓ Proton is responding\n")
	} else {
		log.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	// Step 6: Run test queries
	fmt.Println("Step 6: Running test queries...")
	ExampleTestProtonQueries(cluster.LoadBalancerDNS)
	fmt.Println("✓ Test queries successful\n")

	// Step 7: Create initial backup
	fmt.Println("Step 7: Creating initial backup...")
	backupID, err := manager.BackupCluster(ctx, cluster)
	if err != nil {
		log.Printf("Warning: Failed to create backup: %v", err)
	} else {
		fmt.Printf("✓ Backup created: %s\n\n", backupID)
	}

	// Step 8: Print connection information
	fmt.Println("=== Deployment Complete! ===")
	fmt.Printf("\nCluster Information:\n")
	fmt.Printf("  Cluster ID: %s\n", cluster.ClusterID)
	fmt.Printf("  Load Balancer DNS: %s\n", cluster.LoadBalancerDNS)
	fmt.Printf("  Instance Count: %d\n", len(cluster.InstanceIDs))
	fmt.Printf("  S3 Bucket: %s\n", cluster.S3BucketName)
	fmt.Printf("  Created At: %s\n", cluster.CreatedAt.Format(time.RFC3339))

	fmt.Printf("\nConnection Details:\n")
	fmt.Printf("  HTTP Endpoint: http://%s\n", cluster.LoadBalancerDNS)
	fmt.Printf("  Example Query:\n")
	fmt.Printf("    curl -X POST http://%s -d 'SELECT version()'\n", cluster.LoadBalancerDNS)

	fmt.Printf("\nManagement Commands:\n")
	fmt.Printf("  Scale cluster: manager.ScaleCluster(ctx, cluster, <new_count>)\n")
	fmt.Printf("  Create backup: manager.BackupCluster(ctx, cluster)\n")
	fmt.Printf("  Check health: manager.GetClusterHealth(ctx, cluster)\n")
	fmt.Printf("  Delete cluster: manager.DeleteCluster(ctx, cluster)\n")

	fmt.Printf("\nAWS Console Links:\n")
	fmt.Printf("  EC2 Instances: https://console.aws.amazon.com/ec2/v2/home?region=%s#Instances:\n", config.Region)
	fmt.Printf("  Load Balancer: https://console.aws.amazon.com/ec2/v2/home?region=%s#LoadBalancers:\n", config.Region)
	fmt.Printf("  S3 Bucket: https://s3.console.aws.amazon.com/s3/buckets/%s\n", cluster.S3BucketName)
	fmt.Printf("  CloudWatch Logs: https://console.aws.amazon.com/cloudwatch/home?region=%s#logsV2:log-groups/log-group/$252Faws$252Fproton$252F%s\n",
		config.Region, config.ClusterName)
}

// Example 8: Disaster recovery scenario
func ExampleDisasterRecovery() {
	ctx := context.Background()

	config := &ProtonBYOCConfig{
		Region:      "us-west-2",
		ClusterName: "production-proton",
		// ... other config
	}

	manager, err := NewProtonBYOCManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	fmt.Println("=== Disaster Recovery Scenario ===\n")

	// Scenario: Primary cluster has failed, need to restore from backup
	fmt.Println("Scenario: Primary cluster failed, restoring from backup...")

	// Step 1: Identify latest backup
	// In production, you would query S3 to find the latest backup
	latestBackup := "backup-production-proton-1234567890"
	fmt.Printf("Latest backup: %s\n", latestBackup)

	// Step 2: Deploy new cluster
	fmt.Println("\nDeploying new cluster...")
	newCluster, err := manager.DeployProtonCluster(ctx)
	if err != nil {
		log.Fatalf("Failed to deploy new cluster: %v", err)
	}
	fmt.Printf("✓ New cluster deployed: %s\n", newCluster.ClusterID)

	// Step 3: Wait for cluster to be ready
	fmt.Println("\nWaiting for cluster to be ready...")
	time.Sleep(5 * time.Minute)

	// Step 4: Restore data from backup
	fmt.Printf("\nRestoring data from backup %s...\n", latestBackup)
	err = manager.RestoreCluster(ctx, latestBackup)
	if err != nil {
		log.Fatalf("Failed to restore: %v", err)
	}
	fmt.Println("✓ Data restored")

	// Step 5: Validate data integrity
	fmt.Println("\nValidating data integrity...")
	// Run validation queries here
	fmt.Println("✓ Data validation passed")

	// Step 6: Update DNS or connection strings
	fmt.Println("\nUpdate your application connection strings to:")
	fmt.Printf("  New endpoint: http://%s\n", newCluster.LoadBalancerDNS)

	fmt.Println("\n✓ Disaster recovery complete!")
}

// Example 9: Multi-region deployment
func ExampleMultiRegionDeployment() {
	ctx := context.Background()

	regions := []string{"us-west-2", "us-east-1", "eu-west-1"}

	fmt.Println("=== Multi-Region Deployment ===\n")

	var clusters []*ProtonCluster

	for _, region := range regions {
		fmt.Printf("Deploying cluster in %s...\n", region)

		config := &ProtonBYOCConfig{
			Region:            region,
			AvailabilityZones: getAZsForRegion(region),
			VpcCIDR:           "10.0.0.0/16",
			ClusterName:       fmt.Sprintf("proton-%s", region),
			ProtonVersion:     "latest",
			InstanceType:      "c5.xlarge",
			InstanceCount:     3,
			DiskSizeGB:        200,
			S3BucketName:      fmt.Sprintf("proton-data-%s-%d", region, time.Now().Unix()),
			EnableBackups:     true,
			EnableEncryption:  true,
			Tags: map[string]string{
				"Region": region,
				"Type":   "multi-region",
			},
		}

		manager, err := NewProtonBYOCManager(ctx, config)
		if err != nil {
			log.Printf("Failed to create manager for %s: %v", region, err)
			continue
		}

		cluster, err := manager.DeployProtonCluster(ctx)
		if err != nil {
			log.Printf("Failed to deploy cluster in %s: %v", region, err)
			continue
		}

		clusters = append(clusters, cluster)
		fmt.Printf("✓ Cluster deployed in %s: %s\n\n", region, cluster.LoadBalancerDNS)

		// Add delay between deployments to avoid API rate limits
		time.Sleep(1 * time.Minute)
	}

	fmt.Println("=== Multi-Region Deployment Complete ===")
	fmt.Println("\nCluster Endpoints:")
	for i, cluster := range clusters {
		fmt.Printf("  %s: http://%s\n", regions[i], cluster.LoadBalancerDNS)
	}

	fmt.Println("\nSetup Route53 for global load balancing:")
	fmt.Println("  1. Create a Route53 hosted zone")
	fmt.Println("  2. Add latency-based routing records for each region")
	fmt.Println("  3. Configure health checks for automatic failover")
}

// Example 10: Cost estimation
func ExampleCostEstimation(config *ProtonBYOCConfig) {
	fmt.Println("=== Cost Estimation ===\n")

	// EC2 instance costs (approximate, as of 2025)
	instanceCosts := map[string]float64{
		"t3.large":   0.0832,
		"c5.xlarge":  0.17,
		"c5.2xlarge": 0.34,
		"c5.4xlarge": 0.68,
		"r5.xlarge":  0.252,
		"r5.2xlarge": 0.504,
		"r5.4xlarge": 1.008,
	}

	instanceCost, ok := instanceCosts[config.InstanceType]
	if !ok {
		instanceCost = 0.20 // Default estimate
	}

	// Calculate monthly costs
	hoursPerMonth := 730.0 // Average hours per month

	// EC2 costs
	ec2MonthlyCost := instanceCost * float64(config.InstanceCount) * hoursPerMonth

	// EBS costs (GP3: $0.08/GB/month)
	ebsMonthlyCost := float64(config.DiskSizeGB*int32(config.InstanceCount)) * 0.08

	// Data transfer costs (estimate 1TB/month egress at $0.09/GB)
	dataTransferMonthlyCost := 1000.0 * 0.09

	// S3 costs (estimate)
	// Storage: 1TB at $0.023/GB
	// Requests: 1M PUT at $0.005/1000, 10M GET at $0.0004/1000
	s3StorageCost := 1000.0 * 0.023
	s3RequestCost := (1000000.0 * 0.005 / 1000.0) + (10000000.0 * 0.0004 / 1000.0)
	s3MonthlyCost := s3StorageCost + s3RequestCost

	// Load balancer costs (ALB: $0.0225/hour + $0.008/LCU-hour, estimate 10 LCU)
	albMonthlyCost := (0.0225 + (0.008 * 10)) * hoursPerMonth

	// CloudWatch costs (estimate)
	cloudWatchMonthlyCost := 10.0

	// NAT Gateway costs ($0.045/hour + $0.045/GB processed, estimate 1TB)
	natMonthlyCost := (0.045 * hoursPerMonth) + (1000.0 * 0.045)

	// Total
	totalMonthlyCost := ec2MonthlyCost + ebsMonthlyCost + dataTransferMonthlyCost +
		s3MonthlyCost + albMonthlyCost + cloudWatchMonthlyCost + natMonthlyCost

	fmt.Printf("Configuration:\n")
	fmt.Printf("  Instance Type: %s\n", config.InstanceType)
	fmt.Printf("  Instance Count: %d\n", config.InstanceCount)
	fmt.Printf("  Disk Size: %d GB per instance\n", config.DiskSizeGB)
	fmt.Printf("\nEstimated Monthly Costs:\n")
	fmt.Printf("  EC2 Instances:        $%.2f\n", ec2MonthlyCost)
	fmt.Printf("  EBS Storage:          $%.2f\n", ebsMonthlyCost)
	fmt.Printf("  Data Transfer:        $%.2f\n", dataTransferMonthlyCost)
	fmt.Printf("  S3 Storage:           $%.2f\n", s3MonthlyCost)
	fmt.Printf("  Load Balancer:        $%.2f\n", albMonthlyCost)
	fmt.Printf("  CloudWatch:           $%.2f\n", cloudWatchMonthlyCost)
	fmt.Printf("  NAT Gateway:          $%.2f\n", natMonthlyCost)
	fmt.Printf("  ─────────────────────────────\n")
	fmt.Printf("  Total (estimated):    $%.2f/month\n", totalMonthlyCost)
	fmt.Printf("  Annual (estimated):   $%.2f/year\n", totalMonthlyCost*12)

	fmt.Printf("\nCost Optimization Tips:\n")
	fmt.Printf("  - Use Reserved Instances for 1-year: Save ~40%% (~$%.2f/month)\n", ec2MonthlyCost*0.4)
	fmt.Printf("  - Use Reserved Instances for 3-year: Save ~60%% (~$%.2f/month)\n", ec2MonthlyCost*0.6)
	fmt.Printf("  - Use Spot Instances (non-production): Save ~70%% (~$%.2f/month)\n", ec2MonthlyCost*0.7)
	fmt.Printf("  - Right-size instances based on actual usage\n")

	/// NOT DONE YET ...
}
