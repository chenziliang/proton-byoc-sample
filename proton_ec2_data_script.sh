#!/bin/bash
# User data script for initializing Proton instances
# This script is executed when the EC2 instance first starts

set -e  # Exit on any error
set -x  # Print commands for debugging

# Variables (these will be templated by Terraform or Go code)
CLUSTER_NAME="${cluster_name}"
PROTON_VERSION="${proton_version}"
S3_BUCKET="${s3_bucket}"
AWS_REGION="${aws_region}"

# Log output to file for troubleshooting
exec > >(tee /var/log/proton-init.log)
exec 2>&1

echo "========================================="
echo "Starting Proton BYOC Installation"
echo "Cluster: $CLUSTER_NAME"
echo "Version: $PROTON_VERSION"
echo "Region: $AWS_REGION"
echo "========================================="

# Update system packages
echo "[1/10] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Install required dependencies
echo "[2/10] Installing dependencies..."
apt-get install -y \
    curl \
    wget \
    apt-transport-https \
    ca-certificates \
    software-properties-common \
    gnupg \
    lsb-release \
    jq \
    unzip

# Install Docker
echo "[3/10] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    
    # Add ubuntu user to docker group for non-root access
    usermod -aG docker ubuntu || true
fi

# Verify Docker installation
docker --version

# Install Docker Compose
echo "[4/10] Installing Docker Compose..."
DOCKER_COMPOSE_VERSION="2.24.0"
curl -L "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version

# Install AWS CLI
echo "[5/10] Installing AWS CLI..."
if ! command -v aws &> /dev/null; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    ./aws/install
    rm -rf aws awscliv2.zip
fi

aws --version

# Configure AWS CLI with instance region
aws configure set default.region $AWS_REGION

# Install CloudWatch Agent
echo "[6/10] Installing CloudWatch Agent..."
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb
rm amazon-cloudwatch-agent.deb

# Create Proton directories
echo "[7/10] Creating Proton directories..."
mkdir -p /var/lib/proton/data
mkdir -p /var/lib/proton/logs
mkdir -p /var/lib/proton/config
mkdir -p /var/lib/proton/tmp
mkdir -p /etc/proton

# Set proper permissions
chown -R ubuntu:ubuntu /var/lib/proton
chmod 755 /var/lib/proton

# Get instance metadata
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
AVAILABILITY_ZONE=$(ec2-metadata --availability-zone | cut -d " " -f 2)
LOCAL_IPV4=$(ec2-metadata --local-ipv4 | cut -d " " -f 2)

echo "Instance ID: $INSTANCE_ID"
echo "Availability Zone: $AVAILABILITY_ZONE"
echo "Local IPv4: $LOCAL_IPV4"

# Create Proton configuration file
echo "[8/10] Creating Proton configuration..."
cat > /etc/proton/config.xml <<EOL
<?xml version="1.0"?>
<proton>
    <!-- Logging configuration -->
    <logger>
        <level>information</level>
        <log>/var/lib/proton/logs/proton.log</log>
        <errorlog>/var/lib/proton/logs/proton.err.log</errorlog>
        <size>1000M</size>
        <count>10</count>
    </logger>

    <!-- Network interfaces -->
    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    <interserver_http_port>9009</interserver_http_port>

    <!-- Listen on all interfaces -->
    <listen_host>0.0.0.0</listen_host>

    <!-- Data paths -->
    <path>/var/lib/proton/data/</path>
    <tmp_path>/var/lib/proton/tmp/</tmp_path>
    <user_files_path>/var/lib/proton/user_files/</user_files_path>
    <format_schema_path>/var/lib/proton/format_schemas/</format_schema_path>

    <!-- S3 storage configuration -->
    <storage_configuration>
        <disks>
            <s3_disk>
                <type>s3</type>
                <endpoint>https://s3.$AWS_REGION.amazonaws.com/$S3_BUCKET/data/</endpoint>
                <use_environment_credentials>true</use_environment_credentials>
                <region>$AWS_REGION</region>
            </s3_disk>
        </disks>
        <policies>
            <default>
                <volumes>
                    <main>
                        <disk>default</disk>
                    </main>
                    <s3_volume>
                        <disk>s3_disk</disk>
                    </s3_volume>
                </volumes>
            </default>
        </policies>
    </storage_configuration>

    <!-- Memory settings (adjust based on instance type) -->
    <max_server_memory_usage_to_ram_ratio>0.9</max_server_memory_usage_to_ram_ratio>
    <max_concurrent_queries>100</max_concurrent_queries>
    <max_connections>4096</max_connections>

    <!-- Performance settings -->
    <mark_cache_size>5368709120</mark_cache_size>
    <background_pool_size>16</background_pool_size>
    <background_schedule_pool_size>16</background_schedule_pool_size>

    <!-- Distributed configuration (for multi-node clusters) -->
    <remote_servers>
        <proton_cluster>
            <shard>
                <replica>
                    <host>$LOCAL_IPV4</host>
                    <port>9000</port>
                </replica>
            </shard>
        </proton_cluster>
    </remote_servers>

    <!-- Timezone -->
    <timezone>UTC</timezone>

    <!-- User configuration -->
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>

    <!-- Profiles -->
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
        </default>
    </profiles>

    <!-- Quotas -->
    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</proton>
EOL

# Create systemd service for Proton
echo "[9/10] Creating Proton systemd service..."
cat > /etc/systemd/system/proton.service <<EOL
[Unit]
Description=Timeplus Proton Streaming Database
After=docker.service
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=10
User=root
StandardOutput=append:/var/lib/proton/logs/proton-service.log
StandardError=append:/var/lib/proton/logs/proton-service.err.log

# Pull latest image on restart
ExecStartPre=/usr/bin/docker pull ghcr.io/timeplus-io/proton:$PROTON_VERSION

# Remove any existing container
ExecStartPre=-/usr/bin/docker rm -f proton

# Start Proton container
ExecStart=/usr/bin/docker run --rm \
    --name proton \
    --network host \
    -v /var/lib/proton/data:/var/lib/proton/data \
    -v /var/lib/proton/logs:/var/lib/proton/logs \
    -v /var/lib/proton/tmp:/var/lib/proton/tmp \
    -v /etc/proton/config.xml:/etc/proton-server/config.xml \
    -e AWS_REGION=$AWS_REGION \
    -e INSTANCE_ID=$INSTANCE_ID \
    -e CLUSTER_NAME=$CLUSTER_NAME \
    ghcr.io/timeplus-io/proton:$PROTON_VERSION

# Stop container
ExecStop=/usr/bin/docker stop proton

[Install]
WantedBy=multi-user.target
EOL

# Configure CloudWatch Agent
echo "[10/10] Configuring CloudWatch Agent..."
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOL
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "metrics": {
    "namespace": "ProtonCluster/$CLUSTER_NAME",
    "metrics_collected": {
      "cpu": {
        "measurement": [
          {
            "name": "cpu_usage_idle",
            "rename": "CPU_IDLE",
            "unit": "Percent"
          },
          {
            "name": "cpu_usage_iowait",
            "rename": "CPU_IOWAIT",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60,
        "totalcpu": false
      },
      "disk": {
        "measurement": [
          {
            "name": "used_percent",
            "rename": "DISK_USED",
            "unit": "Percent"
          },
          {
            "name": "inodes_free",
            "rename": "DISK_INODES_FREE",
            "unit": "Count"
          }
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "*"
        ]
      },
      "diskio": {
        "measurement": [
          {
            "name": "io_time",
            "rename": "DISK_IO_TIME",
            "unit": "Milliseconds"
          },
          {
            "name": "read_bytes",
            "rename": "DISK_READ_BYTES",
            "unit": "Bytes"
          },
          {
            "name": "write_bytes",
            "rename": "DISK_WRITE_BYTES",
            "unit": "Bytes"
          }
        ],
        "metrics_collection_interval": 60
      },
      "mem": {
        "measurement": [
          {
            "name": "mem_used_percent",
            "rename": "MEM_USED",
            "unit": "Percent"
          },
          {
            "name": "mem_available",
            "rename": "MEM_AVAILABLE",
            "unit": "Megabytes"
          }
        ],
        "metrics_collection_interval": 60
      },
      "netstat": {
        "measurement": [
          {
            "name": "tcp_established",
            "rename": "TCP_ESTABLISHED",
            "unit": "Count"
          },
          {
            "name": "tcp_time_wait",
            "rename": "TCP_TIME_WAIT",
            "unit": "Count"
          }
        ],
        "metrics_collection_interval": 60
      },
      "swap": {
        "measurement": [
          {
            "name": "swap_used_percent",
            "rename": "SWAP_USED",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60
      }
    },
    "append_dimensions": {
      "InstanceId": "$INSTANCE_ID",
      "InstanceType": "\${aws:InstanceType}",
      "AutoScalingGroupName": "\${aws:AutoScalingGroupName}"
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/lib/proton/logs/proton.log",
            "log_group_name": "/aws/proton/$CLUSTER_NAME",
            "log_stream_name": "{instance_id}/proton.log",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/lib/proton/logs/proton.err.log",
            "log_group_name": "/aws/proton/$CLUSTER_NAME",
            "log_stream_name": "{instance_id}/proton.err.log",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/lib/proton/logs/proton-service.log",
            "log_group_name": "/aws/proton/$CLUSTER_NAME",
            "log_stream_name": "{instance_id}/service.log",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/proton-init.log",
            "log_group_name": "/aws/proton/$CLUSTER_NAME",
            "log_stream_name": "{instance_id}/init.log",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOL

# Start CloudWatch Agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

# Enable and start Proton service
echo "Enabling and starting Proton service..."
systemctl daemon-reload
systemctl enable proton.service
systemctl start proton.service

# Wait for Proton to start
echo "Waiting for Proton to become ready..."
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
        echo "✓ Proton is ready!"
        break
    fi
    echo "Waiting for Proton to start... ($((RETRY_COUNT + 1))/$MAX_RETRIES)"
    sleep 10
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "✗ Proton failed to start within expected time"
    systemctl status proton.service
    exit 1
fi

# Create a health check script
cat > /usr/local/bin/proton-health-check.sh <<'EOL'
#!/bin/bash
# Health check script for Proton

# Check if Docker container is running
if ! docker ps | grep -q proton; then
    echo "ERROR: Proton container is not running"
    exit 1
fi

# Check if Proton is responding to HTTP requests
if ! curl -sf http://localhost:8123/ping > /dev/null; then
    echo "ERROR: Proton is not responding to HTTP requests"
    exit 1
fi

# Check if Proton native port is listening
if ! netstat -tuln | grep -q ":9000 "; then
    echo "ERROR: Proton native port (9000) is not listening"
    exit 1
fi

echo "OK: Proton is healthy"
exit 0
EOL

chmod +x /usr/local/bin/proton-health-check.sh

# Create a backup script
cat > /usr/local/bin/proton-backup.sh <<EOL
#!/bin/bash
# Backup script for Proton data

set -e

BACKUP_DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="backups/\$BACKUP_DATE"
S3_PATH="s3://$S3_BUCKET/\$BACKUP_PATH"

echo "Starting Proton backup to \$S3_PATH..."

# Create a backup using Proton's BACKUP command
# This is a placeholder - actual implementation depends on Proton's backup capabilities
docker exec proton proton-client --query "BACKUP DATABASE default TO Disk('s3_disk', '\$BACKUP_PATH')" || true

# Sync local data to S3 as additional backup
aws s3 sync /var/lib/proton/data \$S3_PATH/data --storage-class STANDARD_IA

# Create backup manifest
cat > /tmp/backup-manifest.json <<MANIFEST
{
  "backup_id": "\$BACKUP_DATE",
  "cluster_name": "$CLUSTER_NAME",
  "instance_id": "$INSTANCE_ID",
  "timestamp": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "s3_location": "\$S3_PATH"
}
MANIFEST

aws s3 cp /tmp/backup-manifest.json \$S3_PATH/manifest.json
rm /tmp/backup-manifest.json

echo "Backup completed: \$S3_PATH"
EOL

chmod +x /usr/local/bin/proton-backup.sh

# Create a restore script
cat > /usr/local/bin/proton-restore.sh <<EOL
#!/bin/bash
# Restore script for Proton data

set -e

if [ -z "\$1" ]; then
    echo "Usage: \$0 <backup-date>"
    echo "Example: \$0 20250101_120000"
    exit 1
fi

BACKUP_DATE=\$1
BACKUP_PATH="backups/\$BACKUP_DATE"
S3_PATH="s3://$S3_BUCKET/\$BACKUP_PATH"

echo "Restoring Proton from \$S3_PATH..."

# Stop Proton service
systemctl stop proton.service

# Backup current data
mv /var/lib/proton/data /var/lib/proton/data.backup.\$(date +%s)

# Restore data from S3
mkdir -p /var/lib/proton/data
aws s3 sync \$S3_PATH/data /var/lib/proton/data

# Fix permissions
chown -R ubuntu:ubuntu /var/lib/proton/data

# Start Proton service
systemctl start proton.service

echo "Restore completed from \$BACKUP_PATH"
EOL

chmod +x /usr/local/bin/proton-restore.sh

# Setup cron job for automated backups (daily at 2 AM)
cat > /etc/cron.d/proton-backup <<EOL
# Proton automated backup - runs daily at 2 AM UTC
0 2 * * * root /usr/local/bin/proton-backup.sh >> /var/log/proton-backup.log 2>&1
EOL

# Create a monitoring script for Proton metrics
cat > /usr/local/bin/proton-metrics.sh <<'EOL'
#!/bin/bash
# Collect and push custom Proton metrics to CloudWatch

NAMESPACE="ProtonCluster/$CLUSTER_NAME"
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)

# Query Proton for metrics
QUERY_COUNT=$(docker exec proton proton-client --query "SELECT count() FROM system.query_log WHERE event_time > now() - INTERVAL 1 MINUTE" 2>/dev/null | tail -1 || echo 0)
QUERY_DURATION=$(docker exec proton proton-client --query "SELECT avg(query_duration_ms) FROM system.query_log WHERE event_time > now() - INTERVAL 1 MINUTE" 2>/dev/null | tail -1 || echo 0)

# Push metrics to CloudWatch
aws cloudwatch put-metric-data \
    --namespace "$NAMESPACE" \
    --metric-name QueriesPerMinute \
    --value $QUERY_COUNT \
    --dimensions InstanceId=$INSTANCE_ID \
    --unit Count

aws cloudwatch put-metric-data \
    --namespace "$NAMESPACE" \
    --metric-name AvgQueryDuration \
    --value $QUERY_DURATION \
    --dimensions InstanceId=$INSTANCE_ID \
    --unit Milliseconds
EOL

chmod +x /usr/local/bin/proton-metrics.sh

# Setup cron job for metrics collection (every 5 minutes)
cat > /etc/cron.d/proton-metrics <<EOL
# Proton metrics collection - runs every 5 minutes
*/5 * * * * root /usr/local/bin/proton-metrics.sh >> /var/log/proton-metrics.log 2>&1
EOL

# Tag the instance with Proton information
aws ec2 create-tags \
    --resources $INSTANCE_ID \
    --tags \
        Key=Name,Value="$CLUSTER_NAME-proton-instance" \
        Key=Cluster,Value="$CLUSTER_NAME" \
        Key=ProtonVersion,Value="$PROTON_VERSION" \
        Key=InitializedAt,Value="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --region $AWS_REGION || true

# Create a status file
cat > /var/lib/proton/status.json <<EOL
{
  "cluster_name": "$CLUSTER_NAME",
  "instance_id": "$INSTANCE_ID",
  "availability_zone": "$AVAILABILITY_ZONE",
  "local_ipv4": "$LOCAL_IPV4",
  "proton_version": "$PROTON_VERSION",
  "s3_bucket": "$S3_BUCKET",
  "initialized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "ready"
}
EOL

# Print completion message
echo "========================================="
echo "Proton BYOC Installation Complete!"
echo "========================================="
echo "Cluster Name: $CLUSTER_NAME"
echo "Instance ID: $INSTANCE_ID"
echo "Proton Version: $PROTON_VERSION"
echo "HTTP Endpoint: http://$LOCAL_IPV4:8123"
echo "Native TCP Port: $LOCAL_IPV4:9000"
echo ""
echo "Useful commands:"
echo "  - Check status: systemctl status proton"
echo "  - View logs: journalctl -u proton -f"
echo "  - Health check: /usr/local/bin/proton-health-check.sh"
echo "  - Create backup: /usr/local/bin/proton-backup.sh"
echo "  - Restore: /usr/local/bin/proton-restore.sh <backup-date>"
echo "========================================="

# Send completion notification to CloudWatch
aws cloudwatch put-metric-data \
    --namespace "$NAMESPACE" \
    --metric-name InstanceInitialized \
    --value 1 \
    --dimensions InstanceId=$INSTANCE_ID \
    --unit Count \
    --region $AWS_REGION || true

# Exit successfully
exit 0
