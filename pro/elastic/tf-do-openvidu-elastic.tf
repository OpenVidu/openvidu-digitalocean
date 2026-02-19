# -------------- VPC and Firewalls ----------------

resource "digitalocean_vpc" "openvidu_vpc" {
  name     = "${var.stackName}-vpc"
  region   = var.region
  ip_range = "10.10.10.0/24"
}

resource "digitalocean_tag" "media_node_tag" {
  name = "${var.stackName}-media-node-tag"
}

# Firewall for Master Node - external access
resource "digitalocean_firewall" "master_firewall" {
  name = "${var.stackName}-master-firewall"

  droplet_ids = [digitalocean_droplet.openvidu_master_node.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "1935"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Firewall for Media Nodes - external access
resource "digitalocean_firewall" "media_firewall" {
  name = "${var.stackName}-media-firewall"

  tags = [digitalocean_tag.media_node_tag.name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7881"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "50000-60000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "7885"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "50000-60000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Firewall for Media Nodes to Master Node internal communication
resource "digitalocean_firewall" "media_to_master_firewall" {
  name = "${var.stackName}-media-to-master-firewall"

  droplet_ids = [digitalocean_droplet.openvidu_master_node.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "4443"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9080"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "3100"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7880"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9009"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7000"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9100"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "20000"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }
}

# Firewall for Master Node to Media Nodes internal communication
resource "digitalocean_firewall" "master_to_media_firewall" {
  name = "${var.stackName}-master-to-media-firewall"

  tags = [digitalocean_tag.media_node_tag.name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "1935"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "5349"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7880"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "8080"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }
}

# --------------------- droplets -----------------------

# SSH key
resource "tls_private_key" "openvidu_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "digitalocean_ssh_key" "openvidu_ssh_key_do" {
  name       = "${var.stackName}-ssh-key"
  public_key = tls_private_key.openvidu_ssh_key.public_key_openssh
}

# Master Node
resource "digitalocean_droplet" "openvidu_master_node" {
  name   = "${var.stackName}-master-node"
  image  = "ubuntu-24-04-x64"
  region = var.region
  size   = var.masterNodeInstanceType

  ssh_keys = [digitalocean_ssh_key.openvidu_ssh_key_do.id]
  vpc_uuid = digitalocean_vpc.openvidu_vpc.id
  tags     = ["openvidu", var.stackName, "master-node"]

  user_data = local.user_data_master
}

# Master Node IP
resource "digitalocean_reserved_ip" "master_public_ip" {
  droplet_id = digitalocean_droplet.openvidu_master_node.id
  region     = var.region
}

# Media node Autoscale Pool
resource "digitalocean_droplet_autoscale" "media_node_pool" {
  name = "${var.stackName}-media-node-pool"

  config {
    # min_instances          = var.minNumberOfMediaNodes
    # max_instances          = var.maxNumberOfMediaNodes
    # target_cpu_utilization = var.scaleTargetCPU / 100
    target_number_instances = var.fixedNumberOfMediaNodes
    # cooldown_minutes       = 5
  }

  droplet_template {
    size      = var.mediaNodeInstanceType
    region    = var.region
    image     = "ubuntu-24-04-x64"
    tags      = [digitalocean_tag.media_node_tag.name]
    ssh_keys  = [digitalocean_ssh_key.openvidu_ssh_key_do.id]
    user_data = local.user_data_media
    vpc_uuid  = digitalocean_vpc.openvidu_vpc.id
  }

  depends_on = [digitalocean_droplet.openvidu_master_node]
}

# DigitalOcean Space
resource "digitalocean_spaces_bucket" "openvidu_space" {
  count  = var.spaceName == "" ? 1 : 0
  name   = "openvidu-appdata"
  region = var.spaceRegion
  acl    = "private"
}

resource "digitalocean_spaces_key" "openvidu_space_key" {
  name = "${var.stackName}-space-key"
  grant {
    bucket     = var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName
    permission = "readwrite"
  }
}

locals {
  install_script_master = <<-EOF
#!/bin/bash -x
set -e

OPENVIDU_VERSION=main
DOMAIN=
echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout

# Install dependencies
apt-get update && apt-get install -y

# Create counter file for tracking script executions
echo 1 > /usr/local/bin/openvidu_install_counter.txt

mkdir -p /opt/openvidu
touch /opt/openvidu/secrets.env

# Get IPs using DO metadata
PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/floating_ip/ipv4/ip_address)
MASTER_NODE_PRIVATE_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address)

if [[ "${var.domainName}" == "" ]]; then
  [ ! -d "/usr/share/openvidu" ] && mkdir -p /usr/share/openvidu
  RANDOM_DOMAIN_STRING=$(tr -dc 'a-z' < /dev/urandom | head -c 8)
  DOMAIN="openvidu-$RANDOM_DOMAIN_STRING-$(echo $PUBLIC_IP | tr '.' '-').sslip.io"
else
  DOMAIN="${var.domainName}"
fi
DOMAIN="$(/usr/local/bin/store_secret.sh save DOMAIN_NAME "$DOMAIN")"

# Meet initial admin user and password
MEET_INITIAL_ADMIN_USER="$(/usr/local/bin/store_secret.sh save MEET_INITIAL_ADMIN_USER "admin")"
if [[ "${var.initialMeetAdminPassword}" != '' ]]; then
  MEET_INITIAL_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh save MEET_INITIAL_ADMIN_PASSWORD "${var.initialMeetAdminPassword}")"
else
  MEET_INITIAL_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate MEET_INITIAL_ADMIN_PASSWORD)"
fi

if [[ "${var.initialMeetApiKey}" != '' ]]; then
  MEET_INITIAL_API_KEY="$(/usr/local/bin/store_secret.sh save MEET_INITIAL_API_KEY "${var.initialMeetApiKey}")"
fi

REDIS_PASSWORD="$(/usr/local/bin/store_secret.sh generate REDIS_PASSWORD)"
MONGO_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save MONGO_ADMIN_USERNAME "mongoadmin")"
MONGO_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate MONGO_ADMIN_PASSWORD)"
MONGO_REPLICA_SET_KEY="$(/usr/local/bin/store_secret.sh generate MONGO_REPLICA_SET_KEY)"
MINIO_ACCESS_KEY="$(/usr/local/bin/store_secret.sh save MINIO_ACCESS_KEY "minioadmin")"
MINIO_SECRET_KEY="$(/usr/local/bin/store_secret.sh generate MINIO_SECRET_KEY)"
DASHBOARD_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save DASHBOARD_ADMIN_USERNAME "dashboardadmin")"
DASHBOARD_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate DASHBOARD_ADMIN_PASSWORD)"
GRAFANA_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save GRAFANA_ADMIN_USERNAME "grafanaadmin")"
GRAFANA_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate GRAFANA_ADMIN_PASSWORD)"
ENABLED_MODULES="$(/usr/local/bin/store_secret.sh save ENABLED_MODULES "observability,openviduMeet")"
LIVEKIT_API_KEY="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_KEY "API" 12)"
LIVEKIT_API_SECRET="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_SECRET)"
OPENVIDU_PRO_LICENSE="$(/usr/local/bin/store_secret.sh save OPENVIDU_PRO_LICENSE "${var.openviduLicense}")"
OPENVIDU_RTC_ENGINE="$(/usr/local/bin/store_secret.sh save OPENVIDU_RTC_ENGINE "${var.rtcEngine}")"
OPENVIDU_VERSION="$(/usr/local/bin/store_secret.sh save OPENVIDU_VERSION "$OPENVIDU_VERSION")"
MASTER_NODE_PRIVATE_IP="$(/usr/local/bin/store_secret.sh save MASTER_NODE_PRIVATE_IP "$MASTER_NODE_PRIVATE_IP")"

ALL_SECRETS_GENERATED="$(/usr/local/bin/store_secret.sh save ALL_SECRETS_GENERATED "true")"

# Build install command
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/pro/elastic/$OPENVIDU_VERSION/install_ov_master_node.sh)"

# Common arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=on_premise"
  "--deployment-type=elastic"
  "--node-role=master-node"
  "--openvidu-pro-license=$OPENVIDU_PRO_LICENSE"
  "--private-ip=$MASTER_NODE_PRIVATE_IP"
  "--domain-name=$DOMAIN"
  "--enabled-modules='$ENABLED_MODULES'"
  "--rtc-engine=$OPENVIDU_RTC_ENGINE"
  "--redis-password=$REDIS_PASSWORD"
  "--mongo-admin-user=$MONGO_ADMIN_USERNAME"
  "--mongo-admin-password=$MONGO_ADMIN_PASSWORD"
  "--mongo-replica-set-key=$MONGO_REPLICA_SET_KEY"
  "--minio-access-key=$MINIO_ACCESS_KEY"
  "--minio-secret-key=$MINIO_SECRET_KEY"
  "--dashboard-admin-user=$DASHBOARD_ADMIN_USERNAME"
  "--dashboard-admin-password=$DASHBOARD_ADMIN_PASSWORD"
  "--grafana-admin-user=$GRAFANA_ADMIN_USERNAME"
  "--grafana-admin-password=$GRAFANA_ADMIN_PASSWORD"
  "--meet-initial-admin-password=$MEET_INITIAL_ADMIN_PASSWORD"
  "--meet-initial-api-key=$MEET_INITIAL_API_KEY"
  "--livekit-api-key=$LIVEKIT_API_KEY"
  "--livekit-api-secret=$LIVEKIT_API_SECRET"
)

# Include additional installer flags provided by the user
if [[ "${var.additionalInstallFlags}" != "" ]]; then
  IFS=',' read -ra EXTRA_FLAGS <<< "${var.additionalInstallFlags}"
  for extra_flag in "$${EXTRA_FLAGS[@]}"; do
    # Trim whitespace around each flag
    extra_flag="$(echo -e "$${extra_flag}" | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')"
    if [[ "$extra_flag" != "" ]]; then
      COMMON_ARGS+=("$extra_flag")
    fi
  done
fi

# Certificate arguments
if [[ "${var.certificateType}" == "selfsigned" ]]; then
  CERT_ARGS=(
    "--certificate-type=selfsigned"
  )
elif [[ "${var.certificateType}" == "letsencrypt" ]]; then
  CERT_ARGS=(
    "--certificate-type=letsencrypt"
  )
else
  # Use base64 encoded certificates directly
  OWN_CERT_CRT=${var.ownPublicCertificate}
  OWN_CERT_KEY=${var.ownPrivateCertificate}
  CERT_ARGS=(
    "--certificate-type=owncert"
    "--owncert-public-key=$OWN_CERT_CRT"
    "--owncert-private-key=$OWN_CERT_KEY"
  )
fi

# Final command
FINAL_COMMAND="$INSTALL_COMMAND $(printf "%s " "$${COMMON_ARGS[@]}") $(printf "%s " "$${CERT_ARGS[@]}")"

# Execute installation
exec bash -c "$FINAL_COMMAND"
EOF

  config_s3_script_master = <<-EOF
#!/bin/bash -x
set -e

# Install dir and config dir
INSTALL_DIR="/opt/openvidu"
CLUSTER_CONFIG_DIR="$${INSTALL_DIR}/config/cluster"


# Get DigitalOcean Spaces access keys from environment or metadata
EXTERNAL_S3_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.access_key}"
EXTERNAL_S3_SECRET_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"

# Config S3 bucket
EXTERNAL_S3_ENDPOINT="https://${var.spaceRegion}.digitaloceanspaces.com"
EXTERNAL_S3_REGION="${var.spaceRegion}"
EXTERNAL_S3_PATH_STYLE_ACCESS="true"
EXTERNAL_S3_BUCKET_APP_DATA="${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}"

sed -i "s|EXTERNAL_S3_ENDPOINT=.*|EXTERNAL_S3_ENDPOINT=$EXTERNAL_S3_ENDPOINT|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_REGION=.*|EXTERNAL_S3_REGION=$EXTERNAL_S3_REGION|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_PATH_STYLE_ACCESS=.*|EXTERNAL_S3_PATH_STYLE_ACCESS=$EXTERNAL_S3_PATH_STYLE_ACCESS|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_BUCKET_APP_DATA=.*|EXTERNAL_S3_BUCKET_APP_DATA=$EXTERNAL_S3_BUCKET_APP_DATA|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_ACCESS_KEY=.*|EXTERNAL_S3_ACCESS_KEY=$EXTERNAL_S3_ACCESS_KEY|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_SECRET_KEY=.*|EXTERNAL_S3_SECRET_KEY=$EXTERNAL_S3_SECRET_KEY|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
EOF

  after_install_script_master = <<-EOF
#!/bin/bash
set -e

# Generate URLs
DOMAIN="$(grep '^DOMAIN_NAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)"
OPENVIDU_URL="https://$${DOMAIN}/"
LIVEKIT_URL="wss://$${DOMAIN}/"
DASHBOARD_URL="https://$${DOMAIN}/dashboard/"
GRAFANA_URL="https://$${DOMAIN}/grafana/"
MINIO_URL="https://$${DOMAIN}/minio-console/"

# Update shared secret
/usr/local/bin/store_secret.sh save OPENVIDU_URL "$OPENVIDU_URL"
/usr/local/bin/store_secret.sh save LIVEKIT_URL "$LIVEKIT_URL"
/usr/local/bin/store_secret.sh save DASHBOARD_URL "$DASHBOARD_URL"
/usr/local/bin/store_secret.sh save GRAFANA_URL "$GRAFANA_URL"
/usr/local/bin/store_secret.sh save MINIO_URL "$MINIO_URL"

# Full save secrets.env to S3 bucket
/usr/local/bin/store_secret.sh fullsave
EOF

  update_config_from_secret_script_master = <<-EOF
#!/bin/bash
set -e

export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
export AWS_DEFAULT_REGION="${var.spaceRegion}"

INSTALL_DIR="/opt/openvidu"
CLUSTER_CONFIG_DIR="$${INSTALL_DIR}/config/cluster"
MASTER_NODE_CONFIG_DIR="$${INSTALL_DIR}/config/node"
SECRETS_FILE="/opt/openvidu/secrets.env"

# Download secrets.env from S3 bucket
aws s3 cp \
  s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/secrets.env \
  "$SECRETS_FILE" \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --region=${var.spaceRegion}


# Define which keys belong to meet.env
MEET_KEYS=("MEET_INITIAL_ADMIN_USER" "MEET_INITIAL_ADMIN_PASSWORD" "MEET_INITIAL_API_KEY")
# Define which keys belong to master_node.env
MASTER_NODE_KEYS=("REDIS_PASSWORD")

while IFS='=' read -r key value; do
  # Skip empty values
  if [[ -z "$value" ]]; then
    continue
  fi
  
  # Skip MEET_INITIAL_API_KEY if var.initialMeetApiKey is empty
  if [[ "$key" == "MEET_INITIAL_API_KEY" && "${var.initialMeetApiKey}" == "" ]]; then
    continue
  fi
  
  # Check if the key belongs to master_node.env
  if [[ " $${MASTER_NODE_KEYS[@]} " =~ " $${key} " ]]; then
    TARGET_FILE="$${MASTER_NODE_CONFIG_DIR}/master_node.env"
  # Check if the key belongs to meet.env
  elif [[ " $${MEET_KEYS[@]} " =~ " $${key} " ]]; then
    TARGET_FILE="$${CLUSTER_CONFIG_DIR}/master_node/meet.env"
  else
    TARGET_FILE="$${CLUSTER_CONFIG_DIR}/openvidu.env"
  fi
  
  # Update only if the key already exists
  if grep -q "^$key=" "$TARGET_FILE"; then
    sed -i "s|^$key=.*|$key=$value|" "$TARGET_FILE"
  fi
done < "$SECRETS_FILE"
EOF

  update_secret_from_config_script_master = <<-EOF
#!/bin/bash
set -e

# Installation directory
INSTALL_DIR="/opt/openvidu"
CLUSTER_CONFIG_DIR="$${INSTALL_DIR}/config/cluster"
MASTER_NODE_CONFIG_DIR="$${INSTALL_DIR}/config/node"
SECRETS_FILE="/opt/openvidu/secrets.env"

# Get current values of the config
REDIS_PASSWORD="$(/usr/local/bin/get_value_from_config.sh REDIS_PASSWORD "$${MASTER_NODE_CONFIG_DIR}/master_node.env")"
DOMAIN_NAME="$(/usr/local/bin/get_value_from_config.sh DOMAIN_NAME "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
OPENVIDU_RTC_ENGINE="$(/usr/local/bin/get_value_from_config.sh OPENVIDU_RTC_ENGINE "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
OPENVIDU_PRO_LICENSE="$(/usr/local/bin/get_value_from_config.sh OPENVIDU_PRO_LICENSE "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MONGO_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh MONGO_ADMIN_USERNAME "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MONGO_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh MONGO_ADMIN_PASSWORD "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MONGO_REPLICA_SET_KEY="$(/usr/local/bin/get_value_from_config.sh MONGO_REPLICA_SET_KEY "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MINIO_ACCESS_KEY="$(/usr/local/bin/get_value_from_config.sh MINIO_ACCESS_KEY "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MINIO_SECRET_KEY="$(/usr/local/bin/get_value_from_config.sh MINIO_SECRET_KEY "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
DASHBOARD_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh DASHBOARD_ADMIN_USERNAME "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
DASHBOARD_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh DASHBOARD_ADMIN_PASSWORD "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
GRAFANA_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh GRAFANA_ADMIN_USERNAME "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
GRAFANA_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh GRAFANA_ADMIN_PASSWORD "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
LIVEKIT_API_KEY="$(/usr/local/bin/get_value_from_config.sh LIVEKIT_API_KEY "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
LIVEKIT_API_SECRET="$(/usr/local/bin/get_value_from_config.sh LIVEKIT_API_SECRET "$${CLUSTER_CONFIG_DIR}/openvidu.env")"
MEET_INITIAL_ADMIN_USER="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_ADMIN_USER "$${CLUSTER_CONFIG_DIR}/master_node/meet.env")"
MEET_INITIAL_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_ADMIN_PASSWORD "$${CLUSTER_CONFIG_DIR}/master_node/meet.env")"
if [[ "${var.initialMeetApiKey}" != '' ]]; then
  MEET_INITIAL_API_KEY="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_API_KEY "$${CLUSTER_CONFIG_DIR}/master_node/meet.env")"
fi
ENABLED_MODULES="$(/usr/local/bin/get_value_from_config.sh ENABLED_MODULES "$${CLUSTER_CONFIG_DIR}/openvidu.env")"

# Update secrets file
# Function to update or add a key-value pair
update_secret() {
  local key="$1"
  local value="$2"
  if grep -q "^$${key}=" "$SECRETS_FILE"; then
    sed -i "s|^$${key}=.*|$${key}=$${value}|" "$SECRETS_FILE"
  else
    echo "$${key}=$${value}" >> "$SECRETS_FILE"
  fi
}

# Update all secrets
update_secret "REDIS_PASSWORD" "$REDIS_PASSWORD"
update_secret "DOMAIN_NAME" "$DOMAIN_NAME"
update_secret "OPENVIDU_RTC_ENGINE" "$OPENVIDU_RTC_ENGINE"
update_secret "OPENVIDU_PRO_LICENSE" "$OPENVIDU_PRO_LICENSE"
update_secret "MONGO_ADMIN_USERNAME" "$MONGO_ADMIN_USERNAME"
update_secret "MONGO_ADMIN_PASSWORD" "$MONGO_ADMIN_PASSWORD"
update_secret "MONGO_REPLICA_SET_KEY" "$MONGO_REPLICA_SET_KEY"
update_secret "MINIO_ACCESS_KEY" "$MINIO_ACCESS_KEY"
update_secret "MINIO_SECRET_KEY" "$MINIO_SECRET_KEY"
update_secret "DASHBOARD_ADMIN_USERNAME" "$DASHBOARD_ADMIN_USERNAME"
update_secret "DASHBOARD_ADMIN_PASSWORD" "$DASHBOARD_ADMIN_PASSWORD"
update_secret "GRAFANA_ADMIN_USERNAME" "$GRAFANA_ADMIN_USERNAME"
update_secret "GRAFANA_ADMIN_PASSWORD" "$GRAFANA_ADMIN_PASSWORD"
update_secret "LIVEKIT_API_KEY" "$LIVEKIT_API_KEY"
update_secret "LIVEKIT_API_SECRET" "$LIVEKIT_API_SECRET"
update_secret "MEET_INITIAL_ADMIN_USER" "$MEET_INITIAL_ADMIN_USER"
update_secret "MEET_INITIAL_ADMIN_PASSWORD" "$MEET_INITIAL_ADMIN_PASSWORD"
if [[ "${var.initialMeetApiKey}" != '' ]]; then
  update_secret "MEET_INITIAL_API_KEY" "$MEET_INITIAL_API_KEY"
fi
update_secret "ENABLED_MODULES" "$ENABLED_MODULES"

/usr/local/bin/store_secret.sh fullsave
EOF

  get_value_from_config_script_master = <<-EOF
#!/bin/bash -x
set -e

# Function to get the value of a given key from the environment file
get_value() {
    local key="$1"
    local file_path="$2"
    # Use grep to find the line with the key, ignoring lines starting with #
    # Use awk to split on '=' and print the second field, which is the value
    local value=$(grep -E "^\s*$key\s*=" "$file_path" | awk -F= '{print $2}' | sed 's/#.*//; s/^\s*//; s/\s*$//')
    # If the value is empty, return "none"
    if [ -z "$value" ]; then
        echo "none"
    else
        echo "$value"
    fi
}

# Check if the correct number of arguments are supplied
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <key> <file_path>"
    exit 1
fi

# Get the key and file path from the arguments
key="$1"
file_path="$2"

# Get and print the value
get_value "$key" "$file_path"
EOF

  store_secret_script_master = <<-EOF
#!/bin/bash
set -e

export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
export AWS_DEFAULT_REGION="${var.spaceRegion}"

# Modes: generate, save, fullsave
# save mode: save the provided value in secrets.env and return it
# generate mode: generate a random password save it and return it
# fullsave mode: save the secrets.env to S3 bucket
MODE="$1"
if [[ "$MODE" == "generate" ]]; then
    SECRET_KEY_NAME="$2"
    PREFIX="$${3:-}"
    LENGTH="$${4:-44}"
    RANDOM_PASSWORD="$(openssl rand -base64 64 | tr -d '+/=\n' | cut -c -$${LENGTH})"
    RANDOM_PASSWORD="$${PREFIX}$${RANDOM_PASSWORD}"
    # Save to secrets.env in bucket
    echo "$${SECRET_KEY_NAME}=$${RANDOM_PASSWORD}" >> /opt/openvidu/secrets.env
    echo "$RANDOM_PASSWORD"
elif [[ "$MODE" == "save" ]]; then
    SECRET_KEY_NAME="$2"
    SECRET_VALUE="$3"
    # Check if the key already exists
    if grep -q "^$${SECRET_KEY_NAME}=" /opt/openvidu/secrets.env; then
      # Update existing key
      sed -i "s|^$${SECRET_KEY_NAME}=.*|$${SECRET_KEY_NAME}=$${SECRET_VALUE}|" /opt/openvidu/secrets.env
    else
      # Add new key
      echo "$${SECRET_KEY_NAME}=$${SECRET_VALUE}" >> /opt/openvidu/secrets.env
    fi
    echo "$SECRET_VALUE"
elif [[ "$MODE" == "fullsave" ]]; then
      aws s3 cp /opt/openvidu/secrets.env \
        s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/secrets.env \
        --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
        --acl private \
        --region=${var.spaceRegion}
fi
EOF

  check_app_ready_script_master = <<-EOF
#!/bin/bash
while true; do
  HTTP_STATUS=$(curl -Ik http://localhost:7880/health/caddy | head -n1 | awk '{print $2}')
  if [ $HTTP_STATUS == 200 ]; then
    break
  fi
  sleep 5
done
EOF

  restart_script_master = <<-EOF
#!/bin/bash -x
set -e

# Stop all services
systemctl stop openvidu

# Update config from secrets
/usr/local/bin/update_config_from_secret.sh

# Start all services
systemctl start openvidu
EOF

  #   autoscale_script_master = <<-EOF
  # #!/bin/bash

  # DO_TOKEN="${var.do_token}"
  # TAG="${digitalocean_tag.media_node_tag.name}"
  # REGION="${var.region}"
  # SIZE="${var.mediaNodeInstanceType}"
  # MIN_NODES=${var.minNumberOfMediaNodes}
  # MAX_NODES=${var.maxNumberOfMediaNodes}

  # doctl auth init -t $DO_TOKEN

  # # Get Droplets using doctl
  # DROPLETS_JSON=$(doctl compute droplet list --tag-name "$TAG" --format ID,Name,PublicIPv4,PrivateIPv4,Region,Size,Status --output json)
  # CURRENT_IPS=$(echo "$DROPLETS_JSON" | jq -r '.[].PublicIPv4')
  # COUNT=$(echo "$DROPLETS_JSON" | jq '. | length')

  # # Get CPU metrics for all media nodes
  # TOTAL_CPU=0
  # VALID_COUNT=0

  # for DROPLET_ID in $(echo "$DROPLETS_JSON" | jq -r '.[].ID'); do
  #   # Get CPU usage from DigitalOcean monitoring API
  #   CPU_USAGE=$(doctl monitoring droplet cpu "$DROPLET_ID" --format Average --no-header 2>/dev/null | tail -1 | awk '{print $1}')

  #   if [ -n "$CPU_USAGE" ] && [ "$CPU_USAGE" != "null" ]; then
  #     TOTAL_CPU=$(echo "$TOTAL_CPU + $CPU_USAGE" | bc)
  #     VALID_COUNT=$((VALID_COUNT + 1))
  #   fi
  # done

  # # Calculate average CPU
  # if [ "$VALID_COUNT" -gt 0 ]; then
  #   AVG_CPU=$(echo "scale=2; $TOTAL_CPU / $VALID_COUNT" | bc)
  # else
  #   AVG_CPU=0
  # fi

  # SCALE_TARGET_CPU=${var.scaleTargetCPU}

  # echo "Current nodes: $COUNT, Average CPU: $AVG_CPU%, Target CPU: $SCALE_TARGET_CPU%"

  # # Scale Out: if average CPU > target AND current count < max
  # if [ "$(echo "$AVG_CPU > $SCALE_TARGET_CPU" | bc)" -eq 1 ] && [ "$COUNT" -lt "$MAX_NODES" ]; then

  #     NEXT_INDEX=$((COUNT + 1))
  #     NODE_NAME="${var.stackName}-media-node-$NEXT_INDEX"

  #     cat > /tmp/media-node-user-data.sh << 'MEDIA_USER_DATA_EOF'
  # ${local.user_data_media}
  # MEDIA_USER_DATA_EOF

  #     doctl compute droplet create "$${NODE_NAME}" \
  #       --region "$${REGION}" \
  #       --size "$${SIZE}" \
  #       --image ubuntu-24-04-x64 \
  #       --vpc-uuid "${digitalocean_vpc.openvidu_vpc.id}" \
  #       --tag-names "$${TAG}" \
  #       --ssh-keys "${var.sshKeyFingerprint},$(cat /etc/cluster_ssh_key_id)" \
  #       --user-data-file /tmp/media-node-user-data.sh \
  #       --wait

  # # Scale In: if average CPU < target AND current count > min
  # elif [ "$(echo "$AVG_CPU < $SCALE_TARGET_CPU" | bc)" -eq 1 ] && [ "$COUNT" -gt "$MIN_NODES" ]; then

  #   # Get the node with lowest CPU usage
  #   LOWEST_CPU_ID=""
  #   LOWEST_CPU=100

  #   for DROPLET_ID in $(echo "$DROPLETS_JSON" | jq -r '.[].ID'); do
  #     CPU_USAGE=$(doctl monitoring droplet cpu "$DROPLET_ID" --format Average --no-header 2>/dev/null | tail -1 | awk '{print $1}')
  #     if [ -n "$CPU_USAGE" ] && [ "$(echo "$CPU_USAGE < $LOWEST_CPU" | bc)" -eq 1 ]; then
  #       LOWEST_CPU=$CPU_USAGE
  #       LOWEST_CPU_ID=$DROPLET_ID
  #     fi
  #   done

  #   if [ "$LOWEST_CPU_ID" != "" ]; then
  #     # Get the private IP of the node to be drained
  #     NODE_IP=$(echo "$DROPLETS_JSON" | jq -r --arg id "$LOWEST_CPU_ID" '.[] | select(.ID == ($id | tonumber)) | .PrivateIPv4')

  #     # Remove the media-node tag and add draining tag to exclude from future queries
  #     doctl compute droplet tag "$LOWEST_CPU_ID" --tag-name "${var.stackName}-draining"
  #     doctl compute droplet untag "$LOWEST_CPU_ID" --tag-name "$TAG"

  #     # Tell the media node to initiate graceful shutdown (it will self-delete)
  #     ssh -i /root/.ssh/id_rsa -o ConnectTimeout=300 root@"$NODE_IP" "nohup /usr/local/bin/graceful_shutdown.sh > /var/log/graceful_shutdown.log 2>&1 &" || true
  #   fi

  # # Ensure minimum nodes
  # elif [ "$COUNT" -lt "$MIN_NODES" ]; then

  #     NEXT_INDEX=$((COUNT + 1))
  #     NODE_NAME="${var.stackName}-media-node-$NEXT_INDEX"

  #     cat > /tmp/media-node-user-data.sh << 'MEDIA_USER_DATA_EOF'
  # ${local.user_data_media}
  # MEDIA_USER_DATA_EOF

  #     doctl compute droplet create "$${NODE_NAME}" \
  #       --region "$${REGION}" \
  #       --size "$${SIZE}" \
  #       --image ubuntu-24-04-x64 \
  #       --vpc-uuid "${digitalocean_vpc.openvidu_vpc.id}" \
  #       --tag-name "$${TAG}" \
  #       --ssh-keys "${var.sshKeyFingerprint},$(cat /etc/cluster_ssh_key_id)" \
  #       --user-data-file /tmp/media-node-user-data.sh \
  #       --wait

  # fi
  # EOF

  user_data_master = <<-EOF
#!/bin/bash -x
set -eu -o pipefail

# restart.sh
cat > /usr/local/bin/restart.sh << 'RESTART_EOF'
${local.restart_script_master}
RESTART_EOF
chmod +x /usr/local/bin/restart.sh

# Check if installation already completed
if [ -f /usr/local/bin/openvidu_install_counter.txt ]; then
  # Launch on reboot
  /usr/local/bin/restart.sh || { echo "[OpenVidu] error restarting OpenVidu"; exit 1; }
else
  # install.sh
  cat > /usr/local/bin/install.sh << 'INSTALL_EOF'
${local.install_script_master}
INSTALL_EOF
  chmod +x /usr/local/bin/install.sh

  # after_install.sh
  cat > /usr/local/bin/after_install.sh << 'AFTER_INSTALL_EOF'
${local.after_install_script_master}
AFTER_INSTALL_EOF
  chmod +x /usr/local/bin/after_install.sh

  # update_config_from_secret.sh
  cat > /usr/local/bin/update_config_from_secret.sh << 'UPDATE_CONFIG_EOF'
${local.update_config_from_secret_script_master}
UPDATE_CONFIG_EOF
  chmod +x /usr/local/bin/update_config_from_secret.sh

  # update_secret_from_config.sh
  cat > /usr/local/bin/update_secret_from_config.sh << 'UPDATE_SECRET_EOF'
${local.update_secret_from_config_script_master}
UPDATE_SECRET_EOF
  chmod +x /usr/local/bin/update_secret_from_config.sh

  # get_value_from_config.sh
  cat > /usr/local/bin/get_value_from_config.sh << 'GET_VALUE_EOF'
${local.get_value_from_config_script_master}
GET_VALUE_EOF
  chmod +x /usr/local/bin/get_value_from_config.sh

  # store_secret.sh
  cat > /usr/local/bin/store_secret.sh << 'STORE_SECRET_EOF'
${local.store_secret_script_master}
STORE_SECRET_EOF
  chmod +x /usr/local/bin/store_secret.sh

  # check_app_ready.sh
  cat > /usr/local/bin/check_app_ready.sh << 'CHECK_APP_EOF'
${local.check_app_ready_script_master}
CHECK_APP_EOF
  chmod +x /usr/local/bin/check_app_ready.sh

  # config_s3.sh
  cat > /usr/local/bin/config_s3.sh << 'CONFIG_S3_EOF'
${local.config_s3_script_master}
CONFIG_S3_EOF
  chmod +x /usr/local/bin/config_s3.sh

  echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout
  apt-get update && apt-get install -y \
  curl \
  unzip \
  jq \
  wget \
  ca-certificates \
  gnupg \
  lsb-release \
  openssl

  # Install aws-cli
  curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip"
  unzip -qq awscliv2.zip
  ./aws/install
  rm -rf awscliv2.zip aws

  # Install doctl
  cd ~
  wget https://github.com/digitalocean/doctl/releases/download/v1.146.0/doctl-1.146.0-linux-amd64.tar.gz
  tar xf ~/doctl-1.146.0-linux-amd64.tar.gz
  mv ~/doctl /usr/local/bin
  rm -f ~/doctl-1.146.0-linux-amd64.tar.gz

  export HOME="/root"

  doctl auth init -t "${var.do_token}"

  export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
  export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
  export AWS_DEFAULT_REGION="${var.spaceRegion}"
  
  # Save private key to file
  echo "${tls_private_key.openvidu_ssh_key.private_key_openssh}" > /tmp/openvidu_ssh_key_elastic.pem
  chmod 600 /tmp/openvidu_ssh_key_elastic.pem
  
  # Upload private key to the bucket
  aws s3 cp /tmp/openvidu_ssh_key_elastic.pem \
  s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/openvidu_ssh_key_elastic.pem \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --acl private \
  --region=${var.spaceRegion}
  
  # Clean up
  rm -f /tmp/openvidu_ssh_key_elastic.pem

  # Install OpenVidu
  /usr/local/bin/install.sh || { echo "[OpenVidu] error installing OpenVidu"; exit 1; }
  
  # Config S3 bucket
  /usr/local/bin/config_s3.sh || { echo "[OpenVidu] error configuring S3 bucket"; exit 1; }

  # Start OpenVidu
  systemctl start openvidu || { echo "[OpenVidu] error starting OpenVidu"; exit 1; }

  # Update shared secrets
  /usr/local/bin/after_install.sh || { echo "[OpenVidu] error updating shared secrets"; exit 1; }

  # restart.sh on reboot
  echo "@reboot /usr/local/bin/restart.sh >> /var/log/openvidu-restart.log 2>&1" | crontab
  
  # Mark installation as complete
  echo "installation_complete" > /usr/local/bin/openvidu_install_counter.txt
fi

# Wait for the app
/usr/local/bin/check_app_ready.sh
EOF

  # ----- media -----

  install_script_media = <<-EOF
#!/bin/bash -x
set -e

# Install dependencies
echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout

apt-get update && apt-get install -y

# Get secret from s3 bucket with active wait
export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
export AWS_DEFAULT_REGION="${var.spaceRegion}"
mkdir -p /opt/openvidu

# Active wait for secrets.env to be available
MAX_RETRIES=200
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if aws s3 cp \
    s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/secrets.env \
    /opt/openvidu/secrets.env \
    --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
    --region=${var.spaceRegion}; then
    echo "Successfully retrieved secrets.env"
    break
  else
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "Waiting for secrets.env... Attempt $RETRY_COUNT/$MAX_RETRIES"
    sleep 10
  fi
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo "Failed to retrieve secrets.env after $MAX_RETRIES attempts"
  exit 1
fi

# Get IPs using DO metadata
PRIVATE_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address)
MASTER_NODE_PRIVATE_IP=$(grep '^MASTER_NODE_PRIVATE_IP=' /opt/openvidu/secrets.env | cut -d'=' -f2)

# Get all necessary values from secrets
DOMAIN=$(grep '^DOMAIN_NAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
REDIS_PASSWORD=$(grep '^REDIS_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_VERSION=$(grep '^OPENVIDU_VERSION=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_PRO_LICENSE=$(grep '^OPENVIDU_PRO_LICENSE=' /opt/openvidu/secrets.env | cut -d'=' -f2)

# Build install command for media node
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/pro/elastic/$OPENVIDU_VERSION/install_ov_media_node.sh)"

# Media node arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=on_premise"
  "--deployment-type=elastic"
  "--node-role=media-node"
  "--master-node-private-ip=$MASTER_NODE_PRIVATE_IP"
  "--private-ip=$PRIVATE_IP"
  "--redis-password=$REDIS_PASSWORD"
)

# Construct the final command
FINAL_COMMAND="$INSTALL_COMMAND $(printf "%s " "$${COMMON_ARGS[@]}")"

# Execute installation
exec bash -c "$FINAL_COMMAND"
EOF

  graceful_shutdown_script_media = <<-EOF
#!/bin/bash -x
set -e

echo "Starting graceful shutdown of OpenVidu Media Node..."

# Execute if docker is installed
if [ -x "$(command -v docker)" ]; then

  echo "Stopping media node services and waiting for termination..."
  docker container kill --signal=SIGQUIT openvidu || true
  docker container kill --signal=SIGQUIT ingress || true
  docker container kill --signal=SIGQUIT egress || true
  for agent_container in $(docker ps --filter "label=openvidu-agent=true" --format '{{.Names}}'); do
    docker container kill --signal=SIGQUIT "$agent_container"
  done

  # Wait for running containers to not be openvidu, ingress, egress or an openvidu agent
  while [ $(docker ps --filter "label=openvidu-agent=true" -q | wc -l) -gt 0 ] || \
        [ $(docker inspect -f '{{.State.Running}}' openvidu 2>/dev/null) == "true" ] || \
        [ $(docker inspect -f '{{.State.Running}}' ingress 2>/dev/null) == "true" ] || \
        [ $(docker inspect -f '{{.State.Running}}' egress 2>/dev/null) == "true" ]; do
    echo "Waiting for containers to stop..."
    sleep 10
  done
fi

# Self-delete using doctl

# Get droplet ID from metadata
DROPLET_ID=$(curl -s http://169.254.169.254/metadata/v1/id)

# Delete this instance using doctl
doctl compute droplet delete "$DROPLET_ID" \
  --force || echo "Failed to self-delete, instance may already be terminating"

echo "Graceful shutdown completed."
EOF

  user_data_media = <<-EOF
#!/bin/bash -x
set -eu -o pipefail

# install.sh (media node)
cat > /usr/local/bin/install.sh << 'INSTALL_MEDIA_EOF'
${local.install_script_media}
INSTALL_MEDIA_EOF
chmod +x /usr/local/bin/install.sh

# graceful_shutdown.sh
cat > /usr/local/bin/graceful_shutdown.sh << 'GRACEFUL_SHUTDOWN_EOF'
${local.graceful_shutdown_script_media}
GRACEFUL_SHUTDOWN_EOF
chmod +x /usr/local/bin/graceful_shutdown.sh

echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout
apt-get update && apt-get install -y \
  curl \
  unzip \
  jq \
  wget \
  ca-certificates \
  gnupg \
  lsb-release \
  openssl

# Install aws-cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip"
unzip -qq awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws

# Install doctl
cd ~
wget https://github.com/digitalocean/doctl/releases/download/v1.146.0/doctl-1.146.0-linux-amd64.tar.gz
tar xf ~/doctl-1.146.0-linux-amd64.tar.gz
mv ~/doctl /usr/local/bin
rm -f ~/doctl-1.146.0-linux-amd64.tar.gz

export HOME="/root"

doctl auth init -t "${var.do_token}"

# Install OpenVidu Media Node
/usr/local/bin/install.sh || { echo "[OpenVidu] error installing OpenVidu Media Node"; exit 1; }

# Mark installation as complete
echo "installation_complete" > /usr/local/bin/openvidu_install_counter.txt

# Start OpenVidu
systemctl start openvidu || { echo "[OpenVidu] error starting OpenVidu"; exit 1; }
EOF
}
