# SSH key
resource "tls_private_key" "openvidu_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "digitalocean_ssh_key" "openvidu_ssh_key_do" {
  name       = "${var.stackName}-ssh-key"
  public_key = tls_private_key.openvidu_ssh_key.public_key_openssh
}

# Droplet
resource "digitalocean_droplet" "openvidu_server" {
  name   = "${var.stackName}-vm-ce-pro"
  image  = "ubuntu-24-04-x64"
  region = var.region
  size   = var.instanceType

  ssh_keys  = [digitalocean_ssh_key.openvidu_ssh_key_do.id]
  user_data = local.user_data
}

# Firewall - Same ports as GCP deployment
resource "digitalocean_firewall" "openvidu_firewall" {
  name = "${var.stackName}-firewall"

  droplet_ids = [digitalocean_droplet.openvidu_server.id]

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
    port_range       = "7881"
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

  inbound_rule {
    protocol         = "tcp"
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

# Reserved IP (Floating IP)
resource "digitalocean_reserved_ip" "public_ip" {
  droplet_id = digitalocean_droplet.openvidu_server.id
  region     = var.region
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
  install_script = <<-EOF
#!/bin/bash -x
set -e

OPENVIDU_VERSION=main
DOMAIN=
echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout

# Install dependencies
apt-get update && apt-get install -y 

# Create counter file for tracking script executions
echo 1 > /usr/local/bin/openvidu_install_counter.txt

# Create OpenVidu directory and secrets file
mkdir -p /opt/openvidu
touch /opt/openvidu/secrets.env

# Determine Domain using DO metadata
PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/floating_ip/ipv4/ip_address)

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

# Store usernames and generate random passwords
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
ENABLED_MODULES="$(/usr/local/bin/store_secret.sh save ENABLED_MODULES "observability,openviduMeet,v2compatibility")"
LIVEKIT_API_KEY="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_KEY "API" 12)"
LIVEKIT_API_SECRET="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_SECRET)"
OPENVIDU_PRO_LICENSE="$(/usr/local/bin/store_secret.sh save OPENVIDU_PRO_LICENSE "${var.openviduLicense}")"
OPENVIDU_RTC_ENGINE="$(/usr/local/bin/store_secret.sh save OPENVIDU_RTC_ENGINE "${var.rtcEngine}")"


# Build install command
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/community/singlenode/$OPENVIDU_VERSION/install.sh)"

# Common arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=on_premise"
  "--deployment-type=single_node_pro"
  "--openvidu-pro-license=$OPENVIDU_PRO_LICENSE"
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
  # Download owncert files
  mkdir -p /tmp/owncert
  wget -O /tmp/owncert/fullchain.pem ${var.ownPublicCertificate}
  wget -O /tmp/owncert/privkey.pem ${var.ownPrivateCertificate}

  # Convert to base64
  OWN_CERT_CRT=$(base64 -w 0 /tmp/owncert/fullchain.pem)
  OWN_CERT_KEY=$(base64 -w 0 /tmp/owncert/privkey.pem)
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

  config_s3_script = <<-EOF
#!/bin/bash -x
set -e

# Install dir and config dir
INSTALL_DIR="/opt/openvidu"
CONFIG_DIR="$${INSTALL_DIR}/config"


# Get DigitalOcean Spaces access keys from environment or metadata
EXTERNAL_S3_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.access_key}"
EXTERNAL_S3_SECRET_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"

# Config S3 bucket
EXTERNAL_S3_ENDPOINT="https://${var.spaceRegion}.digitaloceanspaces.com"
EXTERNAL_S3_REGION="${var.spaceRegion}"
EXTERNAL_S3_PATH_STYLE_ACCESS="true"
EXTERNAL_S3_BUCKET_APP_DATA="${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}"

sed -i "s|EXTERNAL_S3_ENDPOINT=.*|EXTERNAL_S3_ENDPOINT=$EXTERNAL_S3_ENDPOINT|" "$${CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_REGION=.*|EXTERNAL_S3_REGION=$EXTERNAL_S3_REGION|" "$${CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_PATH_STYLE_ACCESS=.*|EXTERNAL_S3_PATH_STYLE_ACCESS=$EXTERNAL_S3_PATH_STYLE_ACCESS|" "$${CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_BUCKET_APP_DATA=.*|EXTERNAL_S3_BUCKET_APP_DATA=$EXTERNAL_S3_BUCKET_APP_DATA|" "$${CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_ACCESS_KEY=.*|EXTERNAL_S3_ACCESS_KEY=$EXTERNAL_S3_ACCESS_KEY|" "$${CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_SECRET_KEY=.*|EXTERNAL_S3_SECRET_KEY=$EXTERNAL_S3_SECRET_KEY|" "$${CONFIG_DIR}/openvidu.env"
EOF

  after_install_script = <<-EOF
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
EOF

  update_config_from_secret_script = <<-EOF
#!/bin/bash
set -e
INSTALL_DIR="/opt/openvidu"
CONFIG_DIR="$INSTALL_DIR/config"
SECRETS_FILE="/opt/openvidu/secrets.env"


# Define which keys belong to meet.env
MEET_KEYS=("MEET_INITIAL_ADMIN_USER" "MEET_INITIAL_ADMIN_PASSWORD" "MEET_INITIAL_API_KEY")

while IFS='=' read -r key value; do
  # Skip empty values
  if [[ -z "$value" ]]; then
    continue
  fi
  
  # Skip MEET_INITIAL_API_KEY if var.initialMeetApiKey is empty
  if [[ "$key" == "MEET_INITIAL_API_KEY" && "${var.initialMeetApiKey}" == "" ]]; then
    continue
  fi
  
  # Check if the key belongs to meet.env
  if [[ " $${MEET_KEYS[@]} " =~ " $${key} " ]]; then
    TARGET_FILE="$${CONFIG_DIR}/meet.env"
  else
    TARGET_FILE="$${CONFIG_DIR}/openvidu.env"
  fi
  
  # Update only if the key already exists
  if grep -q "^$key=" "$TARGET_FILE"; then
    sed -i "s|^$key=.*|$key=$value|" "$TARGET_FILE"
  fi
done < "$SECRETS_FILE"
EOF

  update_secret_from_config_script = <<-EOF
#!/bin/bash
set -e

# Installation directory
INSTALL_DIR="/opt/openvidu"
CONFIG_DIR="$${INSTALL_DIR}/config"
SECRETS_FILE="/opt/openvidu/secrets.env"

# Get current values of the config
REDIS_PASSWORD="$(/usr/local/bin/get_value_from_config.sh REDIS_PASSWORD "$${CONFIG_DIR}/openvidu.env")"
OPENVIDU_PRO_LICENSE="$(/usr/local/bin/get_value_from_config.sh OPENVIDU_PRO_LICENSE "$${CONFIG_DIR}/openvidu.env")"
OPENVIDU_RTC_ENGINE="$(/usr/local/bin/get_value_from_config.sh OPENVIDU_RTC_ENGINE "$${CONFIG_DIR}/openvidu.env")"
DOMAIN_NAME="$(/usr/local/bin/get_value_from_config.sh DOMAIN_NAME "$${CONFIG_DIR}/openvidu.env")"
MONGO_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh MONGO_ADMIN_USERNAME "$${CONFIG_DIR}/openvidu.env")"
MONGO_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh MONGO_ADMIN_PASSWORD "$${CONFIG_DIR}/openvidu.env")"
MONGO_REPLICA_SET_KEY="$(/usr/local/bin/get_value_from_config.sh MONGO_REPLICA_SET_KEY "$${CONFIG_DIR}/openvidu.env")"
MINIO_ACCESS_KEY="$(/usr/local/bin/get_value_from_config.sh MINIO_ACCESS_KEY "$${CONFIG_DIR}/openvidu.env")"
MINIO_SECRET_KEY="$(/usr/local/bin/get_value_from_config.sh MINIO_SECRET_KEY "$${CONFIG_DIR}/openvidu.env")"
DASHBOARD_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh DASHBOARD_ADMIN_USERNAME "$${CONFIG_DIR}/openvidu.env")"
DASHBOARD_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh DASHBOARD_ADMIN_PASSWORD "$${CONFIG_DIR}/openvidu.env")"
GRAFANA_ADMIN_USERNAME="$(/usr/local/bin/get_value_from_config.sh GRAFANA_ADMIN_USERNAME "$${CONFIG_DIR}/openvidu.env")"
GRAFANA_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh GRAFANA_ADMIN_PASSWORD "$${CONFIG_DIR}/openvidu.env")"
LIVEKIT_API_KEY="$(/usr/local/bin/get_value_from_config.sh LIVEKIT_API_KEY "$${CONFIG_DIR}/openvidu.env")"
LIVEKIT_API_SECRET="$(/usr/local/bin/get_value_from_config.sh LIVEKIT_API_SECRET "$${CONFIG_DIR}/openvidu.env")"
MEET_INITIAL_ADMIN_USER="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_ADMIN_USER "$${CONFIG_DIR}/meet.env")"
MEET_INITIAL_ADMIN_PASSWORD="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_ADMIN_PASSWORD "$${CONFIG_DIR}/meet.env")"
if [[ "${var.initialMeetApiKey}" != '' ]]; then
  MEET_INITIAL_API_KEY="$(/usr/local/bin/get_value_from_config.sh MEET_INITIAL_API_KEY "$${CONFIG_DIR}/meet.env")"
fi
ENABLED_MODULES="$(/usr/local/bin/get_value_from_config.sh ENABLED_MODULES "$${CONFIG_DIR}/openvidu.env")"

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
update_secret "OPENVIDU_PRO_LICENSE" "$OPENVIDU_PRO_LICENSE"
update_secret "OPENVIDU_RTC_ENGINE" "$OPENVIDU_RTC_ENGINE"
update_secret "DOMAIN_NAME" "$DOMAIN_NAME"
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
EOF

  get_value_from_config_script = <<-EOF
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

  store_secret_script = <<-EOF
#!/bin/bash
set -e

# Modes: generate, save
# save mode: save the provided value in secrets.env and return it
# generate mode: generate a random password save it and return it
MODE="$1"
if [[ "$MODE" == "generate" ]]; then
    SECRET_KEY_NAME="$2"
    PREFIX="$${3:-}"
    LENGTH="$${4:-44}"
    RANDOM_PASSWORD="$(openssl rand -base64 64 | tr -d '+/=\n' | cut -c -$${LENGTH})"
    RANDOM_PASSWORD="$${PREFIX}$${RANDOM_PASSWORD}"
    # Save to secrets.env
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
else
    exit 1
fi
EOF

  check_app_ready_script = <<-EOF
#!/bin/bash
while true; do
  HTTP_STATUS=$(curl -Ik http://localhost:7880/health/caddy | head -n1 | awk '{print $2}')
  if [ $HTTP_STATUS == 200 ]; then
    break
  fi
  sleep 5
done
EOF

  restart_script = <<-EOF
#!/bin/bash -x
set -e

# Stop all services
systemctl stop openvidu

# Update config from secrets
/usr/local/bin/update_config_from_secret.sh

# Start all services
systemctl start openvidu
EOF

  user_data = <<-EOF
#!/bin/bash -x
set -eu -o pipefail

# restart.sh
cat > /usr/local/bin/restart.sh << 'RESTART_EOF'
${local.restart_script}
RESTART_EOF
chmod +x /usr/local/bin/restart.sh

# Check if installation already completed
if [ -f /usr/local/bin/openvidu_install_counter.txt ]; then
  # Launch on reboot
  /usr/local/bin/restart.sh || { echo "[OpenVidu] error restarting OpenVidu"; exit 1; }
else
  # install.sh
  cat > /usr/local/bin/install.sh << 'INSTALL_EOF'
${local.install_script}
INSTALL_EOF
  chmod +x /usr/local/bin/install.sh

  # after_install.sh
  cat > /usr/local/bin/after_install.sh << 'AFTER_INSTALL_EOF'
${local.after_install_script}
AFTER_INSTALL_EOF
  chmod +x /usr/local/bin/after_install.sh

  # update_config_from_secret.sh
  cat > /usr/local/bin/update_config_from_secret.sh << 'UPDATE_CONFIG_EOF'
${local.update_config_from_secret_script}
UPDATE_CONFIG_EOF
  chmod +x /usr/local/bin/update_config_from_secret.sh

  # update_secret_from_config.sh
  cat > /usr/local/bin/update_secret_from_config.sh << 'UPDATE_SECRET_EOF'
${local.update_secret_from_config_script}
UPDATE_SECRET_EOF
  chmod +x /usr/local/bin/update_secret_from_config.sh

  # get_value_from_config.sh
  cat > /usr/local/bin/get_value_from_config.sh << 'GET_VALUE_EOF'
${local.get_value_from_config_script}
GET_VALUE_EOF
  chmod +x /usr/local/bin/get_value_from_config.sh

  # store_secret.sh
  cat > /usr/local/bin/store_secret.sh << 'STORE_SECRET_EOF'
${local.store_secret_script}
STORE_SECRET_EOF
  chmod +x /usr/local/bin/store_secret.sh

  # check_app_ready.sh
  cat > /usr/local/bin/check_app_ready.sh << 'CHECK_APP_EOF'
${local.check_app_ready_script}
CHECK_APP_EOF
  chmod +x /usr/local/bin/check_app_ready.sh

  # config_s3.sh
  cat > /usr/local/bin/config_s3.sh << 'CONFIG_S3_EOF'
${local.config_s3_script}
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

  export HOME="/root"
   
  export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
  export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
  export AWS_DEFAULT_REGION="${var.spaceRegion}"

  # Save private key to file
  echo "${tls_private_key.openvidu_ssh_key.private_key_openssh}" > /tmp/openvidu_ssh_key.pem
  chmod 600 /tmp/openvidu_ssh_key.pem
  
  # Upload private key to the bucket
  aws s3 cp /tmp/openvidu_ssh_key.pem \
  s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/openvidu_ssh_key.pem \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --acl private \
  --region=${var.spaceRegion}
  
  # Clean up
  rm -f /tmp/openvidu_ssh_key.pem
  
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
}
