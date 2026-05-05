resource "random_id" "bucket_suffix" { byte_length = 5 }

# -------------- VPC and Firewalls ----------------

resource "digitalocean_vpc" "openvidu_vpc" {
  name     = "${var.stackName}-vpc"
  region   = var.region
  ip_range = "10.10.10.0/24"
}

resource "digitalocean_tag" "media_node_tag" {
  name = "${var.stackName}-media-node-tag"
}

resource "digitalocean_tag" "draining_tag" {
  name = "${var.stackName}-draining"
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
    port_range       = "6080"
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
  depends_on = [digitalocean_droplet.openvidu_master_node]
}

# Media Nodes (when fixed mode is enabled)
resource "digitalocean_droplet" "openvidu_media_nodes" {
  count  = var.fixedNumberOfMediaNodes
  name   = "${var.stackName}-media-node-${count.index + 1}"
  image  = "ubuntu-24-04-x64"
  region = var.region
  size   = var.mediaNodeInstanceType

  ssh_keys = [digitalocean_ssh_key.openvidu_ssh_key_do.id]
  vpc_uuid = digitalocean_vpc.openvidu_vpc.id
  tags     = ["openvidu", var.stackName, "media-node", digitalocean_tag.media_node_tag.name]

  user_data = local.user_data_media
}

# Cleanup all media nodes on destroy (created by autoscaler outside Terraform state)
resource "null_resource" "cleanup_media_nodes" {
  count = var.fixedNumberOfMediaNodes > 0 ? 0 : 1
  triggers = {
    do_token     = var.doToken
    media_tag    = digitalocean_tag.media_node_tag.name
    draining_tag = digitalocean_tag.draining_tag.name
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      curl -s -X DELETE \
        -H "Authorization: Bearer ${self.triggers.do_token}" \
        -H "Content-Type: application/json" \
        "https://api.digitalocean.com/v2/droplets?tag_name=${self.triggers.media_tag}"
      echo "Deleted all media node droplets"
      curl -s -X DELETE \
        -H "Authorization: Bearer ${self.triggers.do_token}" \
        -H "Content-Type: application/json" \
        "https://api.digitalocean.com/v2/droplets?tag_name=${self.triggers.draining_tag}"
      echo "Deleted all draining node droplets"
    EOT
  }
}

# -------------- Autoscaler (DO Function) ----------------

resource "null_resource" "deploy_autoscaler_function" {
  count = var.fixedNumberOfMediaNodes > 0 ? 0 : 1
  triggers = {
    code_hash  = sha256(local.autoscaler_function_code)
    do_token   = var.doToken
    stack_name = var.stackName
    region     = var.region
  }

  provisioner "local-exec" {
    environment = {
      DO_TOKEN    = var.doToken
      FN_CODE_B64 = base64encode(local.autoscaler_function_code)
    }

    command = <<-EOT
      set -e

      DO_API="https://api.digitalocean.com/v2"
      AUTH="Authorization: Bearer $DO_TOKEN"
      CT="Content-Type: application/json"
      LABEL="${var.stackName}-autoscaler"

      # Check dependencies
      for cmd in curl jq base64; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd is required but not installed"; exit 1; }
      done

      # Helper: curl with verbose error on failure
      do_curl() {
        HTTP_BODY=$(curl -s -w "\n__HTTP_CODE__%%{http_code}" "$@")
        HTTP_CODE=$(printf '%s' "$HTTP_BODY" | tail -1 | sed 's/__HTTP_CODE__//')
        BODY=$(printf '%s' "$HTTP_BODY" | head -n -1)
        if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
          echo "ERROR: curl $* returned HTTP $HTTP_CODE: $BODY" >&2
          exit 1
        fi
        printf '%s' "$BODY"
      }

      # === 1. Find or create Functions namespace ===
      NS_LIST=$(do_curl -H "$AUTH" "$DO_API/functions/namespaces")
      echo "Namespaces response: $NS_LIST"
      NS_ID=$(printf '%s' "$NS_LIST" | jq -r --arg l "$LABEL" \
        '[(.namespaces // [])[] | select(.label == $l)] | .[0].namespace // empty')

      if [ -z "$NS_ID" ]; then
        echo "Creating namespace $LABEL in region ${var.region} ..."
        NS_RESP=$(do_curl -X POST -H "$AUTH" -H "$CT" \
          -d "{\"region\":\"${var.region}\",\"label\":\"$LABEL\"}" \
          "$DO_API/functions/namespaces")
        echo "Create namespace response: $NS_RESP"
        NS_ID=$(printf '%s' "$NS_RESP"    | jq -r '.namespace.namespace // empty')
        NS_UUID=$(printf '%s' "$NS_RESP"  | jq -r '.namespace.uuid // empty')
        API_HOST=$(printf '%s' "$NS_RESP" | jq -r '.namespace.api_host // empty')
        API_KEY=$(printf '%s' "$NS_RESP"  | jq -r '.namespace.key // empty')
      else
        echo "Namespace exists: $NS_ID"
        NS_DETAIL=$(do_curl -H "$AUTH" "$DO_API/functions/namespaces/$NS_ID")
        NS_UUID=$(printf '%s' "$NS_DETAIL"  | jq -r '.namespace.uuid // empty')
        API_HOST=$(printf '%s' "$NS_DETAIL" | jq -r '.namespace.api_host // empty')
        API_KEY=$(printf '%s' "$NS_DETAIL"  | jq -r '.namespace.key // empty')
      fi

      [ -n "$NS_ID" ]   || { echo "ERROR: could not get namespace ID";  exit 1; }
      [ -n "$NS_UUID" ]  || { echo "ERROR: could not get namespace UUID"; exit 1; }
      [ -n "$API_HOST" ] || { echo "ERROR: could not get API host";      exit 1; }
      [ -n "$API_KEY" ]  || { echo "ERROR: could not get API key";       exit 1; }

      # OpenWhisk Basic Auth = base64("uuid:key")
      OW_AUTH=$(printf '%s:%s' "$NS_UUID" "$API_KEY" | base64 -w0)

      # === 2. Create / update OpenWhisk package ===
      do_curl -X PUT \
        -H "Authorization: Basic $OW_AUTH" -H "$CT" \
        -d '{}' \
        "$API_HOST/api/v1/namespaces/_/packages/autoscaler?overwrite=true" > /dev/null

      # === 3. Deploy the action ===
      CODE=$(printf '%s' "$FN_CODE_B64" | base64 -d)
      PAYLOAD=$(jq -n --arg code "$CODE" '{
        "exec":  {"kind":"python:default","code":$code},
        "limits":{"timeout":120000,"memory":256},
        "annotations":[{"key":"web-export","value":false}]
      }')

      do_curl -X PUT \
        -H "Authorization: Basic $OW_AUTH" -H "$CT" \
        -d "$PAYLOAD" \
        "$API_HOST/api/v1/namespaces/_/actions/autoscaler/check?overwrite=true" > /dev/null

      echo "Action autoscaler/check deployed."

      # === 4. Create / replace cron trigger (every 4 minutes) ===
      TRIGGER="${var.stackName}-autoscale-cron"
      curl -s -X DELETE -H "$AUTH" \
        "$DO_API/functions/namespaces/$NS_ID/triggers/$TRIGGER" > /dev/null 2>&1 || true

      do_curl -X POST -H "$AUTH" -H "$CT" \
        -d "{
          \"name\":\"$TRIGGER\",
          \"function\":\"autoscaler/check\",
          \"type\":\"SCHEDULED\",
          \"is_enabled\":true,
          \"scheduled_details\":{\"cron\":\"*/4 * * * *\",\"body\":{}}
        }" \
        "$DO_API/functions/namespaces/$NS_ID/triggers" > /dev/null

      echo "Trigger $TRIGGER created. Deployment complete."
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      DO_API="https://api.digitalocean.com/v2"
      TOKEN="${self.triggers.do_token}"
      LABEL="${self.triggers.stack_name}-autoscaler"
      TRIGGER="${self.triggers.stack_name}-autoscale-cron"

      echo "=== Destroying autoscaler function ==="
      echo "Looking for namespace with label: $LABEL"

      NS_LIST=$(curl -sf -H "Authorization: Bearer $TOKEN" "$DO_API/functions/namespaces" || echo '{"namespaces":[]}')
      echo "Namespaces: $NS_LIST"
      NS_ID=$(printf '%s' "$NS_LIST" | jq -r --arg l "$LABEL" \
        '[(.namespaces // [])[] | select(.label == $l)] | .[0].namespace // empty')

      if [ -z "$NS_ID" ]; then
        echo "No namespace found with label $LABEL — nothing to destroy."
        exit 0
      fi

      echo "Found namespace: $NS_ID"
      NS_DETAIL=$(curl -sf -H "Authorization: Bearer $TOKEN" "$DO_API/functions/namespaces/$NS_ID" || echo '{}')
      NS_UUID=$(printf '%s' "$NS_DETAIL"  | jq -r '.namespace.uuid // empty')
      API_HOST=$(printf '%s' "$NS_DETAIL" | jq -r '.namespace.api_host // empty')
      API_KEY=$(printf '%s' "$NS_DETAIL"  | jq -r '.namespace.key // empty')

      # Delete cron trigger
      echo "Deleting trigger $TRIGGER ..."
      curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
        "$DO_API/functions/namespaces/$NS_ID/triggers/$TRIGGER" || true

      # Delete action + package via OpenWhisk API
      if [ -n "$API_HOST" ] && [ -n "$NS_UUID" ] && [ -n "$API_KEY" ]; then
        OW_AUTH=$(printf '%s:%s' "$NS_UUID" "$API_KEY" | base64 -w0)
        echo "Deleting action autoscaler/check ..."
        curl -s -X DELETE -H "Authorization: Basic $OW_AUTH" \
          "$API_HOST/api/v1/namespaces/_/actions/autoscaler/check" || true
        echo "Deleting package autoscaler ..."
        curl -s -X DELETE -H "Authorization: Basic $OW_AUTH" \
          "$API_HOST/api/v1/namespaces/_/packages/autoscaler" || true
      else
        echo "WARN: missing OpenWhisk credentials, skipping action/package deletion"
      fi

      # Delete the namespace itself
      echo "Deleting namespace $NS_ID ..."
      DEL_RESP=$(curl -s -w "\n__HTTP_CODE__%%{http_code}" -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "$DO_API/functions/namespaces/$NS_ID")
      DEL_CODE=$(printf '%s' "$DEL_RESP" | tail -1 | sed 's/__HTTP_CODE__//')
      echo "Namespace delete HTTP $DEL_CODE"

      echo "=== Autoscaler function destroyed ==="
    EOT
  }

  depends_on = [
    digitalocean_droplet.openvidu_master_node,
    digitalocean_vpc.openvidu_vpc,
    digitalocean_tag.media_node_tag,
    digitalocean_tag.draining_tag,
  ]
}

# DigitalOcean Space
resource "digitalocean_spaces_bucket" "openvidu_space" {
  count  = var.spaceName == "" ? 1 : 0
  name   = "${var.stackName}-space-${random_id.bucket_suffix.hex}"
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

OPENVIDU_VERSION=3.7.0
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
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" == "null" ]; then
  PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
fi
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
  "--environment=digitalocean"
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
set +e
MAX_RETRIES=5
RETRY_COUNT=1

until bash -c "$FINAL_COMMAND"; do
  echo "Install command failed (attempt $RETRY_COUNT/$MAX_RETRIES)"
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "Install command failed after $MAX_RETRIES attempts"
    exit 1
  fi
  RETRY_COUNT=$((RETRY_COUNT + 1))
  sleep 10
done
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

  autoscaler_function_code = <<-PYEOF
import base64
import json
import os
import random
import time
import traceback
import urllib.request
import urllib.error

# ---- Configuration (values baked via Terraform interpolation) ----
DO_TOKEN      = "${var.doToken}"
MEDIA_TAG     = "${digitalocean_tag.media_node_tag.name}"
DRAINING_TAG  = "${digitalocean_tag.draining_tag.name}"
REGION        = "${var.region}"
SIZE          = "${var.mediaNodeInstanceType}"
VPC_UUID      = "${digitalocean_vpc.openvidu_vpc.id}"
SSH_KEY_ID    = "${digitalocean_ssh_key.openvidu_ssh_key_do.id}"
STACK_NAME    = "${var.stackName}"
MIN_NODES     = int("${var.minNumberOfMediaNodes}")
MAX_NODES     = int("${var.maxNumberOfMediaNodes}")
TARGET_CPU    = float("${var.scaleTargetCPU}")
USER_DATA     = base64.b64decode("${base64encode(local.user_data_media)}").decode()

API = "https://api.digitalocean.com/v2"
HDR = {"Authorization": f"Bearer {DO_TOKEN}", "Content-Type": "application/json"}

# All log lines are collected here and returned in the response body so they
# are visible in the DigitalOcean Functions console (activation result).
_LOGS = []

def log(m):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}] {m}"
    print(line, flush=True)
    _LOGS.append(line)

def apicall(method, path, body=None):
    url = f"{API}{path}" if path.startswith("/") else path
    req = urllib.request.Request(url, headers=HDR, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
    log(f"  -> {method} {path}")
    if body:
        log(f"     body: {json.dumps(body)}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = r.read().decode()
            parsed = json.loads(d) if d.strip() else {}
            log(f"     <- {r.status} OK")
            return parsed
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode()[:400]
        log(f"     <- HTTP {e.code} ERROR: {body_txt}")
        return None
    except urllib.error.URLError as e:
        log(f"     <- URL error: {e.reason}")
        return None
    except Exception as e:
        log(f"     <- unexpected error: {e}")
        log(traceback.format_exc())
        return None

def list_nodes():
    log("Listing media nodes ...")
    r = apicall("GET", f"/droplets?tag_name={MEDIA_TAG}&per_page=200")
    nodes = r.get("droplets", []) if r else []
    for d in nodes:
        log(f"  droplet id={d['id']} name={d['name']} status={d['status']} "
            f"region={d.get('region',{}).get('slug','?')} created={d.get('created_at','?')}")
    return nodes

def cpu(did, name):
    now = int(time.time())
    log(f"  Fetching CPU metrics for droplet {did} ({name}) ...")
    r = apicall("GET", f"/monitoring/metrics/droplet/cpu?host_id={did}&start={now - 240}&end={now}")
    if not r or "data" not in r:
        log(f"    No metrics data for {did}")
        return None
    idle = next(
      (
        float(item["values"][-1][1])
        for item in (
          r.get("data", {}).get("result", [])
          if isinstance(r.get("data", {}).get("result", []), list)
          else [r]
        )
        if item.get("metric", {}).get("mode") == "idle" and item.get("values")
      ),
      None,
    )
    if not idle:
        log(f"    No idle samples found for {did}")
        return None
    system = next(
      (
        float(item["values"][-1][1])
        for item in (
          r.get("data", {}).get("result", [])
          if isinstance(r.get("data", {}).get("result", []), list)
          else [r]
        )
        if item.get("metric", {}).get("mode") == "system" and item.get("values")
      ),
      None,
    )
    if not system:
        log(f"    No system CPU samples found for {did}")
        return None
    user = next(
      (
        float(item["values"][-1][1])
        for item in (
          r.get("data", {}).get("result", [])
          if isinstance(r.get("data", {}).get("result", []), list)
          else [r]
        )
        if item.get("metric", {}).get("mode") == "user" and item.get("values")
      ),
      None,
    )
    if not user:
        log(f"    No user CPU samples found for {did}")
        return None
    last_idle = next(
      (
      float(item["values"][0][1])  # first sample instead of last
      for item in (
        r.get("data", {}).get("result", [])
        if isinstance(r.get("data", {}).get("result", []), list)
        else [r]
      )
      if item.get("metric", {}).get("mode") == "idle" and item.get("values")
      ),
      None,
    )
    if last_idle is None:
      log(f"    No initial idle sample found for {did}")
      return None
    last_system = next(
      (
      float(item["values"][0][1])  # first sample instead of last
      for item in (
        r.get("data", {}).get("result", [])
        if isinstance(r.get("data", {}).get("result", []), list)
        else [r]
      )
      if item.get("metric", {}).get("mode") == "system" and item.get("values")
      ),
      None,
    )
    if last_system is None:
      log(f"    No initial system CPU sample found for {did}")
      return None
    last_user= next(
      (
      float(item["values"][0][1])  # first sample instead of last
      for item in (
        r.get("data", {}).get("result", [])
        if isinstance(r.get("data", {}).get("result", []), list)
        else [r]
      )
      if item.get("metric", {}).get("mode") == "user" and item.get("values")
      ),
      None,
    )
    if last_user is None:
      log(f"    No initial user CPU sample found for {did}")
      return None

    log(f"    Response data: {json.dumps(r)}")
    log(f"    Idle now: {idle}, 4 minutes ago: {last_idle}")
    log(f"    System now: {system}, 4 minutes ago: {last_system}")
    log(f"    User now: {user}, 4 minutes ago: {last_user}")
    idle_last_4_minutes = idle - last_idle
    system_last_4_minutes = system - last_system
    user_last_4_minutes = user - last_user

    log(f"    Idle CPU in last 4 minutes: {idle_last_4_minutes}")
    log(f"    System CPU in last 4 minutes: {system_last_4_minutes}")
    log(f"    User CPU in last 4 minutes: {user_last_4_minutes}")

    total_last_4_minutes = system_last_4_minutes + user_last_4_minutes

    usage = (total_last_4_minutes / (total_last_4_minutes + idle_last_4_minutes)) * 100 if (total_last_4_minutes + idle_last_4_minutes) > 0 else 0.0
    log(f"    CPU usage for {did} ({name}): {usage}%")
    if last_idle == idle:
        return None
    return usage

def create_node():
    name = f"{STACK_NAME}-media-{int(time.time())}-{random.randint(1000,9999)}"
    log(f"Creating new media node: name={name} region={REGION} size={SIZE} vpc={VPC_UUID}")
    try:
        keys = [int(SSH_KEY_ID)]
    except ValueError:
        keys = [SSH_KEY_ID]
    payload = {
        "name": name, "region": REGION, "size": SIZE,
        "image": "ubuntu-24-04-x64", "vpc_uuid": VPC_UUID,
        "ssh_keys": keys, "tags": [MEDIA_TAG],
        "user_data": USER_DATA, "monitoring": True,
    }
    r = apicall("POST", "/droplets", payload)
    if r and "droplet" in r:
        d = r["droplet"]
        log(f"  Node created: id={d['id']} name={d['name']} status={d['status']}")
        return True
    log(f"  Failed to create node {name}")
    return False

def tag_res(did, t):
    log(f"  Tagging droplet {did} with '{t}' ...")
    apicall("POST", f"/tags/{t}/resources",
        {"resources": [{"resource_id": str(did), "resource_type": "droplet"}]})

def untag_res(did, t):
    log(f"  Removing tag '{t}' from droplet {did} ...")
    url = f"{API}/tags/{t}/resources"
    req = urllib.request.Request(url, headers=HDR, method="DELETE")
    req.data = json.dumps({"resources": [{"resource_id": str(did), "resource_type": "droplet"}]}).encode()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            log(f"    <- {r.status} OK")
    except urllib.error.HTTPError as e:
        log(f"    <- HTTP {e.code} ERROR: {e.read().decode()[:200]}")
    except Exception as e:
        log(f"    <- error: {e}")

def main(args):
    """DO Functions entry point — invoked every 5 minutes by scheduled trigger."""
    log("=" * 60)
    log(f"Autoscaler invoked | stack={STACK_NAME} region={REGION}")
    log(f"Config: min={MIN_NODES} max={MAX_NODES} target_cpu={TARGET_CPU}%")
    log(f"Tags: media='{MEDIA_TAG}' draining='{DRAINING_TAG}'")
    log("=" * 60)

    result = {"action": "none", "nodes": 0, "avg_cpu": 0.0}

    try:
        nodes = list_nodes()
        n = len(nodes)
        result["nodes"] = n
        log(f"Total media nodes: {n}")

        # Ensure minimum
        if n < MIN_NODES:
            log(f"DECISION: scale-out-min (have {n}, need {MIN_NODES})")
            created = create_node()
            result["action"] = "scale-out-min"
            result["created"] = created
            log("=" * 60)
            result["logs"] = _LOGS
            return {"body": result}

        # Gather CPU for all nodes
        log("Gathering CPU metrics ...")
        cmap = {}  # id -> (usage, name)
        for d in nodes:
            usage = cpu(d["id"], d["name"])
            if usage is not None:
                cmap[d["id"]] = (usage, d["name"])
            else:
                log(f"  Skipping {d['id']} ({d['name']}) — no CPU data")

        if cmap:
            avg = sum(v for v, _ in cmap.values()) / len(cmap)
        else:
            avg = 0.0
            log("WARNING: no CPU data available for any node — skipping scaling decisions")

        result["avg_cpu"] = round(avg, 2)
        result["nodes_with_metrics"] = len(cmap)
        log(f"Average CPU across {len(cmap)}/{n} nodes: {avg:.2f}%")
        for did, (usage, name) in sorted(cmap.items(), key=lambda x: x[1][0], reverse=True):
            log(f"  {did} ({name}): {usage}%")

        # Scale out
        if avg > TARGET_CPU and n < MAX_NODES:
            log(f"DECISION: scale-out (avg={avg:.2f}% > target={TARGET_CPU}%, nodes={n} < max={MAX_NODES})")
            created = create_node()
            result["action"] = "scale-out"
            result["created"] = created
            log("=" * 60)
            result["logs"] = _LOGS
            return {"body": result}

        if avg > TARGET_CPU and n >= MAX_NODES:
            log(f"DECISION: hold (avg={avg:.2f}% > target but already at max={MAX_NODES})")

        # Scale in
        thr = TARGET_CPU
        log(f"Scale-in threshold: {thr:.2f}%")
        do_in = (avg < thr and n > MIN_NODES) or (n > MAX_NODES)

        if do_in:
            log(f"DECISION: scale-in (avg={avg:.2f}% < thr={thr:.2f}% or n={n} > max={MAX_NODES})")
            # Pick the node with lowest CPU usage
            if cmap:
                tid = min(cmap, key=lambda x: cmap[x][0])
                tname = cmap[tid][1]
                tcpu  = cmap[tid][0]
            else:
                tid   = nodes[0]["id"]   if nodes else None
                tname = nodes[0]["name"] if nodes else "?"
                tcpu  = 0.0
            if tid:
                log(f"  Selected node to drain: {tid} ({tname}) CPU={tcpu}%")
                untag_res(tid, MEDIA_TAG)
                tag_res(tid, DRAINING_TAG)
                result["action"] = "scale-in"
                result["drained_node"] = {"id": tid, "name": tname, "cpu": tcpu}
            else:
                log("  No node available to drain")
        else:
            log(f"DECISION: hold (avg={avg:.2f}% within range, nodes={n} within min/max)")

    except Exception as e:
        log(f"UNHANDLED EXCEPTION: {e}")
        log(traceback.format_exc())
        result["error"] = str(e)

    log("=" * 60)
    result["logs"] = _LOGS
    return {"body": result}
PYEOF

  tag_watcher_script_media = <<-EOF
#!/bin/bash -x
DRAINING_TAG="${digitalocean_tag.draining_tag.name}"
SELF_TAGS=$(curl -sf http://169.254.169.254/metadata/v1/tags 2>/dev/null || echo "")

if echo "$SELF_TAGS" | grep -qw "$DRAINING_TAG"; then
  echo "$(date): Draining tag detected. Initiating graceful shutdown."
  rm -f /etc/cron.d/tag-watcher
  nohup /usr/local/bin/graceful_shutdown.sh > /var/log/graceful_shutdown.log 2>&1 &
fi
EOF

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

  AWS_CLI_VERSION=2.34.41
  # Install aws-cli
  curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m)-$${AWS_CLI_VERSION}.zip" -o "awscliv2.zip"
  unzip -qq awscliv2.zip
  ./aws/install
  rm -rf awscliv2.zip aws

  DOCTL_VERSION=1.155.0
  # Install doctl
  cd ~
  wget https://github.com/digitalocean/doctl/releases/download/v$${DOCTL_VERSION}/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz
  tar xf ~/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz
  mv ~/doctl /usr/local/bin
  rm -f ~/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz

  export HOME="/root"

  doctl auth init -t "${var.doToken}"

  export AWS_ACCESS_KEY_ID="${digitalocean_spaces_key.openvidu_space_key.access_key}"
  export AWS_SECRET_ACCESS_KEY="${digitalocean_spaces_key.openvidu_space_key.secret_key}"
  export AWS_DEFAULT_REGION="${var.spaceRegion}"
  
  # Save private key to bucket (for manual SSH access)
  echo "${tls_private_key.openvidu_ssh_key.private_key_openssh}" > /tmp/openvidu_ssh_key_elastic.pem
  chmod 600 /tmp/openvidu_ssh_key_elastic.pem

  # Upload private key to the bucket
  aws s3 cp /tmp/openvidu_ssh_key_elastic.pem \
  s3://${var.spaceName == "" ? digitalocean_spaces_bucket.openvidu_space[0].name : var.spaceName}/openvidu_ssh_key_elastic.pem \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --acl private \
  --region=${var.spaceRegion}

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
  "--environment=digitalocean"
  "--deployment-type=elastic"
  "--node-role=media-node"
  "--master-node-private-ip=$MASTER_NODE_PRIVATE_IP"
  "--private-ip=$PRIVATE_IP"
  "--redis-password=$REDIS_PASSWORD"
)

# Construct the final command
FINAL_COMMAND="$INSTALL_COMMAND $(printf "%s " "$${COMMON_ARGS[@]}")"

# Execute installation
set +e
MAX_RETRIES=5
RETRY_COUNT=1

until bash -c "$FINAL_COMMAND"; do
  echo "Install command failed (attempt $RETRY_COUNT/$MAX_RETRIES)"
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "Install command failed after $MAX_RETRIES attempts"
    exit 1
  fi
  RETRY_COUNT=$((RETRY_COUNT + 1))
  sleep 10
done
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

# tag_watcher.sh (detects draining tag and triggers graceful shutdown)
cat > /usr/local/bin/tag_watcher.sh << 'TAG_WATCHER_EOF'
${local.tag_watcher_script_media}
TAG_WATCHER_EOF
chmod +x /usr/local/bin/tag_watcher.sh

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

AWS_CLI_VERSION=2.34.41
# Install aws-cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m)-$${AWS_CLI_VERSION}.zip" -o "awscliv2.zip"
unzip -qq awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws

DOCTL_VERSION=1.155.0
# Install doctl
cd ~
wget https://github.com/digitalocean/doctl/releases/download/v$${DOCTL_VERSION}/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz
tar xf ~/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz
mv ~/doctl /usr/local/bin
rm -f ~/doctl-$${DOCTL_VERSION}-linux-amd64.tar.gz

export HOME="/root"

doctl auth init -t "${var.doToken}"

# Install OpenVidu Media Node
/usr/local/bin/install.sh || { echo "[OpenVidu] error installing OpenVidu Media Node"; exit 1; }

# Mark installation as complete
echo "installation_complete" > /usr/local/bin/openvidu_install_counter.txt

# Start OpenVidu
systemctl start openvidu || { echo "[OpenVidu] error starting OpenVidu"; exit 1; }

# Tag watcher cron: check every minute if this node should be drained
if [ "${var.fixedNumberOfMediaNodes}" -eq 0 ]; then
echo "*/2 * * * * root /usr/local/bin/tag_watcher.sh >> /var/log/tag_watcher.log 2>&1" > /etc/cron.d/tag-watcher
chmod 644 /etc/cron.d/tag-watcher
fi
EOF
}
