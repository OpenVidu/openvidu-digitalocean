# -------------- VPC and Firewalls ----------------

resource "digitalocean_vpc" "openvidu_vpc" {
  name     = "${var.stackName}-vpc"
  region   = var.region
  ip_range = "10.10.10.0/24"
}

resource "digitalocean_tag" "master_node_tag" {
  name = "${var.stackName}-master-node-tag"
}

resource "digitalocean_tag" "media_node_tag" {
  name = "${var.stackName}-media-node-tag"
}

# External SSH access to Master Nodes
resource "digitalocean_firewall" "external_master_ssh" {
  name = "${var.stackName}-external-master-ssh"

  tags = [digitalocean_tag.master_node_tag.name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
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

# Load Balancer health checks and HTTP traffic to Master Nodes
resource "digitalocean_firewall" "lb_to_master_http" {
  name = "${var.stackName}-lb-to-master-http"

  tags = [digitalocean_tag.master_node_tag.name]

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
    port_range       = "1945"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "5349"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7880"
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

# External access to Media Nodes (SSH and media traffic)
resource "digitalocean_firewall" "external_media_access" {
  name = "${var.stackName}-external-media-access"

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

# Master node internal services communication
resource "digitalocean_firewall" "master_to_master_internal" {
  name = "${var.stackName}-master-to-master-internal"

  tags = [digitalocean_tag.master_node_tag.name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7000-7001"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9100-9101"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "20000"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9095-9096"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7946-7947"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "5000"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "3000"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

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

# Media Nodes to Master Nodes communication
resource "digitalocean_firewall" "media_to_master_services" {
  name = "${var.stackName}-media-to-master-services"

  tags = [digitalocean_tag.master_node_tag.name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7000-7001"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "7880"
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

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9009"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "3100"
    source_addresses = [digitalocean_vpc.openvidu_vpc.ip_range]
  }

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

# Master Nodes to Media Nodes communication
resource "digitalocean_firewall" "master_to_media_services" {
  name = "${var.stackName}-master-to-media-services"

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


# --------------------- Load Balancer -----------------------

resource "digitalocean_loadbalancer" "openvidu_lb" {
  name     = "${var.stackName}-lb"
  region   = var.region
  vpc_uuid = digitalocean_vpc.openvidu_vpc.id
  type     = "REGIONAL_NETWORK"

  forwarding_rule {
    entry_port      = 443
    entry_protocol  = "tcp"
    target_port     = 443
    target_protocol = "tcp"
  }

  forwarding_rule {
    entry_port      = 80
    entry_protocol  = "tcp"
    target_port     = 80
    target_protocol = "tcp"
  }

  forwarding_rule {
    entry_port      = 1935
    entry_protocol  = "tcp"
    target_port     = 1935
    target_protocol = "tcp"
  }

  healthcheck {
    port     = 7880
    protocol = "tcp"
  }

  droplet_tag = digitalocean_tag.master_node_tag.name
}

# --------------------- droplets -----------------------

# Master Node
resource "digitalocean_droplet" "openvidu_master_node" {
  count  = 4
  name   = "${var.stackName}-master-node-${count.index + 1}"
  image  = "ubuntu-24-04-x64"
  region = var.region
  size   = var.masterNodeInstanceType

  ssh_keys = [var.sshKeyFingerprint]
  vpc_uuid = digitalocean_vpc.openvidu_vpc.id
  tags     = [digitalocean_tag.master_node_tag.name]

  user_data = local.user_data_master
}

# Media node Autoscale Pool
resource "digitalocean_droplet_autoscale" "media_node_pool" {
  name = "${var.stackName}-media-node-pool"

  config {
    target_number_instances = var.fixedNumberOfMediaNodes
  }

  droplet_template {
    size      = var.mediaNodeInstanceType
    region    = var.region
    image     = "ubuntu-24-04-x64"
    tags      = [digitalocean_tag.media_node_tag.name]
    ssh_keys  = [var.sshKeyFingerprint]
    user_data = local.user_data_media
    vpc_uuid  = digitalocean_vpc.openvidu_vpc.id
  }

  depends_on = [digitalocean_droplet.openvidu_master_node]
}

# DigitalOcean Space
resource "digitalocean_spaces_bucket" "openvidu_space_appdata" {
  count  = var.spaceAppDataName == "" ? 1 : 0
  name   = var.spaceAppDataName == "" ? "openvidu-appdata" : var.spaceAppDataName
  region = var.spaceRegion
  acl    = "private"
}

resource "digitalocean_spaces_bucket" "openvidu_space_clusterdata" {
  count  = var.spaceClusterDataName == "" ? 1 : 0
  name   = var.spaceClusterDataName == "" ? "openvidu-clusterdata" : var.spaceClusterDataName
  region = var.spaceRegion
  acl    = "private"
}


locals {
  install_script_master = <<-EOF
#!/bin/bash -x
set -e

OPENVIDU_VERSION=main
DOMAIN=
YQ_VERSION=v4.44.5
echo "DPkg::Lock::Timeout \"-1\";" > /etc/apt/apt.conf.d/99timeout

# Install dependencies
apt-get update && apt-get install -y

# Install yq
wget https://github.com/mikefarah/yq/releases/download/$${YQ_VERSION}/yq_linux_amd64.tar.gz -O - |\
tar xz && mv yq_linux_amd64 /usr/bin/yq

# Create counter file for tracking script executions
echo 1 > /usr/local/bin/openvidu_install_counter.txt

mkdir -p /opt/openvidu
touch /opt/openvidu/secrets.env

# Get IPs using DO metadata
PUBLIC_IP=$(curl -s "https://api.digitalocean.com/v2/load_balancers?name=${var.stackName}-lb" \
  -H "Authorization: Bearer ${var.do_token}" \
  | jq -r '.load_balancers[0].ip')
MASTER_NODE_PRIVATE_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address)

# Get Master Node Number
MASTER_NODE_NAME=$(curl -s http://169.254.169.254/metadata/v1/hostname)
MASTER_NODE_NUMBER=$(echo "$MASTER_NODE_NAME" | rev | cut -d'-' -f1 | rev)

if [[ "$MASTER_NODE_NUMBER" == "1" ]]; then
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
  MASTER_NODE_PRIVATE_IP="$(/usr/local/bin/store_secret.sh save MASTER_NODE_PRIVATE_IP_1 "$MASTER_NODE_PRIVATE_IP")"
  /usr/local/bin/store_secret.sh fullsave
elif [[ "$MASTER_NODE_NUMBER" == "2" ]]; then
  set +e
  # Wait until first master node has stores his MASTER_NODE_PRIVATE_IP
  while true; do
    if aws s3 cp s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
      /opt/openvidu/secrets.env \
      --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
      --region=${var.spaceRegion}; then
        /usr/local/bin/store_secret.sh save MASTER_NODE_PRIVATE_IP_2 "$MASTER_NODE_PRIVATE_IP"
        /usr/local/bin/store_secret.sh fullsave
        break
    fi
    sleep 5
  done
  set -e
elif [[ "$MASTER_NODE_NUMBER" == "3" ]]; then
  set +e
  while true; do
    aws s3 cp s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
    /opt/openvidu/secrets.env \
    --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
    --region=${var.spaceRegion}
    
    if grep -q "MASTER_NODE_PRIVATE_IP_2=" /opt/openvidu/secrets.env; then
      /usr/local/bin/store_secret.sh save MASTER_NODE_PRIVATE_IP_3 "$MASTER_NODE_PRIVATE_IP"
      /usr/local/bin/store_secret.sh fullsave
      break
    fi
    sleep 5
  done
  set -e
elif [[ "$MASTER_NODE_NUMBER" == "4" ]]; then
  set +e
  while true; do
    aws s3 cp s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
    /opt/openvidu/secrets.env \
    --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
    --region=${var.spaceRegion}
    
    if grep -q "MASTER_NODE_PRIVATE_IP_3=" /opt/openvidu/secrets.env; then
      /usr/local/bin/store_secret.sh save MASTER_NODE_PRIVATE_IP_4 "$MASTER_NODE_PRIVATE_IP"
      /usr/local/bin/store_secret.sh save ALL_SECRETS_GENERATED "true"
      /usr/local/bin/store_secret.sh fullsave
      break
    fi
    sleep 5
  done
  set -e
fi

# Wait to the MASTER_NODE_PRIVATE_IP_4 to be preset in secrets.env and then create the list of MASTER_NODE_PRIVATE_IPS
while true; do
  aws s3 cp s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
  /opt/openvidu/secrets.env \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --region=${var.spaceRegion}

  if grep -q "MASTER_NODE_PRIVATE_IP_4=" /opt/openvidu/secrets.env; then
    MASTER_NODE_PRIVATE_IPS=""
    MASTER_NODE_PRIVATE_IP_1=$(grep '^MASTER_NODE_PRIVATE_IP_1=' /opt/openvidu/secrets.env | cut -d'=' -f2)
      MASTER_NODE_PRIVATE_IP_2=$(grep '^MASTER_NODE_PRIVATE_IP_2=' /opt/openvidu/secrets.env | cut -d'=' -f2)
      MASTER_NODE_PRIVATE_IP_3=$(grep '^MASTER_NODE_PRIVATE_IP_3=' /opt/openvidu/secrets.env | cut -d'=' -f2)
      MASTER_NODE_PRIVATE_IP_4=$(grep '^MASTER_NODE_PRIVATE_IP_4=' /opt/openvidu/secrets.env | cut -d'=' -f2)
      MASTER_NODE_PRIVATE_IPS="$MASTER_NODE_PRIVATE_IP_1,$MASTER_NODE_PRIVATE_IP_2,$MASTER_NODE_PRIVATE_IP_3,$MASTER_NODE_PRIVATE_IP_4"
    break
  fi
  sleep 5
done

DOMAIN=$(grep '^DOMAIN_NAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_PRO_LICENSE=$(grep '^OPENVIDU_PRO_LICENSE=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_RTC_ENGINE=$(grep '^OPENVIDU_RTC_ENGINE=' /opt/openvidu/secrets.env | cut -d'=' -f2)
REDIS_PASSWORD=$(grep '^REDIS_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MONGO_ADMIN_USERNAME=$(grep '^MONGO_ADMIN_USERNAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MONGO_ADMIN_PASSWORD=$(grep '^MONGO_ADMIN_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MONGO_REPLICA_SET_KEY=$(grep '^MONGO_REPLICA_SET_KEY=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MINIO_ACCESS_KEY=$(grep '^MINIO_ACCESS_KEY=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MINIO_SECRET_KEY=$(grep '^MINIO_SECRET_KEY=' /opt/openvidu/secrets.env | cut -d'=' -f2)
DASHBOARD_ADMIN_USERNAME=$(grep '^DASHBOARD_ADMIN_USERNAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
DASHBOARD_ADMIN_PASSWORD=$(grep '^DASHBOARD_ADMIN_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
GRAFANA_ADMIN_USERNAME=$(grep '^GRAFANA_ADMIN_USERNAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
GRAFANA_ADMIN_PASSWORD=$(grep '^GRAFANA_ADMIN_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MEET_INITIAL_ADMIN_USER=$(grep '^MEET_INITIAL_ADMIN_USER=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MEET_INITIAL_ADMIN_PASSWORD=$(grep '^MEET_INITIAL_ADMIN_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
if [[ "${var.initialMeetApiKey}" != '' ]]; then
  MEET_INITIAL_API_KEY=$(grep '^MEET_INITIAL_API_KEY=' /opt/openvidu/secrets.env | cut -d'=' -f2)
fi
LIVEKIT_API_KEY=$(grep '^LIVEKIT_API_KEY=' /opt/openvidu/secrets.env | cut -d'=' -f2)
LIVEKIT_API_SECRET=$(grep '^LIVEKIT_API_SECRET=' /opt/openvidu/secrets.env | cut -d'=' -f2)
ENABLED_MODULES=$(grep '^ENABLED_MODULES=' /opt/openvidu/secrets.env | cut -d'=' -f2)



# Build install command
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/pro/ha/$OPENVIDU_VERSION/install_ov_master_node.sh)"

# Common arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=on_premise"
  "--deployment-type='ha'"
  "--node-role='master-node'"
  "--external-load-balancer"
  "--internal-tls-termination"
  "--master-node-private-ip-list='$MASTER_NODE_PRIVATE_IPS'"
  "--openvidu-pro-license='$OPENVIDU_PRO_LICENSE'"
  "--domain-name='$DOMAIN'"
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
EXTERNAL_S3_ACCESS_KEY="${var.spaces_access_key}"
EXTERNAL_S3_SECRET_KEY="${var.spaces_secret_key}"

# Config S3 bucket
EXTERNAL_S3_ENDPOINT="https://${var.spaceRegion}.digitaloceanspaces.com"
EXTERNAL_S3_REGION="${var.spaceRegion}"
EXTERNAL_S3_PATH_STYLE_ACCESS="true"
EXTERNAL_S3_BUCKET_APP_DATA="${var.spaceAppDataName == "" ? digitalocean_spaces_bucket.openvidu_space_appdata[0].name : var.spaceAppDataName}"
EXTERNAL_S3_BUCKET_CLUSTER_DATA="${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}"

sed -i "s|EXTERNAL_S3_ENDPOINT=.*|EXTERNAL_S3_ENDPOINT=$EXTERNAL_S3_ENDPOINT|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_REGION=.*|EXTERNAL_S3_REGION=$EXTERNAL_S3_REGION|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_PATH_STYLE_ACCESS=.*|EXTERNAL_S3_PATH_STYLE_ACCESS=$EXTERNAL_S3_PATH_STYLE_ACCESS|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_BUCKET_APP_DATA=.*|EXTERNAL_S3_BUCKET_APP_DATA=$EXTERNAL_S3_BUCKET_APP_DATA|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
sed -i "s|EXTERNAL_S3_BUCKET_CLUSTER_DATA=.*|EXTERNAL_S3_BUCKET_CLUSTER_DATA=$EXTERNAL_S3_BUCKET_CLUSTER_DATA|" "$${CLUSTER_CONFIG_DIR}/openvidu.env"
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
INSTALL_DIR="/opt/openvidu"
CLUSTER_CONFIG_DIR="$${INSTALL_DIR}/config/cluster"
MASTER_NODE_CONFIG_DIR="$${INSTALL_DIR}/config/node"
SECRETS_FILE="/opt/openvidu/secrets.env"

# Download secrets.env from S3 bucket
aws s3 cp \
  s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
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

# Try to acquire lock before fullsave
MAX_LOCK_RETRIES=60
LOCK_RETRY_COUNT=0
while [ $LOCK_RETRY_COUNT -lt $MAX_LOCK_RETRIES ]; do
  # Try to create lock file in S3 (fails if already exists)
  if aws s3 cp /dev/null \
    s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/lock.lock \
    --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
    --region=${var.spaceRegion} 2>/dev/null; then
    break
  else
    LOCK_RETRY_COUNT=$((LOCK_RETRY_COUNT + 1))
    sleep 2
  fi
done

if [ $LOCK_RETRY_COUNT -eq $MAX_LOCK_RETRIES ]; then
  echo "Failed to acquire lock after $MAX_LOCK_RETRIES attempts"
  exit 1
fi

# Perform fullsave
/usr/local/bin/store_secret.sh fullsave

# Delete lock file
aws s3 rm \
  s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/lock.lock \
  --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
  --region=${var.spaceRegion}

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
        s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
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

  export AWS_ACCESS_KEY_ID="${var.spaces_access_key}"
  export AWS_SECRET_ACCESS_KEY="${var.spaces_secret_key}"
  export AWS_DEFAULT_REGION="${var.spaceRegion}"

  # Add route to load balancer
  LB_IP=$(doctl compute load-balancer list --format IP --no-header | grep -v "^$" | head -n1)
  if [ -n "$LB_IP" ]; then
    ip route add to local $LB_IP dev eth0 || true
  fi

  # Create script for network load balancer configuration
  cat > /usr/local/bin/configure-nlb.sh << 'NLB_SCRIPT_EOF'
#!/bin/bash
export HOME="/root"
doctl auth init -t "${var.do_token}"
LB_IP=$(doctl compute load-balancer list --format IP --no-header | grep -v "^$" | head -n1)
if [ -n "$LB_IP" ]; then
  ip route add to local $LB_IP dev eth0 || true
fi
NLB_SCRIPT_EOF
  chmod +x /usr/local/bin/configure-nlb.sh

  # Create systemd service for network load balancer configuration
  cat > /etc/systemd/system/configure-nlb.service << 'NLB_SERVICE_EOF'
[Unit]
Description=Configure Network Load Balancer
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/configure-nlb.sh

[Install]
WantedBy=multi-user.target
NLB_SERVICE_EOF

  # Enable and start the service
  systemctl enable configure-nlb
  systemctl start configure-nlb

  # Install OpenVidu
  /usr/local/bin/install.sh || { echo "[OpenVidu] error installing OpenVidu"; exit 1; }
  
  # Config S3 bucket
  /usr/local/bin/config_s3.sh || { echo "[OpenVidu] error configuring S3 bucket"; exit 1; }

  # Start OpenVidu
  systemctl start openvidu || { echo "[OpenVidu] error starting OpenVidu"; exit 1; }

  # Update shared secrets (only for master node 1)
  MASTER_NODE_NAME=$(curl -s http://169.254.169.254/metadata/v1/hostname)
  MASTER_NODE_NUMBER=$(echo "$MASTER_NODE_NAME" | rev | cut -d'-' -f1 | rev)
  if [[ "$MASTER_NODE_NUMBER" == "1" ]]; then
    /usr/local/bin/after_install.sh || { echo "[OpenVidu] error updating shared secrets"; exit 1; }
  fi

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
export AWS_ACCESS_KEY_ID="${var.spaces_access_key}"
export AWS_SECRET_ACCESS_KEY="${var.spaces_secret_key}"
export AWS_DEFAULT_REGION="${var.spaceRegion}"
mkdir -p /opt/openvidu

# Active wait for secrets.env to be available and ALL_SECRETS_GENERATED=true
MAX_RETRIES=200
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if aws s3 cp \
    s3://${var.spaceClusterDataName == "" ? digitalocean_spaces_bucket.openvidu_space_clusterdata[0].name : var.spaceClusterDataName}/secrets.env \
    /opt/openvidu/secrets.env \
    --endpoint-url=https://${var.spaceRegion}.digitaloceanspaces.com \
    --region=${var.spaceRegion}; then
    
    # Check if ALL_SECRETS_GENERATED is true
    if grep -q "^ALL_SECRETS_GENERATED=true" /opt/openvidu/secrets.env; then
      echo "Successfully retrieved secrets.env with ALL_SECRETS_GENERATED=true"
      break
    fi
  fi
  
  RETRY_COUNT=$((RETRY_COUNT + 1))
  sleep 10
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo "Failed to retrieve secrets.env with ALL_SECRETS_GENERATED=true after $MAX_RETRIES attempts"
  exit 1
fi

# Get IPs using DO metadata
PRIVATE_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address)

# Get all necessary values from secrets
DOMAIN=$(grep '^DOMAIN_NAME=' /opt/openvidu/secrets.env | cut -d'=' -f2)
REDIS_PASSWORD=$(grep '^REDIS_PASSWORD=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_VERSION=$(grep '^OPENVIDU_VERSION=' /opt/openvidu/secrets.env | cut -d'=' -f2)
OPENVIDU_PRO_LICENSE=$(grep '^OPENVIDU_PRO_LICENSE=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MASTER_NODE_PRIVATE_IP_1=$(grep '^MASTER_NODE_PRIVATE_IP_1=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MASTER_NODE_PRIVATE_IP_2=$(grep '^MASTER_NODE_PRIVATE_IP_2=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MASTER_NODE_PRIVATE_IP_3=$(grep '^MASTER_NODE_PRIVATE_IP_3=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MASTER_NODE_PRIVATE_IP_4=$(grep '^MASTER_NODE_PRIVATE_IP_4=' /opt/openvidu/secrets.env | cut -d'=' -f2)
MASTER_NODE_PRIVATE_IPS="$MASTER_NODE_PRIVATE_IP_1,$MASTER_NODE_PRIVATE_IP_2,$MASTER_NODE_PRIVATE_IP_3,$MASTER_NODE_PRIVATE_IP_4"

# Build install command for media node
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/pro/ha/$OPENVIDU_VERSION/install_ov_media_node.sh)"

# Media node arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=on_premise"
  "--deployment-type=ha"
  "--node-role=media-node"
  "--master-node-private-ip-list=$MASTER_NODE_PRIVATE_IPS"
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
