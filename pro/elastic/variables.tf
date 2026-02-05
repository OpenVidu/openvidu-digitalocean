variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "DigitalOcean region where resources will be created"
  type        = string
  default     = "ams3"
}

variable "stackName" {
  description = "Stack name for OpenVidu deployment"
  type        = string
}

variable "certificateType" {
  description = "[selfsigned] Not recommended for production use. Just for testing purposes or development environments. You don't need a FQDN to use this option. [owncert] Valid for production environments. Use your own certificate. You need a FQDN to use this option. [letsencrypt] Valid for production environments. Can be used with or without a FQDN (if no FQDN is provided, a random sslip.io domain will be used)."
  type        = string
  default     = "letsencrypt"
  validation {
    condition     = contains(["selfsigned", "owncert", "letsencrypt"], var.certificateType)
    error_message = "certificateType must be one of: selfsigned, owncert, letsencrypt"
  }
}

variable "domainName" {
  description = "Domain name for the OpenVidu Deployment."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^$|^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", var.domainName))
    error_message = "The domain name does not have a valid domain name format"
  }
}

variable "ownPublicCertificate" {
  description = "If certificate type is 'owncert', this parameter will be used to specify the public certificate URL"
  type        = string
  default     = ""
}

variable "ownPrivateCertificate" {
  description = "If certificate type is 'owncert', this parameter will be used to specify the private certificate URL"
  type        = string
  default     = ""
}

variable "initialMeetAdminPassword" {
  description = "Initial password for the 'admin' user in OpenVidu Meet. If not provided, a random password will be generated."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]*$", var.initialMeetAdminPassword))
    error_message = "Must contain only alphanumeric characters (A-Z, a-z, 0-9). Leave empty to generate a random password."
  }
}

variable "initialMeetApiKey" {
  description = "Initial API key for OpenVidu Meet. If not provided, no API key will be set and the user can set it later from Meet Console."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]*$", var.initialMeetApiKey))
    error_message = "Must contain only alphanumeric characters (A-Z, a-z, 0-9). Leave empty to not set an initial API key."
  }
}

variable "masterNodeInstanceType" {
  description = "Specifies the Droplet size for your OpenVidu Master Node"
  type        = string
  default     = "s-4vcpu-8gb"
}

variable "mediaNodeInstanceType" {
  description = "Specifies the Droplet size for your OpenVidu Media Nodes"
  type        = string
  default     = "s-4vcpu-8gb"
}

variable "fixedNumberOfMediaNodes" {
  description = "If greater than 0, the number of media nodes will be fixed to this value, disabling autoscaling"
  type        = number
  default     = 4
}

# variable "initialNumberOfMediaNodes" {
#   description = "Number of initial media nodes to deploy"
#   type        = number
#   default     = 1
# }

# variable "minNumberOfMediaNodes" {
#   description = "Minimum number of media nodes to deploy (for reference, manual scaling required)"
#   type        = number
#   default     = 1
# }

# variable "maxNumberOfMediaNodes" {
#   description = "Maximum number of media nodes to deploy (for reference, manual scaling required)"
#   type        = number
#   default     = 5
# }

# variable "scaleTargetCPU" {
#   description = "Target CPU percentage to scale up or down"
#   type        = number
#   default     = 50
# }

variable "openviduLicense" {
  description = "Visit https://openvidu.io/account"
  type        = string
  sensitive   = true
}

variable "rtcEngine" {
  description = "RTCEngine media engine to use"
  type        = string
  default     = "pion"
  validation {
    condition     = contains(["pion", "mediasoup"], var.rtcEngine)
    error_message = "rtcEngine must be one of: pion, mediasoup"
  }
}

variable "additionalInstallFlags" {
  description = "Additional optional flags to pass to the OpenVidu installer (comma-separated, e.g.,'--flag1=value, --flag2')."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[A-Za-z0-9, =_.\\-]*$", var.additionalInstallFlags))
    error_message = "Must be a comma-separated list of flags (for example, --flag=value, --bool-flag)."
  }
}

variable "sshKeyFingerprint" {
  description = "SSH key fingerprint from DigitalOcean. You can get it from the DigitalOcean console under Settings > Security > SSH Keys"
  type        = string
}

variable "spaceName" {
  description = "Name for the DigitalOcean Space (S3-compatible bucket). If not provided, no Space will be created."
  type        = string
  default     = ""
}

variable "spaceRegion" {
  description = "Region for the DigitalOcean Space. Common values: nyc3, ams3, sgp1, sfo3"
  type        = string
  default     = "ams3"
}

variable "spaces_secret_key" {
  description = "Secret key for the DigitalOcean Space."
  type        = string
  sensitive   = true
}

variable "spaces_access_key" {
  description = "Access key for the DigitalOcean Space."
  type        = string
}
