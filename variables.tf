variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-3" # Paris
}

variable "admin_ip" {
  description = "Your public IP address for admin SSH access (without /32). Run: curl ifconfig.me"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key content for instance access (~/.ssh/id_ed25519.pub)"
  type        = string
}

variable "dshield_email" {
  description = "Email address registered on https://isc.sans.edu"
  type        = string
}

variable "dshield_apikey" {
  description = "DShield API key from https://isc.sans.edu/myaccount.html"
  type        = string
  sensitive   = true
}
