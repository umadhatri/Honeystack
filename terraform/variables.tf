variable "resource_group_name" {
  type        = string
  default     = "honeystack-rg"
  description = "Name of the Azure resource group"
}

variable "location" {
  type        = string
  default     = "East US"
  description = "Azure region to provision resources"
}

variable "vm_size" {
  type        = string
  default     = "Standard_B2s"
  description = "VM size/type for Honeystack server"
}

variable "dns_label" {
  type        = string
  default     = "honeystack-soc"
  description = "DNS prefix for the static public IP"
}

variable "allowed_admin_ip" {
  type        = string
  default     = "*"
  description = "Allowed IP range for admin SSH and SOC Dashboard. Change to your local IP for security."
}

variable "public_key_path" {
  type        = string
  default     = "~/.ssh/id_rsa.pub"
  description = "Local path to SSH public key for VM administration"
}
