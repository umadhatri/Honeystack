output "public_ip_address" {
  value       = azurerm_public_ip.pip.ip_address
  description = "The static public IP address of the Honeystack VM"
}

output "fqdn" {
  value       = azurerm_public_ip.pip.fqdn
  description = "The fully qualified domain name (FQDN) of the Honeystack VM"
}

output "ssh_sensor_url" {
  value       = "${azurerm_public_ip.pip.ip_address}:2222"
  description = "Connect to SSH Honeypot sensor here"
}

output "http_sensor_url" {
  value       = "http://${azurerm_public_ip.pip.ip_address}:8081"
  description = "Access HTTP Honeypot sensor here"
}

output "soc_dashboard_url" {
  value       = "http://${azurerm_public_ip.pip.ip_address}:3000"
  description = "Access SOC Threat Intelligence Dashboard here"
}
